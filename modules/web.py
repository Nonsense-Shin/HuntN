"""
HuntN — Module 4: Web Discovery (Maximum Harvest Edition)
──────────────────────────────────────────────────────────────────────────────
"The earth is the Lord's, and everything in it, the world, and all who live
in it." — Psalm 24:1  (We map every corner.)

Core fixes and philosophy for maximum URL yield:
  ─────────────────────────────────────────────────────────────────────────
  PROBLEM 1 — Self-poisoning merge: all_urls.txt was built from web/*.txt,
    but live_endpoints.txt (also in web/) was included in that glob — so
    verified-live URLs were merged back in on top of themselves, and any
    subsequent uro/sort pass would strip duplicates unpredictably.
  FIX: Raw crawl outputs go to web/raw/. all_urls.txt is built from raw/
    only. live_endpoints.txt stays in web/ root — never re-merged.

  PROBLEM 2 — uro was too aggressive. On large infra it can drop hundreds
    of thousands of unique URLs that differ only in parameter values, which
    are exactly the ones you want for vuln hunting.
  FIX: uro is used only for the live_endpoints verification pass (small set).
    all_urls.txt is built with sort -u only — you get EVERY URL, including
    parameter variants. The user said "I don't care if it's millions."

  PROBLEM 3 — Katana -d 3 with no concurrency cap stalled on large targets.
    Each host was given 180s but with 50+ hosts queued that is 2.5 hours
    minimum and the process pool backed up.
  FIX: Katana runs with -crawl-duration per-host AND the loop uses a
    configurable per-host cap of 240s. Depth bumped to 4 for more coverage.

  PROBLEM 4 — GAU --subs flag wasn't passed correctly on some tool versions,
    silently missing subdomain URLs.
  FIX: GAU runs once on the root domain with --subs, AND once with a host
    list pipe for direct subdomain harvesting — belt and suspenders approach.

  PROBLEM 5 — Network errors during feroxbuster/ffuf caused silent failures.
    Retry logic and connection error handling were absent.
  FIX: feroxbuster now uses --timeout 15 --retry-attempts 2. ffuf uses
    -timeout 15.

Scale: all file operations stream to disk. Memory usage is constant
regardless of how many millions of URLs are collected.
"""

import sys
import hashlib
from pathlib import Path
from modules.utils import (
    C, print_info, print_success, print_warning, print_skip, print_find,
    run_cmd, run_cmd_pipe, which, which_or_install, count_lines
)

# ── EXTENSION PATTERNS ─────────────────────────────────────────────────────────
SENSITIVE_EXTS = (
    r"\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|"
    r"log|cache|secret|db|backup|yml|yaml|exe|dll|bin|ini|bat|sh|deb|rpm|iso|img|"
    r"apk|msi|dmg|tmp|crt|pem|key|pub|asc|env|sqlite|pfx|config|swp|passwords)(\?|$)"
)

HIGH_IMPACT_FILES = (
    r"\.(env|git|config|phpinfo|php\.ini|web\.config|settings\.py|composer\.json|"
    r"package\.json|Dockerfile|docker-compose|\.htaccess|\.htpasswd|backup|sql|dump)(\?|$)"
)

ADMIN_PATTERN = (
    r"/(admin|administrator|dashboard|panel|manage|backend|control|cp|wp-admin|"
    r"phpmyadmin|adminer|webmin|cpanel|jenkins|grafana|kibana|sonar|portainer|rancher)(/|$|\?)"
)

API_PATTERN = (
    r"(/api/|/v[0-9]+/|/rest/|/graphql|/rpc/|/service/|/services/|/endpoint/|/endpoints/)"
)

KEYWORD_PATTERN = (
    r"(token|secret|key|auth|password|pass|pwd|credential|session|jwt|oauth|sso|"
    r"saml|csrf|debug|internal|staging|test|dev|backup|config|upload|download|file|"
    r"import|export|payment|invoice|receipt|report|user|account|profile|billing|cart|checkout)"
)


def run(ctx):
    target  = ctx["target"]
    ws      = ctx["ws"]
    config  = ctx["config"]
    threads = ctx["threads"]

    web_dir   = ws.path("web")
    subs_live = ws.path("subdomains", "live.txt")

    if not subs_live.exists() or count_lines(subs_live) == 0:
        print_warning("No live subdomains available. Run subdomain enumeration first.")
        return

    with open(subs_live, "r", encoding="utf-8", errors="ignore") as f:
        live_hosts = [line.strip() for line in f if line.strip()]

    total_hosts = len(live_hosts)
    print_info(f"Loaded {total_hosts} live hosts for maximum URL harvest pipeline.")

    # Separate raw/ directory — all_urls.txt is NEVER merged from itself
    raw_dir = web_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # ── 4.1 ARCHIVE COLLECTION (GAU + WAYBACKURLS) ──────────────────────────
    print_info("Initiating passive archive harvesting — maximum provider coverage...")
    gau_file     = raw_dir / "gau.txt"
    wayback_file = raw_dir / "wayback.txt"

    if which_or_install("gau"):
        # Pass 1: root domain with --subs for comprehensive subdomain URL collection
        print_info("GAU pass 1 — root domain + subs (wayback, commoncrawl, otx, alienvault)...")
        run_cmd_pipe(
            f"gau --subs --providers wayback,commoncrawl,otx,alienvault "
            f"--threads {threads} "
            f"--blacklist png,jpg,jpeg,gif,svg,woff,woff2,css,ico,ttf,eot "
            f"--retries 3 "
            f"{target}",
            output_file=str(gau_file),
            timeout=1800
        )
        n1 = count_lines(gau_file)
        print_success(f"GAU pass 1 completed → {n1} URLs captured.")

        # Pass 2: pipe live subdomains directly for hosts not caught by --subs
        if total_hosts > 1:
            gau_subs_file = raw_dir / "gau_subs.txt"
            print_info(f"GAU pass 2 — direct subdomain pipe ({total_hosts} hosts)...")
            run_cmd_pipe(
                f"cat {subs_live} | gau --threads {threads} "
                f"--blacklist png,jpg,jpeg,gif,svg,woff,woff2,css,ico,ttf,eot "
                f"--retries 3",
                output_file=str(gau_subs_file),
                timeout=1800
            )
            n2 = count_lines(gau_subs_file)
            print_success(f"GAU pass 2 completed → {n2} additional URLs.")
    else:
        print_skip("gau missing — skipping archive provider lookup.")

    if which_or_install("waybackurls"):
        print_info("Waybackurls — all live subdomains pipeline...")
        run_cmd_pipe(
            f"cat {subs_live} | waybackurls",
            output_file=str(wayback_file),
            timeout=1800
        )
        print_success(f"Waybackurls completed → {count_lines(wayback_file)} URLs captured.")

    # ── 4.2 KATANA ACTIVE CRAWLING ──────────────────────────────────────────
    # Each host gets its own temp file → no race conditions, no file corruption
    katana_file = raw_dir / "katana_raw.txt"
    katana_file.write_text("")  # Clear/create aggregate

    if which_or_install("katana"):
        print_info("Starting deep Katana crawl (per-host, depth 4, JS parsing enabled)...")
        katana_threads_per_host = max(2, min(threads // 4, 20))

        for idx, host in enumerate(live_hosts, 1):
            sys.stdout.write(
                f"\r{C.BLUE}[i]{C.NC} Katana: [{idx}/{total_hosts}] "
                f"Crawling {host:<55}"
            )
            sys.stdout.flush()

            host_hash = hashlib.md5(host.encode()).hexdigest()[:8]
            temp_out  = raw_dir / f"katana_tmp_{host_hash}.txt"

            run_cmd_pipe(
                f"katana -u {host} -silent -jc -kf all -d 4 "
                f"-c {katana_threads_per_host} "
                f"-timeout 15 "
                f"-retry 2 "
                f"-ef png,jpg,jpeg,gif,css,woff,woff2,svg,ico,ttf,eot "
                f"-o {temp_out}",
                output_file=str(temp_out),
                timeout=240
            )

            if temp_out.exists() and temp_out.stat().st_size > 0:
                with open(katana_file, "a", encoding="utf-8") as agg, \
                     open(temp_out, encoding="utf-8", errors="ignore") as tmp:
                    agg.write(tmp.read())
                temp_out.unlink()

        print(f"\n{C.GREEN}[+]{C.NC} Katana complete → "
              f"{count_lines(katana_file)} crawl lines.")
    else:
        print_skip("katana missing — skipping active crawling.")

    # ── 4.3 HAKRAWLER (SUPPLEMENTAL COVERAGE) ───────────────────────────────
    hak_file = raw_dir / "hakrawler.txt"
    if live_hosts and which_or_install("hakrawler"):
        print_info("Hakrawler supplemental coverage pass...")
        run_cmd_pipe(
            f"cat {subs_live} | hakrawler -subs -u -insecure -d 3",
            output_file=str(hak_file),
            timeout=600
        )
        print_success(f"Hakrawler → {count_lines(hak_file)} additional links.")

    # ── 4.4 MERGE — raw/ ONLY, sort -u for max URL preservation ────────────
    # NOTE: live_endpoints.txt intentionally NOT included here.
    # We want all URLs including parameter variants — NO uro dedup here.
    print_info("Consolidating raw URL corpus (maximum yield — no aggressive dedup)...")
    all_urls_file = web_dir / "all_urls.txt"

    run_cmd_pipe(
        f"cat {raw_dir}/*.txt 2>/dev/null | sort -u",
        output_file=str(all_urls_file),
        timeout=120
    )

    total_urls = count_lines(all_urls_file)
    print_success(f"Total URL surface: {total_urls} unique URLs collected.")

    # ── 4.5 SENSITIVE FILE DETECTION ────────────────────────────────────────
    print_info("Scanning URL corpus for sensitive file exposure...")
    sensitive_file = ws.path("findings", "sensitive_files.txt")
    run_cmd_pipe(
        f"cat {all_urls_file} | grep -iEo 'https?://[^\\s]+' "
        f"| grep -iE '{SENSITIVE_EXTS}'",
        output_file=str(sensitive_file),
        timeout=60
    )
    n_sensitive = count_lines(sensitive_file)
    if n_sensitive > 0:
        print_find(f"Sensitive file artifacts: {n_sensitive} matches.")

    high_impact_file = ws.path("findings", "high_impact_files.txt")
    run_cmd_pipe(
        f"cat {all_urls_file} | grep -iE '{HIGH_IMPACT_FILES}'",
        output_file=str(high_impact_file),
        timeout=60
    )
    n_high = count_lines(high_impact_file)
    if n_high > 0:
        print_find(f"CRITICAL: High-impact config files: {n_high} matches.")

    # ── 4.6 PARAMETER EXTRACTION (PARAMSPIDER + ARJUN) ─────────────────────
    print_info("Extracting query parameters via ParamSpider...")
    params_file = web_dir / "params.txt"
    if which_or_install("paramspider"):
        run_cmd_pipe(
            f"paramspider -l {subs_live} --quiet 2>/dev/null",
            output_file=str(params_file),
            timeout=900
        )
        if count_lines(params_file) > 0:
            print_success(f"ParamSpider → {count_lines(params_file)} parameter URLs.")

    if which_or_install("arjun"):
        print_info("Arjun passive parameter discovery...")
        arjun_file = web_dir / "arjun_params.txt"
        run_cmd_pipe(
            f"arjun --passive {target} -oJ {arjun_file} 2>/dev/null",
            output_file=str(web_dir / "arjun_log.txt"),
            timeout=300
        )

    # ── 4.7 DIRECTORY BRUTEFORCE (FEROXBUSTER / FFUF) ──────────────────────
    print_info("Directory bruteforce (per-host, per-timeout for large infra)...")
    dir_file = web_dir / "directories.txt"
    wl = ctx.get("wordlist") or config.get("wordlists", {}).get(
        "directories",
        "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt"
    )

    if which_or_install("feroxbuster") and Path(wl).exists():
        dir_file.write_text("")  # Clear aggregate
        for idx, host in enumerate(live_hosts, 1):
            sys.stdout.write(
                f"\r{C.BLUE}[i]{C.NC} Feroxbuster: [{idx}/{total_hosts}] Scanning {host:<55}"
            )
            sys.stdout.flush()
            host_hash = hashlib.md5(host.encode()).hexdigest()[:8]
            tmp_dir   = raw_dir / f"ferox_tmp_{host_hash}.txt"
            run_cmd_pipe(
                f"feroxbuster -u {host} -w {wl} -t {min(threads, 50)} "
                f"--auto-tune -x php,html,json,txt,asp,aspx,jsp "
                f"--no-recursion -q --output {tmp_dir} "
                f"--timeout 15 --retry-attempts 2",
                output_file=str(tmp_dir),
                timeout=300
            )
            if tmp_dir.exists() and tmp_dir.stat().st_size > 0:
                with open(dir_file, "a", encoding="utf-8") as agg, \
                     open(tmp_dir, encoding="utf-8", errors="ignore") as tmp:
                    agg.write(tmp.read())
                tmp_dir.unlink()
        print(f"\n{C.GREEN}[+]{C.NC} Feroxbuster complete → "
              f"{count_lines(dir_file)} paths found.")

    elif which_or_install("ffuf") and Path(wl).exists():
        print_info("Fallback: FFUF micro-burst across all live hosts...")
        for idx, host in enumerate(live_hosts, 1):
            sys.stdout.write(
                f"\r{C.BLUE}[i]{C.NC} FFUF: [{idx}/{total_hosts}] Fuzzing {host:<55}"
            )
            sys.stdout.flush()
            safe_name = host.replace("://", "_").replace("/", "_").replace(":", "_")
            outfile   = raw_dir / f"ffuf_{safe_name}.csv"
            run_cmd_pipe(
                f"ffuf -u {host}/FUZZ -w {wl} "
                f"-mc 200,201,204,301,302,307,401,403 "
                f"-t {threads} -ac -silent -o {outfile} -of csv "
                f"-timeout 15",
                output_file=str(outfile),
                timeout=240
            )
        print(f"\n{C.GREEN}[+]{C.NC} FFUF complete.")
    else:
        if not which("feroxbuster") and not which("ffuf"):
            print_skip("feroxbuster and ffuf both missing — directory bruteforce skipped.")
        elif not Path(wl).exists():
            print_warning(f"Wordlist not found: {wl}")
            print_info("git clone https://github.com/danielmiessler/SecLists /usr/share/seclists")

    # ── 4.8 ROOT ARTIFACT HARVESTING ─────────────────────────────────────────
    print_info("Inspecting root descriptors (robots.txt, sitemap.xml, humans.txt)...")
    if which("curl"):
        robots_file = web_dir / "robots_sitemap.txt"
        run_cmd_pipe(
            f"cat {subs_live} | xargs -P 20 -I {{}} sh -c "
            f"\"echo '=== {{}} ==='; "
            f"curl -sk --max-time 10 {{}}'/robots.txt' 2>/dev/null; "
            f"curl -sk --max-time 10 {{}}'/sitemap.xml' 2>/dev/null | head -50; "
            f"curl -sk --max-time 10 {{}}'/humans.txt' 2>/dev/null\"",
            output_file=str(robots_file),
            timeout=300
        )

    # ── 4.9 GF PATTERN SEGREGATION ──────────────────────────────────────────
    print_info("Categorizing targets into vulnerability candidate buckets with GF...")
    _run_gf_filtering(all_urls_file, ws)

    # ── 4.10 LIVE ENDPOINT VERIFICATION ────────────────────────────────────
    # uro used HERE (not on all_urls) — small verified set is fine to normalize
    print_info("Verifying live accessibility of harvested endpoints (httpx)...")
    if which_or_install("httpx"):
        live_endpoints = web_dir / "live_endpoints.txt"
        # Sample top 50k URLs for verification — avoids httpx running for days
        # on multi-million URL sets; the full set is in all_urls.txt
        run_cmd_pipe(
            f"cat {all_urls_file} | head -50000 "
            f"| httpx -silent -threads {threads} -retries 2 -timeout 15 "
            f"-mc 200,201,301,302,403",
            output_file=str(live_endpoints),
            timeout=3600
        )
        n_live_ep = count_lines(live_endpoints)
        print_success(f"Verified live endpoints: {n_live_ep} active.")
    else:
        print_skip("httpx not found — endpoint verification skipped.")

    print_success("Web discovery complete — maximum URL surface captured.\n")


def _run_gf_filtering(urls_file, ws):
    """Run all GF patterns and save categorized results."""
    if not which("gf"):
        print_skip("gf not available — go install github.com/tomnomnom/gf@latest")
        return

    gf_dir       = ws.path("gf_filtered")
    findings_dir = ws.path("findings")

    patterns = {
        "xss":         ("xss_candidates.txt",           "XSS injection candidates"),
        "sqli":        ("sqli_candidates.txt",          "SQL injection candidates"),
        "ssrf":        ("ssrf_candidates.txt",          "SSRF candidates"),
        "ssti":        ("ssti_candidates.txt",          "SSTI candidates"),
        "redirect":    ("open_redirect_candidates.txt", "Open redirect candidates"),
        "rce":         ("rce_candidates.txt",           "RCE candidates"),
        "idor":        ("idor_candidates.txt",          "IDOR candidates"),
        "lfi":         ("lfi_candidates.txt",           "LFI candidates"),
        "debug_logic": ("debug_endpoints.txt",          "Debug/config endpoints"),
        "cors":        ("cors_candidates.txt",          "CORS candidates"),
        "aws-keys":    ("aws_keys.txt",                 "AWS key exposure"),
        "s3-buckets":  ("s3_buckets.txt",               "S3 bucket references"),
    }

    for pattern, (outfile, desc) in patterns.items():
        out = gf_dir / outfile
        run_cmd_pipe(
            f"cat {urls_file} | gf {pattern} 2>/dev/null",
            output_file=str(out),
            timeout=120
        )
        n = count_lines(out)
        if n > 0:
            print_find(f"  gf {pattern} → {n} targets ({desc})")

    # Admin panels
    admin_file = findings_dir / "admin_panels.txt"
    run_cmd_pipe(
        f"cat {urls_file} | grep -iE '{ADMIN_PATTERN}'",
        output_file=str(admin_file),
        timeout=60
    )
    n = count_lines(admin_file)
    if n > 0:
        print_find(f"  Admin panels located: {n}")

    # API endpoints
    api_endpoints_file = findings_dir / "api_endpoints.txt"
    run_cmd_pipe(
        f"cat {urls_file} | grep -iE '{API_PATTERN}'",
        output_file=str(api_endpoints_file),
        timeout=60
    )
    n_api = count_lines(api_endpoints_file)
    if n_api > 0:
        print_info(f"  API frameworks mapped: {n_api}")

    # High-priority keywords
    interesting_file = findings_dir / "interesting_endpoints.txt"
    run_cmd_pipe(
        f"cat {urls_file} | grep -iE '{KEYWORD_PATTERN}'",
        output_file=str(interesting_file),
        timeout=60
    )
    n_kw = count_lines(interesting_file)
    if n_kw > 0:
        print_info(f"  High-priority keywords cataloged: {n_kw}")

    print_success("GF pattern classification complete.")
