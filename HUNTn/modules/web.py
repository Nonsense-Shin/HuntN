"""
HuntN — Module 4: Web Discovery
Covers: GAU, waybackurls, katana crawling, paramspider, arjun,
        directory bruteforce (feroxbuster/ffuf), sensitive file discovery,
        robots.txt/sitemap/humans.txt, GF filtering of all endpoints
"""

from pathlib import Path
from modules.utils import (
    C, print_info, print_success, print_warning, print_skip, print_find,
    run_cmd, run_cmd_pipe, which, count_lines
)


# Extensions to always grep for
SENSITIVE_EXTS = (
    r"\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|"
    r"log|cache|secret|db|backup|yml|yaml|exe|dll|bin|ini|bat|sh|deb|rpm|iso|img|"
    r"apk|msi|dmg|tmp|crt|pem|key|pub|asc|env|git|sqlite|pfx|config|swp|passwords)(\?|$)"
)

HIGH_IMPACT_FILES = (
    r"\.(env|git|config|phpinfo|php\.ini|web\.config|settings\.py|composer\.json|"
    r"package\.json|Dockerfile|docker-compose|\.htaccess|\.htpasswd|backup|sql|dump)(\?|$)"
)


def run(ctx):
    target  = ctx["target"]
    ws      = ctx["ws"]
    config  = ctx["config"]
    threads = ctx["threads"]

    web_dir   = ws.path("web")
    subs_live = ws.path("subdomains", "live.txt")

    # ── 4.1 ARCHIVE COLLECTION ────────────────────────────────────
    print_info("Collecting archived URLs with GAU...")
    gau_file = web_dir / "gau.txt"

    if which("gau"):
        run_cmd_pipe(
            f"gau --subs --threads {threads} --blacklist png,jpg,jpeg,gif,svg,woff,woff2,css,ico {target}",
            output_file=str(gau_file)
        )
        print_success(f"GAU → {count_lines(gau_file)} URLs")
    else:
        print_skip("gau — go install github.com/lc/gau/v2/cmd/gau@latest")

    print_info("Collecting archived URLs with waybackurls...")
    wayback_file = web_dir / "wayback.txt"

    if which("waybackurls"):
        run_cmd_pipe(
            f"cat {subs_live} 2>/dev/null | waybackurls",
            output_file=str(wayback_file)
        )
        print_success(f"waybackurls → {count_lines(wayback_file)} URLs")
    else:
        print_skip("waybackurls — go install github.com/tomnomnom/waybackurls@latest")

    # ── 4.2 ACTIVE CRAWLING WITH KATANA ──────────────────────────
    print_info("Active crawling with katana...")
    katana_file = web_dir / "katana.txt"

    if which("katana") and subs_live.exists():
        run_cmd_pipe(
            f"katana -list {subs_live} -silent -jc -kf all "
            f"-ef png,jpg,jpeg,gif,css,woff,svg -c {threads} -o {katana_file}",
            output_file=str(katana_file)
        )
        print_success(f"katana → {count_lines(katana_file)} URLs")
    else:
        print_skip("katana — go install github.com/projectdiscovery/katana/cmd/katana@latest")

    # ── 4.3 HAKRAWLER SUPPLEMENTAL ───────────────────────────────
    if which("hakrawler") and subs_live.exists():
        hak_file = web_dir / "hakrawler.txt"
        run_cmd_pipe(
            f"cat {subs_live} | hakrawler -subs -u -insecure -d 2",
            output_file=str(hak_file)
        )
        print_success(f"hakrawler → {count_lines(hak_file)} URLs")

    # ── 4.4 MERGE ALL URLS ───────────────────────────────────────
    print_info("Merging and deduplicating all URLs...")
    all_urls_file = web_dir / "all_urls.txt"

    if which("uro"):
        run_cmd_pipe(
            f"cat {web_dir}/*.txt 2>/dev/null | uro | sort -u",
            output_file=str(all_urls_file)
        )
    else:
        run_cmd_pipe(
            f"cat {web_dir}/*.txt 2>/dev/null | sort -u",
            output_file=str(all_urls_file)
        )

    total_urls = count_lines(all_urls_file)
    print_success(f"Total unique URLs: {total_urls}")

    # ── 4.5 SENSITIVE FILE DISCOVERY ─────────────────────────────
    print_info("Grepping for sensitive file extensions...")
    sensitive_file = ws.path("findings", "sensitive_files.txt")
    run_cmd_pipe(
        f"cat {all_urls_file} | grep -iEo 'https?://[^\\s]+' | grep -iE '{SENSITIVE_EXTS}'",
        output_file=str(sensitive_file)
    )
    n_sensitive = count_lines(sensitive_file)
    print_success(f"Sensitive files found: {n_sensitive}")

    # High-impact subset
    high_impact_file = ws.path("findings", "high_impact_files.txt")
    run_cmd_pipe(
        f"cat {all_urls_file} | grep -iE '{HIGH_IMPACT_FILES}'",
        output_file=str(high_impact_file)
    )
    n_high = count_lines(high_impact_file)
    if n_high > 0:
        print_find(f"HIGH IMPACT files found: {n_high} — check findings/high_impact_files.txt")

    # ── 4.6 PARAMETER DISCOVERY ──────────────────────────────────
    print_info("Parameter discovery with paramspider...")
    params_file = web_dir / "params.txt"

    if which("paramspider"):
        run_cmd_pipe(
            f"paramspider -l {subs_live} --quiet 2>/dev/null",
            output_file=str(params_file)
        )
        print_success(f"paramspider → parameters found")
    else:
        print_skip("paramspider — pip3 install paramspider")

    if which("arjun"):
        arjun_file = web_dir / "arjun_params.txt"
        run_cmd_pipe(
            f"arjun --passive {target} -oJ {arjun_file} 2>/dev/null",
            output_file=str(web_dir / "arjun_log.txt")
        )
        print_success("arjun passive parameter discovery done")
    else:
        print_skip("arjun — pip3 install arjun")

    # ── 4.7 DIRECTORY BRUTEFORCE ─────────────────────────────────
    print_info("Directory bruteforce with feroxbuster / ffuf...")
    dir_file = web_dir / "directories.txt"
    wl = ctx.get("wordlist") or config.get("wordlists", {}).get("directories",
        "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt")

    if which("feroxbuster") and subs_live.exists() and Path(wl).exists():
        run_cmd_pipe(
            f"feroxbuster --stdin -w {wl} -t {threads} --auto-tune "
            f"-x php,html,json,txt,asp,aspx,jsp --no-recursion -q "
            f"--output {dir_file} < {subs_live}",
            output_file=str(dir_file)
        )
        print_success(f"feroxbuster → {count_lines(dir_file)} paths found")
    elif which("ffuf") and subs_live.exists() and Path(wl).exists():
        print_info("Using ffuf for directory bruteforce...")
        import subprocess
        with open(subs_live) as f:
            hosts = [l.strip() for l in f if l.strip()]
        for host in hosts[:20]:  # Limit to first 20 live hosts
            outfile = web_dir / f"ffuf_{host.replace('/', '_').replace(':', '')}.txt"
            run_cmd_pipe(
                f"ffuf -u {host}/FUZZ -w {wl} -mc 200,201,204,301,302,307,401,403 "
                f"-t {threads} -ac -silent -o {outfile} -of csv",
                output_file=str(outfile)
            )
    else:
        if not which("feroxbuster") and not which("ffuf"):
            print_skip("feroxbuster / ffuf not found")
            print_info("  Install feroxbuster: cargo install feroxbuster")
            print_info("  Install ffuf: go install github.com/ffuf/ffuf/v2@latest")
        elif not Path(wl).exists():
            print_warning(f"Wordlist not found: {wl}")
            print_info("  Download SecLists: git clone https://github.com/danielmiessler/SecLists /usr/share/seclists")

    # ── 4.8 ROBOTS/SITEMAP/HUMANS ────────────────────────────────
    print_info("Fetching robots.txt, sitemap, humans.txt...")
    if subs_live.exists() and which("httpx"):
        robots_file = web_dir / "robots_sitemap.txt"
        run_cmd_pipe(
            f"cat {subs_live} | xargs -P 20 -I {{}} sh -c "
            f"\"echo '=== {{}} ==='; curl -sk {{}}/robots.txt 2>/dev/null; "
            f"curl -sk {{}}/sitemap.xml 2>/dev/null | head -50; "
            f"curl -sk {{}}/humans.txt 2>/dev/null\"",
            output_file=str(robots_file)
        )
        print_success("robots.txt / sitemap.xml / humans.txt collected")

    # ── 4.9 GF PATTERN FILTERING ─────────────────────────────────
    print_info("GF pattern filtering on all URLs...")
    _run_gf_filtering(all_urls_file, ws)

    # Live endpoint verification
    print_info("Verifying live endpoints (httpx on all_urls)...")
    if which("httpx"):
        live_endpoints = web_dir / "live_endpoints.txt"
        run_cmd_pipe(
            f"cat {all_urls_file} | httpx -silent -threads {threads} -mc 200,201,301,302,403",
            output_file=str(live_endpoints)
        )
        print_success(f"Live endpoints → {count_lines(live_endpoints)}")

    print_success("Web discovery complete.\n")


def _run_gf_filtering(urls_file, ws):
    """Run all GF patterns and save categorized results."""
    if not which("gf"):
        print_skip("gf not found — go install github.com/tomnomnom/gf@latest")
        print_info("  Then install patterns: git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf/")
        return

    gf_dir = ws.path("gf_filtered")
    findings_dir = ws.path("findings")

    patterns = {
        "xss":          ("xss_candidates.txt",           "XSS injection candidates"),
        "sqli":         ("sqli_candidates.txt",           "SQL injection candidates"),
        "ssrf":         ("ssrf_candidates.txt",           "SSRF candidates"),
        "ssti":         ("ssti_candidates.txt",           "SSTI candidates"),
        "redirect":     ("open_redirect_candidates.txt",  "Open redirect candidates"),
        "rce":          ("rce_candidates.txt",            "RCE candidates"),
        "idor":         ("idor_candidates.txt",           "IDOR candidates"),
        "lfi":          ("lfi_candidates.txt",            "LFI candidates"),
        "debug_logic":  ("debug_endpoints.txt",           "Debug/config endpoints"),
        "cors":         ("cors_candidates.txt",           "CORS candidates"),
        "aws-keys":     ("aws_keys.txt",                  "AWS key exposure"),
        "s3-buckets":   ("s3_buckets.txt",                "S3 bucket references"),
    }

    for pattern, (outfile, desc) in patterns.items():
        out = gf_dir / outfile
        rc = run_cmd_pipe(
            f"cat {urls_file} | gf {pattern} 2>/dev/null",
            output_file=str(out)
        )
        n = count_lines(out)
        if n > 0:
            print_find(f"  gf {pattern} → {n} candidates ({desc})")
        else:
            print_info(f"  gf {pattern} → 0 results")

    # Admin panels
    admin_file = findings_dir / "admin_panels.txt"
    run_cmd_pipe(
        f"cat {urls_file} | grep -iE '/(admin|administrator|dashboard|panel|manage|"
        f"backend|control|cp|wp-admin|phpmyadmin|adminer|webmin|cpanel|"
        f"jenkins|grafana|kibana|sonar|portainer|rancher)(/|$|\\?)'",
        output_file=str(admin_file)
    )
    n = count_lines(admin_file)
    if n > 0:
        print_find(f"  Admin panels found: {n}")

    # API endpoints
    api_endpoints_file = findings_dir / "api_endpoints.txt"
    run_cmd_pipe(
        f"cat {urls_file} | grep -iE '(/api/|/v[0-9]+/|/rest/|/graphql|/rpc/|"
        f"/service/|/services/|/endpoint/|/endpoints/)'",
        output_file=str(api_endpoints_file)
    )
    n = count_lines(api_endpoints_file)
    print_info(f"  API endpoints extracted: {n}")

    # Interesting keywords
    interesting_file = findings_dir / "interesting_endpoints.txt"
    run_cmd_pipe(
        f"cat {urls_file} | grep -iE '(token|secret|key|auth|password|pass|pwd|"
        f"credential|session|jwt|oauth|sso|saml|csrf|debug|internal|staging|"
        f"test|dev|backup|config|upload|download|file|import|export|payment|"
        f"invoice|receipt|report|user|account|profile|billing|cart|checkout)'",
        output_file=str(interesting_file)
    )
    n = count_lines(interesting_file)
    print_info(f"  Interesting endpoints: {n}")

    print_success("GF filtering complete → gf_filtered/")
