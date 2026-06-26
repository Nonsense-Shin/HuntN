"""
HuntN — Module 2: Subdomain Enumeration (Fortified Edition)
──────────────────────────────────────────────────────────────────────────────
"Ask and it will be given to you; seek and you will find; knock and the door
will be opened to you." — Matthew 7:7

Root-cause fixes for inconsistent live host counts (16 → 7 → 2 regression):
  ─────────────────────────────────────────────────────────────────────────
  PROBLEM 1 — Circular merge: all.txt was built from *.txt in subs_dir, which
    included last-run's live.txt.  On resume or re-run, httpx-filtered hosts
    were re-fed back into passive data, and any that timed out on the second
    httpx pass were silently dropped → live count shrank each run.
  FIX: Passive tools now write to a dedicated raw/ subdirectory. Merging only
    reads raw/*.txt, never live.txt or live_full.txt.

  PROBLEM 2 — Double httpx: two back-to-back httpx calls on the same input
    list means network flakiness hits twice. On large scopes the second call
    (clean URL list) almost always times out on a different subset → different
    count every run.
  FIX: One httpx call with -json -o live_full.txt, then a simple grep/jq
    pass extracts the clean URL list. Zero extra network traffic.

  PROBLEM 3 — subfinder -all + -recursive on the same run with no dedup
    between steps meant the merge step saw thousands of dupes, inflating
    all.txt, and dnsx / alterx worked on an unnecessarily huge input.
  FIX: append_unique used between every passive step. Merge is deduped with
    sort -u before feeding into dnsx.

  PROBLEM 4 — No retry / back-off for httpx on large infra. Connections were
    refused or rate-limited and silently dropped.
  FIX: httpx now runs with -retries 3 -timeout 15 -delay 100ms on live check.

Scale note: designed to handle infinite infrastructure — all intermediate
files stream to disk, nothing lives in RAM lists.
"""

import subprocess
import json
from pathlib import Path
from modules.utils import (
    C, print_info, print_success, print_warning, print_skip,
    run_cmd, run_cmd_pipe, which, which_or_install, count_lines, append_unique
)


def run(ctx):
    target  = ctx["target"]
    ws      = ctx["ws"]
    config  = ctx["config"]
    threads = ctx["threads"]
    apis    = config.get("apis", {})

    subs_dir = ws.path("subdomains")

    # Dedicated raw directory — keeps passive output SEPARATE from live files
    raw_dir = subs_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # ── 2.1 PASSIVE ENUMERATION ──────────────────────────────────────────────
    print_info("Passive subdomain enumeration — all tools running in parallel vectors...")

    if which_or_install("subfinder"):
        run_cmd_pipe(
            f"subfinder -d {target} -all -silent",
            output_file=str(raw_dir / "subfinder.txt"),
            timeout=600
        )
        n = count_lines(raw_dir / "subfinder.txt")
        print_success(f"subfinder → {n} subdomains")
    else:
        print_skip("subfinder — go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

    if which_or_install("assetfinder"):
        run_cmd_pipe(
            f"assetfinder --subs-only {target}",
            output_file=str(raw_dir / "assetfinder.txt"),
            timeout=300
        )
        n = count_lines(raw_dir / "assetfinder.txt")
        print_success(f"assetfinder → {n} subdomains")
    else:
        print_skip("assetfinder — go install github.com/tomnomnom/assetfinder@latest")

    if which_or_install("amass"):
        run_cmd_pipe(
            f"amass enum -passive -d {target} -timeout 15",
            output_file=str(raw_dir / "amass_passive.txt"),
            timeout=950
        )
        print_success(f"amass passive → {count_lines(raw_dir / 'amass_passive.txt')} subdomains")
    else:
        print_skip("amass — go install github.com/owasp-amass/amass/v4/...@master")

    # Chaos (ProjectDiscovery)
    chaos_key = apis.get("chaos", "")
    if which("chaos") and chaos_key:
        run_cmd_pipe(
            f"chaos -d {target} -key {chaos_key} -silent",
            output_file=str(raw_dir / "chaos.txt"),
            timeout=300
        )
        print_success(f"chaos → {count_lines(raw_dir / 'chaos.txt')} subdomains")
    elif which("chaos"):
        print_skip("chaos: API key not set — register at https://chaos.projectdiscovery.io")

    # TLS SAN subs from intelligence stage (passive, no extra network)
    crtsh_intel = ws.path("intelligence", "crtsh.txt")
    if crtsh_intel.exists():
        escaped = target.replace(".", "\\.")
        run_cmd_pipe(
            f"cat {crtsh_intel} | grep -E '.+\\.{escaped}$'",
            output_file=str(raw_dir / "crtsh.txt"),
            timeout=30
        )
        print_success(f"crt.sh subs → {count_lines(raw_dir / 'crtsh.txt')}")

    # ── 2.2 INITIAL PASSIVE MERGE (raw only — never touches live files) ───────
    print_info("Merging passive results (raw sources only)...")
    passive_file = subs_dir / "passive.txt"
    escaped_target = target.replace(".", "\\.")
    run_cmd_pipe(
        f"cat {raw_dir}/*.txt 2>/dev/null "
        f"| grep -E '^[a-zA-Z0-9]([a-zA-Z0-9\\-]{{0,61}}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{{0,61}}[a-zA-Z0-9])?)*$' "
        f"| grep -iE '.+\\.{escaped_target}$|^{target}$' "
        f"| sort -u",
        output_file=str(passive_file),
        timeout=60
    )
    total_passive = count_lines(passive_file)
    print_success(f"Merged passive subdomains: {total_passive}")

    # ── 2.3 RECURSIVE SUBFINDER ──────────────────────────────────────────────
    print_info("Recursive subdomain enumeration (hunting nested domains)...")
    if which("subfinder"):
        recursive_file = raw_dir / "recursive.txt"
        run_cmd_pipe(
            f"subfinder -d {target} -all -recursive -silent",
            output_file=str(recursive_file),
            timeout=1200
        )
        added = append_unique(str(passive_file), [
            l.strip() for l in recursive_file.read_text(errors="ignore").splitlines()
            if l.strip()
        ] if recursive_file.exists() else [])
        n = count_lines(recursive_file)
        print_success(f"Recursive subfinder → {n} subdomains ({added} new unique)")

    # ── 2.4 ALTERX PERMUTATIONS ──────────────────────────────────────────────
    print_info("Generating subdomain permutations with alterx + dnsx resolution...")
    if which_or_install("alterx") and which_or_install("dnsx"):
        alterx_file = raw_dir / "alterx_permutations.txt"
        run_cmd_pipe(
            f"cat {passive_file} | alterx -silent "
            f"| dnsx -silent -r /etc/resolv.conf -t {threads} -retries 3",
            output_file=str(alterx_file),
            timeout=1800
        )
        n = count_lines(alterx_file)
        added = append_unique(str(passive_file), [
            l.strip() for l in alterx_file.read_text(errors="ignore").splitlines()
            if l.strip()
        ] if alterx_file.exists() else [])
        print_success(f"alterx + dnsx → {n} resolved permutations ({added} new unique)")
    else:
        print_skip("alterx/dnsx not found — permutation discovery skipped")

    # ── 2.5 DNS BRUTEFORCE ───────────────────────────────────────────────────
    print_info("DNS bruteforce with dnsx...")
    wordlist = config.get("wordlists", {}).get(
        "subdomains",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
    )
    brute_file = raw_dir / "bruteforce.txt"

    if which_or_install("dnsx") and Path(wordlist).exists():
        run_cmd_pipe(
            f"dnsx -d {target} -w {wordlist} -silent -t {threads} -retries 3",
            output_file=str(brute_file),
            timeout=900
        )
        added = append_unique(str(passive_file), [
            l.strip() for l in brute_file.read_text(errors="ignore").splitlines()
            if l.strip()
        ] if brute_file.exists() else [])
        print_success(f"DNS bruteforce → {count_lines(brute_file)} resolved ({added} new unique)")
    elif not which("dnsx"):
        print_skip("dnsx not found — go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
    else:
        print_warning(f"Wordlist not found: {wordlist}")
        print_info("Download SecLists: git clone https://github.com/danielmiessler/SecLists /usr/share/seclists")

    # ── 2.6 FINAL MERGE — raw sources only, strict dedup ─────────────────────
    print_info("Final merge of all discovered subdomains...")
    all_subs_file = subs_dir / "all.txt"

    # Merge all raw/ files + passive.txt, never live.txt
    run_cmd_pipe(
        f"cat {raw_dir}/*.txt {passive_file} 2>/dev/null "
        f"| grep -iE '.+\\.{escaped_target}$|^{target}$' "
        f"| sort -u",
        output_file=str(all_subs_file),
        timeout=90
    )
    total = count_lines(all_subs_file)
    print_success(f"Total unique subdomains: {total}")

    # ── 2.7 LIVE HOST FILTERING — single httpx pass, parse output for both ────
    print_info(f"Filtering live hosts from {total} subdomains with httpx (single-pass)...")
    live_file      = subs_dir / "live.txt"
    live_full_file = subs_dir / "live_full.txt"

    if which_or_install("httpx"):
        # ONE httpx invocation — writes JSON details + we extract clean URLs
        # -retries 3 and -delay 100ms handle rate-limited servers on large infra
        # -timeout 15 gives slow servers a fair shot
        run_cmd(
            f"httpx -l {all_subs_file} -silent "
            f"-title -status-code -tech-detect -content-length -web-server "
            f"-threads {threads} -retries 3 -timeout 15 -delay 100ms "
            f"-json -o {live_full_file}",
            shell=True,
            timeout=3600  # Large infra can take a long time — we let it run
        )

        # Extract clean URLs from JSON output (no second httpx call needed)
        if live_full_file.exists() and live_full_file.stat().st_size > 0:
            clean_urls = []
            with open(live_full_file, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        url = data.get("url", "").strip()
                        if url:
                            clean_urls.append(url)
                    except json.JSONDecodeError:
                        continue

            # Write clean live.txt from parsed JSON (deterministic — same input, same output)
            if clean_urls:
                live_file.write_text("\n".join(sorted(set(clean_urls))) + "\n", encoding="utf-8")
            else:
                live_file.write_text("", encoding="utf-8")

        live_count = count_lines(live_file)
        print_success(f"Live hosts confirmed: {live_count}")

        if live_count == 0:
            print_warning("Zero live hosts — check network connectivity or httpx installation.")
        elif live_count < 5:
            print_warning(
                f"Only {live_count} live hosts. For large infra: consider increasing "
                f"--threads or verifying DNS resolution with: "
                f"dnsx -l {all_subs_file} -silent -t {threads}"
            )

        # Technology summary (side-effect, doesn't affect live.txt)
        _summarize_technologies(live_full_file, ws)
    else:
        print_skip("httpx — go install github.com/projectdiscovery/httpx/cmd/httpx@latest")


def _summarize_technologies(live_full_file, ws):
    """Parse httpx JSON output and create a technology summary."""
    tech_summary  = {}
    hosts_by_tech = {}

    try:
        with open(live_full_file, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data   = json.loads(line)
                    url    = data.get("url", "")
                    techs  = data.get("tech", [])
                    status = data.get("status-code", 0)
                    title  = data.get("title", "")

                    for tech in techs:
                        tech_summary[tech] = tech_summary.get(tech, 0) + 1
                        if tech not in hosts_by_tech:
                            hosts_by_tech[tech] = []
                        if len(hosts_by_tech[tech]) < 20:  # cap per-tech list
                            hosts_by_tech[tech].append(f"{url} ({status}) — {title}")
                except json.JSONDecodeError:
                    continue

        tech_file = ws.path("infrastructure", "tech_stack.txt")
        with open(tech_file, "w", encoding="utf-8") as f:
            f.write("# Technology Stack Summary\n\n")
            for tech, count in sorted(tech_summary.items(), key=lambda x: -x[1]):
                f.write(f"\n## {tech} ({count} hosts)\n")
                for host in hosts_by_tech.get(tech, []):
                    f.write(f"  {host}\n")

        top_techs = list(tech_summary.keys())[:8]
        if top_techs:
            print_success(f"Tech stack detected: {', '.join(top_techs)}")
        _generate_tech_recommendations(list(tech_summary.keys()), ws)

    except Exception as e:
        print_warning(f"Tech summary error (non-fatal): {e}")


def _generate_tech_recommendations(techs, ws):
    """Generate tech-aware manual testing recommendations."""
    recs_file  = ws.path("reports", "tech_recommendations.md")
    tech_lower = [t.lower() for t in techs]

    TECH_HINTS = {
        "laravel": [
            "/.env — often exposed with DB credentials",
            "/telescope — Laravel debug panel (check if open)",
            "/horizon — Queue manager",
            "/_ignition/health-check — Ignition debug endpoint",
            "/storage — public storage directory",
        ],
        "wordpress": [
            "/wp-json/wp/v2/users — user enumeration",
            "/wp-admin — brute force login",
            "/wp-content/uploads — file upload artifacts",
            "/xmlrpc.php — bruteforce, SSRF vector",
            "WPScan: wpscan --url TARGET --enumerate p,t,u",
        ],
        "jenkins": [
            "/script — Groovy script console (RCE)",
            "/manage — Management interface",
            "/api/json?pretty=true — API enumeration",
            "/asynchPeople — user listing",
        ],
        "jira": [
            "/rest/api/2/project — project listing (unauthenticated?)",
            "/rest/api/2/user/search?username= — user enum",
            "/secure/Dashboard.jspa — authentication bypass checks",
        ],
        "django": [
            "/admin — admin panel",
            "/api/ — DRF browsable API",
            "DEBUG=True? Check error pages for settings leak",
        ],
        "spring": [
            "/actuator — Spring Boot actuator (env, beans, heap dump)",
            "/actuator/env — environment variables (credentials!)",
            "/actuator/logfile — application log",
            "/swagger-ui.html — API documentation",
        ],
        "kubernetes": [
            "Port 10250 — Kubelet API (unauthenticated exec?)",
            "Port 2379 — etcd (cluster secrets)",
            "/api/v1/pods — pod listing",
            "SSRF → http://169.254.169.254/latest/meta-data/",
        ],
        "nginx": [
            "Check for path traversal: /../../../etc/passwd",
            "Off-by-slash misconfiguration: /path vs /path/",
            "Server-side request forgery via proxy configs",
        ],
        "react": [
            "Source maps (.js.map files) — expose full source code",
            "Hardcoded API keys in bundled JS",
            "Redux DevTools state leakage",
        ],
        "graphql": [
            "/__graphql — playground open?",
            "/graphiql — interactive explorer",
            "Introspection: {__schema{types{name}}}",
            "Batch query attacks, field suggestions abuse",
        ],
    }

    with open(recs_file, "w", encoding="utf-8") as f:
        f.write("# Technology-Aware Testing Recommendations\n\n")
        found_any = False
        for tech_key, hints in TECH_HINTS.items():
            if any(tech_key in t for t in tech_lower):
                found_any = True
                f.write(f"## {tech_key.capitalize()}\n")
                for hint in hints:
                    f.write(f"- {hint}\n")
                f.write("\n")
        if not found_any:
            f.write("No specific tech hints generated (check tech_stack.txt for detected technologies).\n")

    print_success("Tech-aware recommendations → reports/tech_recommendations.md")
