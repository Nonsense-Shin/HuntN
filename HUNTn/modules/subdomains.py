"""
HuntN — Module 2: Subdomain Enumeration
Covers: subfinder, assetfinder, amass, chaos, crt.sh subs,
        recursive enumeration, alterx permutations, dnsx resolution, httpx live check
"""

import subprocess
from pathlib import Path
from modules.utils import (
    C, print_info, print_success, print_warning, print_skip,
    run_cmd, run_cmd_pipe, which, count_lines, append_unique
)


def run(ctx):
    target  = ctx["target"]
    ws      = ctx["ws"]
    config  = ctx["config"]
    threads = ctx["threads"]
    apis    = config.get("apis", {})

    subs_dir = ws.path("subdomains")

    # ── 2.1 PASSIVE ENUMERATION ──────────────────────────────────
    print_info("Passive subdomain enumeration...")

    passive_file = subs_dir / "passive.txt"

    if which("subfinder"):
        run_cmd(
            f"subfinder -d {target} -all -silent -o {subs_dir}/subfinder.txt",
            shell=True, output_file=str(subs_dir / "subfinder.txt")
        )
        n = count_lines(subs_dir / "subfinder.txt")
        print_success(f"subfinder → {n} subdomains")
    else:
        print_skip("subfinder — go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

    if which("assetfinder"):
        run_cmd_pipe(
            f"assetfinder --subs-only {target}",
            output_file=str(subs_dir / "assetfinder.txt")
        )
        n = count_lines(subs_dir / "assetfinder.txt")
        print_success(f"assetfinder → {n} subdomains")
    else:
        print_skip("assetfinder — go install github.com/tomnomnom/assetfinder@latest")

    if which("amass"):
        run_cmd(
            f"amass enum -passive -d {target} -o {subs_dir}/amass_passive.txt -timeout 10",
            shell=True, timeout=700
        )
        print_success("amass passive done")
    else:
        print_skip("amass — go install github.com/owasp-amass/amass/v4/...@master")

    # Chaos (ProjectDiscovery)
    chaos_key = apis.get("chaos", "")
    if which("chaos") and chaos_key:
        run_cmd_pipe(
            f"chaos -d {target} -key {chaos_key} -silent",
            output_file=str(subs_dir / "chaos.txt")
        )
        print_success(f"chaos → {count_lines(subs_dir / 'chaos.txt')} subdomains")
    elif which("chaos"):
        print_skip("chaos: API key not set in config.yaml → Register at https://chaos.projectdiscovery.io")

    # ── 2.2 CERTIFICATE TRANSPARENCY SUBS ────────────────────────
    print_info("Parsing crt.sh subdomains (from intelligence stage)...")
    crtsh_intel = ws.path("intelligence", "crtsh.txt")
    if crtsh_intel.exists():
        run_cmd_pipe(
            f"cat {crtsh_intel} | grep -E '.+\\.{target.replace('.', '\\.')}$'",
            output_file=str(subs_dir / "crtsh.txt")
        )
        print_success(f"crt.sh subs → {count_lines(subs_dir / 'crtsh.txt')}")

    # ── 2.3 MERGE PASSIVE ────────────────────────────────────────
    print_info("Merging all passive results...")
    merge_cmd = f"cat {subs_dir}/*.txt 2>/dev/null | sort -u | grep -E '.+\\.{target.replace('.','\\.')}$|^{target}$'"
    run_cmd_pipe(merge_cmd, output_file=str(passive_file))
    total_passive = count_lines(passive_file)
    print_success(f"Merged passive subdomains: {total_passive}")

    # ── 2.4 RECURSIVE SUBFINDER ─────────────────────────────────
    print_info("Recursive subdomain enumeration...")
    if which("subfinder"):
        recursive_file = subs_dir / "recursive.txt"
        run_cmd(
            f"subfinder -d {target} -all -recursive -silent -o {recursive_file}",
            shell=True, timeout=900
        )
        n = count_lines(recursive_file)
        print_success(f"Recursive subfinder → {n} additional subdomains")

    # ── 2.5 ALTERX PERMUTATIONS ──────────────────────────────────
    print_info("Generating subdomain permutations with alterx...")
    if which("alterx") and which("dnsx"):
        alterx_file = subs_dir / "alterx_permutations.txt"
        run_cmd_pipe(
            f"cat {passive_file} | alterx -silent | dnsx -silent -r /etc/resolv.conf -t {threads}",
            output_file=str(alterx_file)
        )
        n = count_lines(alterx_file)
        print_success(f"alterx + dnsx → {n} new resolved hosts")
    else:
        print_skip("alterx/dnsx not found — permutation-based discovery skipped")

    # ── 2.6 DNS BRUTEFORCE ───────────────────────────────────────
    print_info("DNS bruteforce with dnsx...")
    wordlist = config.get("wordlists", {}).get("subdomains",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt")
    brute_file = subs_dir / "bruteforce.txt"

    if which("dnsx") and Path(wordlist).exists():
        run_cmd_pipe(
            f"dnsx -d {target} -w {wordlist} -silent -t {threads}",
            output_file=str(brute_file)
        )
        print_success(f"DNS bruteforce → {count_lines(brute_file)} resolved")
    elif not which("dnsx"):
        print_skip("dnsx not found — go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
    else:
        print_warning(f"Wordlist not found: {wordlist}")
        print_info("Download SecLists: git clone https://github.com/danielmiessler/SecLists /usr/share/seclists")

    # ── 2.7 MERGE ALL & RESOLVE ──────────────────────────────────
    print_info("Final merge of all discovered subdomains...")
    all_subs_file = subs_dir / "all.txt"
    run_cmd_pipe(
        f"cat {subs_dir}/*.txt 2>/dev/null | sort -u | grep -E '.+'",
        output_file=str(all_subs_file)
    )
    total = count_lines(all_subs_file)
    print_success(f"Total unique subdomains: {total}")

    # ── 2.8 LIVE HOST FILTERING WITH HTTPX ──────────────────────
    print_info("Filtering live hosts with httpx (tech detection)...")
    live_file = subs_dir / "live.txt"
    live_full_file = subs_dir / "live_full.txt"   # with title, status, tech

    if which("httpx"):
        # Full details for reporting
        run_cmd(
            f"httpx -l {all_subs_file} -silent -title -status-code -tech-detect "
            f"-content-length -web-server -json -o {live_full_file} -threads {threads}",
            shell=True, timeout=900
        )
        # Clean URL list only
        run_cmd_pipe(
            f"httpx -l {all_subs_file} -silent -threads {threads}",
            output_file=str(live_file)
        )
        live_count = count_lines(live_file)
        print_success(f"Live hosts: {live_count}")

        # Technology summary
        _summarize_technologies(live_full_file, ws)
    else:
        print_skip("httpx — go install github.com/projectdiscovery/httpx/cmd/httpx@latest")


def _summarize_technologies(live_full_file, ws):
    """Parse httpx JSON output and create a technology summary."""
    import json

    tech_summary = {}
    hosts_by_tech = {}

    try:
        with open(live_full_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    url = data.get("url", "")
                    techs = data.get("tech", [])
                    status = data.get("status-code", 0)
                    title = data.get("title", "")

                    for tech in techs:
                        tech_summary[tech] = tech_summary.get(tech, 0) + 1
                        if tech not in hosts_by_tech:
                            hosts_by_tech[tech] = []
                        hosts_by_tech[tech].append(f"{url} ({status}) — {title}")
                except json.JSONDecodeError:
                    continue

        tech_file = ws.path("infrastructure", "tech_stack.txt")
        with open(tech_file, "w") as f:
            f.write("# Technology Stack Summary\n\n")
            for tech, count in sorted(tech_summary.items(), key=lambda x: -x[1]):
                f.write(f"\n## {tech} ({count} hosts)\n")
                for host in hosts_by_tech.get(tech, [])[:20]:
                    f.write(f"  {host}\n")

        print_success(f"Tech stack detected: {', '.join(list(tech_summary.keys())[:8])}")
        _generate_tech_recommendations(list(tech_summary.keys()), ws)

    except Exception as e:
        print_warning(f"Tech summary error: {e}")


def _generate_tech_recommendations(techs, ws):
    """Generate tech-aware manual testing recommendations."""
    recs_file = ws.path("reports", "tech_recommendations.md")
    tech_lower = [t.lower() for t in techs]

    TECH_HINTS = {
        "laravel": [
            "/.env — often exposed with DB credentials",
            "/telescope — Laravel debug panel (check if open)",
            "/horizon — Queue manager (default login: disabled but check)",
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
            "/static/ — check for debug artifacts",
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
            "SSRF → http://169.254.169.254/latest/meta-data/ (if on cloud)",
        ],
        "nginx": [
            "Check for path traversal: /../../../etc/passwd",
            "Server-side request forgery via proxy configs",
            "Off-by-slash: /path vs /path/",
        ],
        "react": [
            "Source maps (.js.map files) — expose full source code",
            "Hardcoded API keys in bundled JS",
            "Redux DevTools state leakage",
        ],
        "graphql": [
            "/__graphql — playground open?",
            "/graphiql — interactive explorer",
            "Introspection query: {__schema{types{name}}}",
            "Batch query attacks, field suggestions abuse",
        ],
    }

    with open(recs_file, "w") as f:
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
