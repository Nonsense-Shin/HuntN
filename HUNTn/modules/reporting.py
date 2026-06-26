"""
HuntN — Module 9: Reporting
Generates the final attack surface report and hunting checklist
"""

import json
from pathlib import Path
from datetime import datetime
from modules.utils import (
    C, print_info, print_success, print_warning, count_lines
)


def run(ctx, elapsed=0):
    target = ctx["target"]
    ws     = ctx["ws"]

    report_file   = ws.path("reports", "attack_surface.md")
    checklist     = ws.path("reports", "hunting_checklist.md")

    # Gather stats
    stats = _gather_stats(ws)

    # Write main report
    _write_attack_surface_report(target, ws, stats, elapsed, report_file)

    # Write hunting checklist
    _write_hunting_checklist(target, ws, stats, checklist)

    print_success(f"Attack surface report → {report_file}")
    print_success(f"Hunting checklist     → {checklist}")

    # Print summary to terminal
    _print_terminal_summary(target, stats, elapsed, ws)


def _gather_stats(ws):
    """Count lines in key output files."""
    return {
        "total_subdomains":  ws.count_lines("subdomains", "all.txt"),
        "live_hosts":        ws.count_lines("subdomains", "live.txt"),
        "open_ports":        ws.count_lines("infrastructure", "ports.txt"),
        "total_urls":        ws.count_lines("web", "all_urls.txt"),
        "live_endpoints":    ws.count_lines("web", "live_endpoints.txt"),
        "js_files":          ws.count_lines("js", "js_files.txt"),
        "secrets_found":     ws.count_lines("js", "secrets.txt"),
        "api_docs":          ws.count_lines("api", "swagger_openapi.txt"),
        "graphql_endpoints": ws.count_lines("api", "graphql.txt"),
        "admin_panels":      ws.count_lines("findings", "admin_panels.txt"),
        "sensitive_files":   ws.count_lines("findings", "sensitive_files.txt"),
        "high_impact_files": ws.count_lines("findings", "high_impact_files.txt"),
        "xss_candidates":    ws.count_lines("gf_filtered", "xss_candidates.txt"),
        "sqli_candidates":   ws.count_lines("gf_filtered", "sqli_candidates.txt"),
        "ssrf_candidates":   ws.count_lines("gf_filtered", "ssrf_candidates.txt"),
        "redirect_cands":    ws.count_lines("gf_filtered", "open_redirect_candidates.txt"),
        "idor_candidates":   ws.count_lines("gf_filtered", "idor_candidates.txt"),
        "cves":              ws.count_lines("nuclei", "cves.txt"),
        "misconfigs":        ws.count_lines("nuclei", "misconfigurations.txt"),
        "default_logins":    ws.count_lines("nuclei", "default_logins.txt"),
        "takeovers":         ws.count_lines("nuclei", "takeovers.txt"),
        "exposures":         ws.count_lines("nuclei", "exposures.txt"),
    }


def _write_attack_surface_report(target, ws, stats, elapsed, report_file):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(report_file, "w") as f:
        f.write(f"# HuntN Attack Surface Report\n")
        f.write(f"**Target:** {target}\n")
        f.write(f"**Scanned:** {ts}\n")
        f.write(f"**Duration:** {elapsed/60:.1f} minutes\n\n")
        f.write("> *\"Even though I walk through the valley of the shadow of death,*\n")
        f.write("> *I will fear no evil, for You are with me.\" — Psalm 23:4*\n\n")
        f.write("---\n\n")

        # ── OVERVIEW ──────────────────────────────────────────────
        f.write("## Overview\n\n")
        f.write(f"| Category | Count |\n")
        f.write(f"|----------|-------|\n")
        f.write(f"| Subdomains discovered | {stats['total_subdomains']} |\n")
        f.write(f"| Live hosts | {stats['live_hosts']} |\n")
        f.write(f"| Open ports | {stats['open_ports']} |\n")
        f.write(f"| Total URLs collected | {stats['total_urls']} |\n")
        f.write(f"| Live endpoints | {stats['live_endpoints']} |\n")
        f.write(f"| JavaScript files | {stats['js_files']} |\n")
        f.write(f"| API/Swagger docs | {stats['api_docs']} |\n")
        f.write(f"| GraphQL endpoints | {stats['graphql_endpoints']} |\n")
        f.write(f"| Admin panels | {stats['admin_panels']} |\n")
        f.write("\n")

        # ── VULNERABILITY FINDINGS ────────────────────────────────
        f.write("## Vulnerability Findings\n\n")
        f.write(f"| Type | Count | Priority |\n")
        f.write(f"|------|-------|----------|\n")

        def prio(n, high_thresh, med_thresh):
            if n >= high_thresh: return "🔴 HIGH"
            if n >= med_thresh:  return "🟡 MEDIUM"
            if n > 0:            return "🟢 LOW"
            return "—"

        f.write(f"| CVEs | {stats['cves']} | {prio(stats['cves'], 1, 0)} |\n")
        f.write(f"| Subdomain Takeovers | {stats['takeovers']} | {prio(stats['takeovers'], 1, 0)} |\n")
        f.write(f"| Default Logins | {stats['default_logins']} | {prio(stats['default_logins'], 1, 0)} |\n")
        f.write(f"| Exposed Secrets | {stats['secrets_found']} | {prio(stats['secrets_found'], 1, 0)} |\n")
        f.write(f"| High-Impact Files | {stats['high_impact_files']} | {prio(stats['high_impact_files'], 5, 1)} |\n")
        f.write(f"| Misconfigurations | {stats['misconfigs']} | {prio(stats['misconfigs'], 5, 1)} |\n")
        f.write(f"| Admin Panels | {stats['admin_panels']} | {prio(stats['admin_panels'], 3, 1)} |\n")
        f.write(f"| Exposures | {stats['exposures']} | {prio(stats['exposures'], 10, 3)} |\n")
        f.write("\n")

        # ── ATTACK VECTOR CANDIDATES ──────────────────────────────
        f.write("## Attack Vector Candidates (for Manual Testing)\n\n")
        f.write(f"| Vector | URLs | File |\n")
        f.write(f"|--------|------|------|\n")
        f.write(f"| XSS | {stats['xss_candidates']} | gf_filtered/xss_candidates.txt |\n")
        f.write(f"| SQLi | {stats['sqli_candidates']} | gf_filtered/sqli_candidates.txt |\n")
        f.write(f"| SSRF | {stats['ssrf_candidates']} | gf_filtered/ssrf_candidates.txt |\n")
        f.write(f"| Open Redirect | {stats['redirect_cands']} | gf_filtered/open_redirect_candidates.txt |\n")
        f.write(f"| IDOR | {stats['idor_candidates']} | gf_filtered/idor_candidates.txt |\n")
        f.write("\n")

        # ── HIGH-VALUE TARGETS ────────────────────────────────────
        f.write("## High-Value Targets\n\n")
        f.write("_Targets to prioritize for manual investigation:_\n\n")
        high_value = _extract_high_value_targets(ws)
        for host in high_value[:20]:
            f.write(f"- `{host}`\n")
        f.write("\n")

        # ── TECH STACK ────────────────────────────────────────────
        f.write("## Technology Stack\n\n")
        tech_file = ws.path("infrastructure", "tech_stack.txt")
        if tech_file.exists():
            with open(tech_file) as tf:
                content = tf.read()
            # Extract just the tech names (lines starting with ##)
            techs = [l.replace("##", "").split("(")[0].strip()
                     for l in content.splitlines() if l.startswith("##")]
            for tech in techs[:15]:
                f.write(f"- {tech}\n")
        else:
            f.write("_Run with web discovery to detect technologies_\n")
        f.write("\n")

        # ── NEXT STEPS ────────────────────────────────────────────
        f.write("## Recommended Next Steps\n\n")
        f.write("1. **Review secrets** — `js/secrets.txt` and `js/secretfinder.txt`\n")
        f.write("2. **Admin panels** — test default credentials (see `nuclei/default_logins.txt`)\n")
        f.write("3. **API endpoints** — load Swagger/OpenAPI into Burp Suite\n")
        f.write("4. **GF candidates** — manually test xss/sqli/ssrf/redirect candidates\n")
        f.write("5. **Tech recommendations** — see `reports/tech_recommendations.md`\n")
        f.write("6. **Manual OSINT** — complete `intelligence/manual_osint_checklist.md`\n")
        f.write("7. **GitHub dorking** — check `intelligence/github_dorks.txt`\n")
        f.write("8. **Cloud** — verify S3/Azure/GCP findings in `cloud/`\n\n")

        f.write("---\n")
        f.write(f"*Generated by HuntN — The Hand of Light Uncovering Darkness*\n")


def _write_hunting_checklist(target, ws, stats, checklist_file):
    """Write an actionable manual hunting checklist."""

    with open(checklist_file, "w") as f:
        f.write(f"# Manual Hunting Checklist — {target}\n\n")

        f.write("## Phase 1: Review Automated Findings\n")
        f.write("- [ ] Read `intelligence/manual_osint_checklist.md` and complete OSINT tasks\n")
        f.write("- [ ] Check `js/secrets.txt` — any real API keys/tokens?\n")
        f.write("- [ ] Review `nuclei/cves.txt` — any exploitable CVEs?\n")
        f.write("- [ ] Review `nuclei/takeovers.txt` — claim any takeovers?\n")
        f.write("- [ ] Review `nuclei/default_logins.txt` — any working logins?\n")
        f.write("- [ ] Review `findings/high_impact_files.txt` — accessible?\n")
        f.write("- [ ] Review `findings/admin_panels.txt` — test login pages\n\n")

        f.write("## Phase 2: API Testing\n")
        f.write("- [ ] Load `api/swagger_openapi.txt` endpoints into Burp Suite\n")
        f.write("- [ ] Test GraphQL introspection (see `api/graphql_introspection.txt`)\n")
        f.write("- [ ] Check `api/api_routes.txt` — test IDOR on user IDs\n")
        f.write("- [ ] Review `api/manual_api_checklist.md`\n")
        f.write("- [ ] Try JWT algorithm confusion on authenticated endpoints\n")
        f.write("- [ ] Test mass assignment: add `admin:true` or `role:admin` to JSON bodies\n\n")

        f.write("## Phase 3: Attack Vector Testing\n")
        f.write(f"- [ ] XSS candidates ({stats['xss_candidates']}) — test `gf_filtered/xss_candidates.txt`\n")
        f.write(f"- [ ] SQLi candidates ({stats['sqli_candidates']}) — test `gf_filtered/sqli_candidates.txt`\n")
        f.write(f"- [ ] SSRF candidates ({stats['ssrf_candidates']}) — test `gf_filtered/ssrf_candidates.txt`\n")
        f.write(f"- [ ] Open redirects ({stats['redirect_cands']}) — test `gf_filtered/open_redirect_candidates.txt`\n")
        f.write(f"- [ ] IDOR candidates ({stats['idor_candidates']}) — test `gf_filtered/idor_candidates.txt`\n\n")

        f.write("## Phase 4: Business Logic & Deep Testing\n")
        f.write("- [ ] Authentication bypass: parameter manipulation on login\n")
        f.write("- [ ] IDOR: change user IDs in all API calls\n")
        f.write("- [ ] Rate limiting: test on registration, login, password reset\n")
        f.write("- [ ] Account takeover flows: password reset, OAuth, email change\n")
        f.write("- [ ] Privilege escalation: horizontal & vertical\n")
        f.write("- [ ] CORS misconfig: check headers with Origin: evil.com\n")
        f.write("- [ ] CSRF: check for missing/bypassable tokens\n\n")

        f.write("## Phase 5: Cloud & Infrastructure\n")
        f.write("- [ ] Review `cloud/s3_buckets.txt` — any open/listable buckets?\n")
        f.write("- [ ] Check `cloud/firebase.txt` — any open Firebase databases?\n")
        f.write("- [ ] Review `cloud/ssrf_cloud_hints.md` for metadata SSRF paths\n")
        f.write("- [ ] Check `infrastructure/tls.txt` — weak cipher suites?\n\n")

        f.write("## Quick Reference Commands\n")
        f.write("```bash\n")
        f.write(f"# Re-run nuclei on specific template\n")
        f.write(f"nuclei -l HuntN_{target}/subdomains/live.txt -t cves/ -severity critical\n\n")
        f.write(f"# Test XSS manually\n")
        f.write(f"cat HuntN_{target}/gf_filtered/xss_candidates.txt | Gxss -p '<script>alert(1)</script>'\n\n")
        f.write(f"# API fuzzing\n")
        f.write(f"ffuf -u TARGET/FUZZ -w ~/wordlists/api.txt -H 'Authorization: Bearer TOKEN' -mc 200,401,403\n")
        f.write("```\n")


def _extract_high_value_targets(ws):
    """Extract high-priority targets from various output files."""
    high_value = set()

    # Admin panels
    for line in ws.read("findings", "admin_panels.txt"):
        if line.strip():
            high_value.add(line.strip().split()[0])

    # GraphQL endpoints
    for line in ws.read("api", "graphql.txt"):
        if line.strip():
            high_value.add(line.strip().split()[0])

    # Swagger/API docs
    for line in ws.read("api", "swagger_openapi.txt"):
        if line.strip():
            high_value.add(line.strip().split()[0])

    # CVE-affected hosts
    for line in ws.read("nuclei", "cves.txt"):
        if line.strip() and "[" in line:
            parts = line.strip().split()
            if len(parts) >= 3:
                high_value.add(parts[-1])

    return sorted(high_value)


def _print_terminal_summary(target, stats, elapsed, ws):
    """Print a clean summary to the terminal."""
    print(f"\n{C.CYAN}{'='*65}{C.NC}")
    print(f"{C.BOLD}{C.YELLOW}  HUNT SUMMARY — {target.upper()}{C.NC}")
    print(f"{C.CYAN}{'='*65}{C.NC}")

    def stat_line(label, value, highlight_if_gt=0):
        if value > highlight_if_gt and highlight_if_gt >= 0:
            color = C.GREEN
        else:
            color = C.GRAY
        print(f"  {label:<30} {color}{value}{C.NC}")

    stat_line("Subdomains",          stats["total_subdomains"])
    stat_line("Live Hosts",          stats["live_hosts"])
    stat_line("Total URLs",          stats["total_urls"])
    stat_line("JS Files",            stats["js_files"])
    stat_line("API/Swagger Docs",    stats["api_docs"])
    stat_line("GraphQL Endpoints",   stats["graphql_endpoints"])
    stat_line("Admin Panels",        stats["admin_panels"])

    print(f"\n  {C.BOLD}Nuclei Findings:{C.NC}")
    stat_line("  CVEs",              stats["cves"])
    stat_line("  Takeovers",         stats["takeovers"])
    stat_line("  Default Logins",    stats["default_logins"])
    stat_line("  Misconfigs",        stats["misconfigs"])
    stat_line("  Exposures",         stats["exposures"])
    stat_line("  Secrets Found",     stats["secrets_found"])

    print(f"\n  {C.BOLD}Attack Vectors:{C.NC}")
    stat_line("  XSS Candidates",    stats["xss_candidates"])
    stat_line("  SQLi Candidates",   stats["sqli_candidates"])
    stat_line("  SSRF Candidates",   stats["ssrf_candidates"])
    stat_line("  IDOR Candidates",   stats["idor_candidates"])
    stat_line("  Open Redirects",    stats["redirect_cands"])

    print(f"\n  {C.CYAN}Duration: {elapsed/60:.1f} minutes{C.NC}")
    print(f"  {C.CYAN}Output:   HuntN_{target}/{C.NC}")
    print(f"\n  {C.YELLOW}Start here → reports/attack_surface.md{C.NC}")
    print(f"  {C.YELLOW}Then work → reports/hunting_checklist.md{C.NC}")
    print(f"{C.CYAN}{'='*65}{C.NC}\n")
