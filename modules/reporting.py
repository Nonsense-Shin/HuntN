"""
HuntN — Module 9: Reporting
Generates the final attack surface report and hunting checklist.

Changes from previous version:
  - Same stats contract (_gather_stats keys unchanged — nothing else in the
    pipeline breaks from this file).
  - Report now opens with a narrative verdict instead of a cold table dump:
    a one-line headline + a short human summary of what actually happened.
  - Sections are conditional: empty categories collapse to a single line
    instead of an empty table, so the report shrinks/grows with the findings
    instead of always looking the same regardless of result.
  - Hunting checklist now orders itself by what's actually worth chasing
    first (real findings > probable leads > standard checklist), instead of
    a fixed phase order regardless of what was found.
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

    report_file = ws.path("reports", "attack_surface.md")
    checklist   = ws.path("reports", "hunting_checklist.md")

    stats = _gather_stats(ws)

    _write_attack_surface_report(target, ws, stats, elapsed, report_file)
    _write_hunting_checklist(target, ws, stats, checklist)

    print_success(f"Attack surface report → {report_file}")
    print_success(f"Hunting checklist     → {checklist}")

    _print_terminal_summary(target, stats, elapsed, ws)


def _gather_stats(ws):
    """Count lines in key output files. Keys are load-bearing — other code
    (and the terminal summary) reads these exact names, don't rename."""
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


# ── VERDICT ENGINE — turns raw counts into a headline + tone ──────────────

def _verdict(stats):
    """
    Decide the headline tone for the report based on what was actually
    found. Returns (emoji, headline, one-line summary).
    """
    critical_hits = (stats["cves"] + stats["takeovers"] +
                      stats["default_logins"] + stats["secrets_found"])
    soft_hits = (stats["admin_panels"] + stats["high_impact_files"] +
                 stats["misconfigs"] + stats["api_docs"] + stats["graphql_endpoints"])
    leads = (stats["xss_candidates"] + stats["sqli_candidates"] +
             stats["ssrf_candidates"] + stats["idor_candidates"] + stats["redirect_cands"])

    if critical_hits > 0:
        return (
            "🔴", "Hot target — go straight to the findings",
            f"{critical_hits} high-confidence hit(s) — CVEs, takeovers, default "
            f"logins, or leaked secrets. Don't keep scanning, go verify these first."
        )
    if soft_hits >= 3:
        return (
            "🟡", "Worth the time — several real leads",
            f"No slam-dunk yet, but {soft_hits} exposed surfaces (admin panels, "
            f"misconfigs, API docs) worth manually poking before moving on."
        )
    if leads > 0:
        return (
            "🟢", "Quiet so far — fuzzing material only",
            f"{leads} parameterized URL(s) flagged for XSS/SQLi/SSRF/IDOR shape. "
            f"Nothing confirmed — these need a human with Burp, not another scan."
        )
    return (
        "⚪", "Looks hardened — or the scan came up short",
        "No findings of any kind. If the target is small or you expected more, "
        "check the discovery counts below before trusting a clean result."
    )


def _section_health(stats, target):
    """
    Sanity-check the discovery pipeline itself — if upstream stages produced
    nothing, downstream zero-findings doesn't mean the target is clean, it
    means there was nothing to scan. Surfaces that distinction explicitly.
    """
    notes = []
    if stats["live_hosts"] == 0:
        notes.append("No live hosts recorded — every later stage had nothing to work with.")
    elif stats["total_urls"] == 0:
        notes.append("0 URLs collected despite live hosts — web discovery likely didn't run "
                      "or its output wasn't picked up. Findings below should not be read as 'clean'.")
    elif stats["js_files"] == 0 and stats["total_urls"] > 0:
        notes.append("URLs were collected but 0 JS files identified — check js/js_files.txt "
                      "filtering if this target is known to ship JS.")
    return notes


def _write_attack_surface_report(target, ws, stats, elapsed, report_file):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    emoji, headline, blurb = _verdict(stats)
    health_notes = _section_health(stats, target)

    with open(report_file, "w") as f:
        f.write(f"# HuntN Attack Surface Report — {target}\n")
        f.write(f"*{ts} · {elapsed/60:.1f} min scan*\n\n")

        # ── HEADLINE ──────────────────────────────────────────────
        f.write(f"## {emoji} {headline}\n\n")
        f.write(f"{blurb}\n\n")

        if health_notes:
            f.write("> **Before you read the rest:**\n")
            for n in health_notes:
                f.write(f"> ⚠️ {n}\n")
            f.write("\n")

        f.write("---\n\n")

        # ── TL;DR — only the categories that actually have something ──
        f.write("## TL;DR\n\n")
        highlights = _build_highlights(stats)
        if highlights:
            for line in highlights:
                f.write(f"- {line}\n")
        else:
            f.write("_Nothing stood out — see the discovery numbers below to judge "
                    "whether that's a clean target or a thin scan._\n")
        f.write("\n---\n\n")

        # ── DISCOVERY FOOTPRINT ───────────────────────────────────
        f.write("## Discovery Footprint\n\n")
        f.write("How much of the target was actually mapped this run.\n\n")
        f.write("| Category | Count |\n|----------|-------|\n")
        f.write(f"| Subdomains discovered | {stats['total_subdomains']} |\n")
        f.write(f"| Live hosts | {stats['live_hosts']} |\n")
        f.write(f"| Open ports | {stats['open_ports']} |\n")
        f.write(f"| Total URLs collected | {stats['total_urls']} |\n")
        f.write(f"| Live endpoints | {stats['live_endpoints']} |\n")
        f.write(f"| JavaScript files | {stats['js_files']} |\n")
        f.write(f"| API/Swagger docs | {stats['api_docs']} |\n")
        f.write(f"| GraphQL endpoints | {stats['graphql_endpoints']} |\n")
        f.write(f"| Admin panels | {stats['admin_panels']} |\n\n")

        # ── CONFIRMED FINDINGS (only render if non-empty) ─────────
        confirmed = [
            ("CVEs",                 stats["cves"],           "nuclei/cves.txt"),
            ("Subdomain Takeovers",  stats["takeovers"],      "nuclei/takeovers.txt"),
            ("Default Logins",       stats["default_logins"], "nuclei/default_logins.txt"),
            ("Exposed Secrets",      stats["secrets_found"],  "js/secrets.txt"),
        ]
        hot = [(n, c, p) for n, c, p in confirmed if c > 0]
        f.write("## Confirmed Findings\n\n")
        if hot:
            f.write("_These are real — go verify them before doing anything else._\n\n")
            f.write("| Type | Count | File |\n|------|-------|------|\n")
            for name, cnt, fp in hot:
                f.write(f"| {name} | {cnt} | `{fp}` |\n")
        else:
            f.write("_None this run. Doesn't mean the target's clean — "
                    "see Discovery Footprint above for scan depth._\n")
        f.write("\n")

        # ── SOFT FINDINGS / EXPOSURE SURFACE ───────────────────────
        soft = [
            ("High-Impact Files", stats["high_impact_files"], "findings/high_impact_files.txt"),
            ("Misconfigurations", stats["misconfigs"],         "nuclei/misconfigurations.txt"),
            ("Exposures",         stats["exposures"],          "nuclei/exposures.txt"),
            ("Admin Panels",      stats["admin_panels"],       "findings/admin_panels.txt"),
        ]
        soft_hit = [(n, c, p) for n, c, p in soft if c > 0]
        if soft_hit:
            f.write("## Exposure Surface (manual review)\n\n")
            f.write("| Type | Count | File |\n|------|-------|------|\n")
            for name, cnt, fp in soft_hit:
                f.write(f"| {name} | {cnt} | `{fp}` |\n")
            f.write("\n")

        # ── ATTACK VECTOR CANDIDATES ───────────────────────────────
        vectors = [
            ("XSS",           stats["xss_candidates"], "gf_filtered/xss_candidates.txt"),
            ("SQLi",          stats["sqli_candidates"], "gf_filtered/sqli_candidates.txt"),
            ("SSRF",          stats["ssrf_candidates"], "gf_filtered/ssrf_candidates.txt"),
            ("Open Redirect", stats["redirect_cands"],  "gf_filtered/open_redirect_candidates.txt"),
            ("IDOR",          stats["idor_candidates"], "gf_filtered/idor_candidates.txt"),
        ]
        vec_hit = [(n, c, p) for n, c, p in vectors if c > 0]
        f.write("## Attack Vector Candidates (need a human)\n\n")
        if vec_hit:
            f.write("| Vector | URLs | File |\n|--------|------|------|\n")
            for name, cnt, fp in vec_hit:
                f.write(f"| {name} | {cnt} | `{fp}` |\n")
        else:
            f.write("_No parameterized URLs matched fuzzing patterns. "
                    "Check gf_filtered/ — if it's all empty, gf pattern files may "
                    "not be installed (~/.gf)._\n")
        f.write("\n")

        # ── HIGH-VALUE TARGETS ──────────────────────────────────────
        high_value = _extract_high_value_targets(ws)
        f.write("## High-Value Targets\n\n")
        if high_value:
            f.write("_Hosts that showed up in admin/API/GraphQL/CVE results — start here:_\n\n")
            for host in high_value[:20]:
                f.write(f"- `{host}`\n")
        else:
            f.write("_No standout hosts identified yet._\n")
        f.write("\n")

        # ── TECH STACK ───────────────────────────────────────────────
        f.write("## Technology Stack\n\n")
        tech_file = ws.path("infrastructure", "tech_stack.txt")
        if tech_file.exists():
            content = tech_file.read_text(errors="ignore")
            techs = [l.replace("##", "").split("(")[0].strip()
                     for l in content.splitlines() if l.startswith("##")]
            if techs:
                for tech in techs[:15]:
                    f.write(f"- {tech}\n")
            else:
                f.write("_Tech stack file present but empty._\n")
        else:
            f.write("_Run infrastructure/web discovery to populate this._\n")
        f.write("\n---\n\n")

        # ── NEXT STEPS — ordered by what's actually worth doing ──────
        f.write("## What To Do Next\n\n")
        for i, step in enumerate(_build_next_steps(stats), 1):
            f.write(f"{i}. {step}\n")
        f.write("\n---\n")
        f.write("*Generated by HuntN — The Hand of Light Uncovering Darkness*\n")


def _build_highlights(stats):
    """Plain-English bullets for whatever actually has a count > 0."""
    lines = []
    if stats["secrets_found"]:
        lines.append(f"**{stats['secrets_found']} secret(s)** found in JS — check `js/secrets.txt` first.")
    if stats["cves"]:
        lines.append(f"**{stats['cves']} CVE(s)** matched — see `nuclei/cves.txt`.")
    if stats["takeovers"]:
        lines.append(f"**{stats['takeovers']} possible subdomain takeover(s)** — see `nuclei/takeovers.txt`.")
    if stats["default_logins"]:
        lines.append(f"**{stats['default_logins']} default login(s)** still active — see `nuclei/default_logins.txt`.")
    if stats["admin_panels"]:
        lines.append(f"{stats['admin_panels']} admin panel(s) exposed — see `findings/admin_panels.txt`.")
    if stats["graphql_endpoints"]:
        lines.append(f"{stats['graphql_endpoints']} GraphQL endpoint(s) — test introspection.")
    if stats["api_docs"]:
        lines.append(f"{stats['api_docs']} Swagger/OpenAPI doc(s) — load straight into Burp.")
    total_vec = (stats["xss_candidates"] + stats["sqli_candidates"] +
                 stats["ssrf_candidates"] + stats["idor_candidates"] + stats["redirect_cands"])
    if total_vec:
        lines.append(f"{total_vec} parameterized URL(s) flagged for manual fuzzing.")
    return lines


def _build_next_steps(stats):
    """Priority-ordered action list — real findings bump to the top."""
    steps = []
    if stats["secrets_found"]:
        steps.append("**Verify exposed secrets** — `js/secrets.txt` — rotate/report anything real immediately.")
    if stats["default_logins"]:
        steps.append("**Try the default logins** — `nuclei/default_logins.txt`.")
    if stats["takeovers"]:
        steps.append("**Claim the subdomain takeover(s)** — `nuclei/takeovers.txt`.")
    if stats["cves"]:
        steps.append("**Check CVE exploitability** — `nuclei/cves.txt`.")
    if stats["admin_panels"]:
        steps.append("**Probe admin panels** — `findings/admin_panels.txt` — default creds, auth bypass.")
    if stats["api_docs"] or stats["graphql_endpoints"]:
        steps.append("**Load API surface into Burp** — `api/swagger_openapi.txt`, test GraphQL introspection.")
    total_vec = (stats["xss_candidates"] + stats["sqli_candidates"] +
                 stats["ssrf_candidates"] + stats["idor_candidates"] + stats["redirect_cands"])
    if total_vec:
        steps.append("**Manually test gf_filtered/ candidates** — XSS/SQLi/SSRF/IDOR/redirects.")
    # Always-relevant standing tasks
    steps.append("Complete `intelligence/manual_osint_checklist.md`.")
    steps.append("Check `intelligence/github_dorks.txt` for source leaks.")
    steps.append("Verify any S3/Azure/GCP/Firebase hits in `cloud/`.")
    return steps


def _write_hunting_checklist(target, ws, stats, checklist_file):
    """Actionable manual hunting checklist, ordered by what's worth chasing."""
    with open(checklist_file, "w") as f:
        f.write(f"# Manual Hunting Checklist — {target}\n\n")
        emoji, headline, _ = _verdict(stats)
        f.write(f"**Status:** {emoji} {headline}\n\n")

        f.write("## Priority Queue (do these first)\n")
        for step in _build_next_steps(stats)[:5]:
            f.write(f"- [ ] {step}\n")
        f.write("\n")

        f.write("## Phase 1: Review Automated Findings\n")
        f.write("- [ ] Read `intelligence/manual_osint_checklist.md`\n")
        f.write("- [ ] Check `js/secrets.txt` — any real API keys/tokens?\n")
        f.write("- [ ] Review `nuclei/cves.txt` — any exploitable CVEs?\n")
        f.write("- [ ] Review `nuclei/takeovers.txt` — claim any takeovers?\n")
        f.write("- [ ] Review `nuclei/default_logins.txt` — any working logins?\n")
        f.write("- [ ] Review `findings/high_impact_files.txt` — accessible?\n")
        f.write("- [ ] Review `findings/admin_panels.txt` — test login pages\n\n")

        f.write("## Phase 2: API Testing\n")
        f.write("- [ ] Load `api/swagger_openapi.txt` endpoints into Burp Suite\n")
        f.write("- [ ] Test GraphQL introspection (`api/graphql_introspection.txt`)\n")
        f.write("- [ ] Check `api/api_routes.txt` — test IDOR on user IDs\n")
        f.write("- [ ] Review `api/manual_api_checklist.md`\n")
        f.write("- [ ] Try JWT algorithm confusion on authenticated endpoints\n")
        f.write("- [ ] Test mass assignment: add `admin:true`/`role:admin` to JSON bodies\n\n")

        f.write("## Phase 3: Attack Vector Testing\n")
        f.write(f"- [ ] XSS ({stats['xss_candidates']}) — `gf_filtered/xss_candidates.txt`\n")
        f.write(f"- [ ] SQLi ({stats['sqli_candidates']}) — `gf_filtered/sqli_candidates.txt`\n")
        f.write(f"- [ ] SSRF ({stats['ssrf_candidates']}) — `gf_filtered/ssrf_candidates.txt`\n")
        f.write(f"- [ ] Open redirects ({stats['redirect_cands']}) — `gf_filtered/open_redirect_candidates.txt`\n")
        f.write(f"- [ ] IDOR ({stats['idor_candidates']}) — `gf_filtered/idor_candidates.txt`\n\n")

        f.write("## Phase 4: Business Logic & Deep Testing\n")
        f.write("- [ ] Authentication bypass: parameter manipulation on login\n")
        f.write("- [ ] IDOR: change user IDs in all API calls\n")
        f.write("- [ ] Rate limiting: registration, login, password reset\n")
        f.write("- [ ] Account takeover flows: password reset, OAuth, email change\n")
        f.write("- [ ] Privilege escalation: horizontal & vertical\n")
        f.write("- [ ] CORS misconfig: check headers with Origin: evil.com\n")
        f.write("- [ ] CSRF: missing/bypassable tokens\n\n")

        f.write("## Phase 5: Cloud & Infrastructure\n")
        f.write("- [ ] Review `cloud/s3_buckets.txt` — open/listable buckets?\n")
        f.write("- [ ] Check `cloud/firebase.txt` — open Firebase databases?\n")
        f.write("- [ ] Review `cloud/ssrf_cloud_hints.md` for metadata SSRF paths\n")
        f.write("- [ ] Check `infrastructure/tls.txt` — weak cipher suites?\n\n")

        f.write("## Quick Reference Commands\n")
        f.write("```bash\n")
        f.write("# Re-run nuclei on specific template\n")
        f.write(f"nuclei -l HuntN_{target}/subdomains/live.txt -t cves/ -severity critical\n\n")
        f.write("# Test XSS manually\n")
        f.write(f"cat HuntN_{target}/gf_filtered/xss_candidates.txt | Gxss -p '<script>alert(1)</script>'\n\n")
        f.write("# API fuzzing\n")
        f.write("ffuf -u TARGET/FUZZ -w ~/wordlists/api.txt -H 'Authorization: Bearer TOKEN' -mc 200,401,403\n")
        f.write("```\n")


def _extract_high_value_targets(ws):
    """Extract high-priority targets from various output files."""
    high_value = set()
    for line in ws.read("findings", "admin_panels.txt"):
        if line.strip():
            high_value.add(line.strip().split()[0])
    for line in ws.read("api", "graphql.txt"):
        if line.strip():
            high_value.add(line.strip().split()[0])
    for line in ws.read("api", "swagger_openapi.txt"):
        if line.strip():
            high_value.add(line.strip().split()[0])
    for line in ws.read("nuclei", "cves.txt"):
        if line.strip() and "[" in line:
            parts = line.strip().split()
            if len(parts) >= 3:
                high_value.add(parts[-1])
    return sorted(high_value)


def _print_terminal_summary(target, stats, elapsed, ws):
    """Print a clean, verdict-led summary to the terminal."""
    emoji, headline, blurb = _verdict(stats)

    print(f"\n{C.CYAN}{'='*65}{C.NC}")
    print(f"{C.BOLD}{C.YELLOW}  HUNT SUMMARY — {target.upper()}{C.NC}")
    print(f"{C.CYAN}{'='*65}{C.NC}")
    print(f"\n  {emoji}  {C.BOLD}{headline}{C.NC}")
    print(f"  {C.GRAY}{blurb}{C.NC}\n")

    def stat_line(label, value):
        color = C.GREEN if value > 0 else C.GRAY
        print(f"  {label:<30} {color}{value}{C.NC}")

    stat_line("Subdomains",        stats["total_subdomains"])
    stat_line("Live Hosts",        stats["live_hosts"])
    stat_line("Total URLs",        stats["total_urls"])
    stat_line("JS Files",          stats["js_files"])
    stat_line("API/Swagger Docs",  stats["api_docs"])
    stat_line("GraphQL Endpoints", stats["graphql_endpoints"])
    stat_line("Admin Panels",      stats["admin_panels"])

    print(f"\n  {C.BOLD}Nuclei Findings:{C.NC}")
    stat_line("  CVEs",           stats["cves"])
    stat_line("  Takeovers",      stats["takeovers"])
    stat_line("  Default Logins", stats["default_logins"])
    stat_line("  Misconfigs",     stats["misconfigs"])
    stat_line("  Exposures",      stats["exposures"])
    stat_line("  Secrets Found",  stats["secrets_found"])

    print(f"\n  {C.BOLD}Attack Vectors:{C.NC}")
    stat_line("  XSS Candidates",  stats["xss_candidates"])
    stat_line("  SQLi Candidates", stats["sqli_candidates"])
    stat_line("  SSRF Candidates", stats["ssrf_candidates"])
    stat_line("  IDOR Candidates", stats["idor_candidates"])
    stat_line("  Open Redirects",  stats["redirect_cands"])

    print(f"\n  {C.CYAN}Duration: {elapsed/60:.1f} minutes{C.NC}")
    print(f"  {C.CYAN}Output:   HuntN_{target}/{C.NC}")
    print(f"\n  {C.YELLOW}Start here → reports/attack_surface.md{C.NC}")
    print(f"  {C.YELLOW}Then work  → reports/hunting_checklist.md{C.NC}")
    print(f"{C.CYAN}{'='*65}{C.NC}\n")
