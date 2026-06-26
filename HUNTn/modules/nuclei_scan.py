"""
HuntN — Module 8: Vulnerability Discovery
Covers: Nuclei against live hosts, CVEs, misconfigs, default-logins,
        exposures, takeovers, tech-specific templates,
        filtered endpoint scanning (from GF output)
"""

from pathlib import Path
from modules.utils import (
    C, print_info, print_success, print_warning, print_skip, print_find,
    run_cmd, run_cmd_pipe, which, count_lines
)


def run(ctx):
    target   = ctx["target"]
    ws       = ctx["ws"]
    severity = ctx.get("severity", "medium,high,critical")
    threads  = ctx["threads"]

    nuclei_dir = ws.path("nuclei")
    live_file  = ws.path("subdomains", "live.txt")
    gf_dir     = ws.path("gf_filtered")
    findings   = ws.path("findings")

    if not which("nuclei"):
        print_skip("nuclei — go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return

    # Ensure templates are fresh
    print_info("Updating nuclei templates...")
    run_cmd_pipe("nuclei -update-templates -silent", output_file="/dev/null")

    if not live_file.exists():
        print_warning("No live hosts file found — run subdomain enumeration first")
        return

    sev_flag = f"-severity {severity}"

    # ── 8.1 CVE SCAN ON LIVE HOSTS ───────────────────────────────
    print_info("CVE scanning on live hosts...")
    cve_file = nuclei_dir / "cves.txt"
    run_cmd_pipe(
        f"nuclei -l {live_file} -t cves/ {sev_flag} -silent "
        f"-es info,low -o {cve_file}",
        output_file=str(cve_file)
    )
    n = count_lines(cve_file)
    if n > 0:
        print_find(f"CVEs found: {n} — {cve_file.name}")

    # ── 8.2 MISCONFIGURATIONS ─────────────────────────────────────
    print_info("Scanning for misconfigurations...")
    misconfig_file = nuclei_dir / "misconfigurations.txt"
    run_cmd_pipe(
        f"nuclei -l {live_file} -t misconfiguration/ -silent "
        f"-es info,low -o {misconfig_file}",
        output_file=str(misconfig_file)
    )
    n = count_lines(misconfig_file)
    print_success(f"Misconfigs: {n}")

    # ── 8.3 DEFAULT LOGINS ────────────────────────────────────────
    print_info("Checking for default logins...")
    default_login_file = nuclei_dir / "default_logins.txt"
    run_cmd_pipe(
        f"nuclei -l {live_file} -t misconfiguration/default-login/ -silent "
        f"-o {default_login_file}",
        output_file=str(default_login_file)
    )
    n = count_lines(default_login_file)
    if n > 0:
        print_find(f"Default logins found: {n}")

    # ── 8.4 EXPOSURES ─────────────────────────────────────────────
    print_info("Scanning for exposed files and configs...")
    exposures_file = nuclei_dir / "exposures.txt"
    run_cmd_pipe(
        f"nuclei -l {live_file} -t exposures/ -silent "
        f"-es info -o {exposures_file}",
        output_file=str(exposures_file)
    )
    n = count_lines(exposures_file)
    if n > 0:
        print_find(f"Exposures found: {n}")

    # ── 8.5 SUBDOMAIN TAKEOVERS ───────────────────────────────────
    print_info("Checking for subdomain takeovers...")
    takeovers_file = nuclei_dir / "takeovers.txt"
    run_cmd_pipe(
        f"nuclei -l {live_file} -t takeovers/ -silent -o {takeovers_file}",
        output_file=str(takeovers_file)
    )
    n = count_lines(takeovers_file)
    if n > 0:
        print_find(f"POTENTIAL TAKEOVERS: {n} — CHECK IMMEDIATELY")

    # ── 8.6 TECHNOLOGIES & PANELS ─────────────────────────────────
    print_info("Scanning for exposed panels and technologies...")
    panels_file = nuclei_dir / "exposed_panels.txt"
    run_cmd_pipe(
        f"nuclei -l {live_file} -t http/exposed-panels/ -silent "
        f"-o {panels_file}",
        output_file=str(panels_file)
    )
    n = count_lines(panels_file)
    if n > 0:
        print_find(f"Exposed panels: {n}")

    # ── 8.7 API-SPECIFIC TEMPLATES ────────────────────────────────
    api_docs_file = ws.path("api", "swagger_openapi.txt")
    if api_docs_file.exists() and count_lines(api_docs_file) > 0:
        print_info("Running nuclei on API documentation endpoints...")
        api_nuclei_file = nuclei_dir / "api_vulnerabilities.txt"
        run_cmd_pipe(
            f"nuclei -l {api_docs_file} -t exposures/apis/ -t http/vulnerabilities/ "
            f"-silent -o {api_nuclei_file}",
            output_file=str(api_nuclei_file)
        )
        n = count_lines(api_nuclei_file)
        if n > 0:
            print_find(f"API vulnerabilities: {n}")

    # ── 8.8 JS FILE SCANNING ──────────────────────────────────────
    js_file = ws.path("js", "js_files.txt")
    if js_file.exists() and count_lines(js_file) > 0:
        print_info("Running nuclei on JS files for secret exposure...")
        js_nuclei_file = nuclei_dir / "js_exposure.txt"
        run_cmd_pipe(
            f"nuclei -l {js_file} -t exposures/ -t technologies/ "
            f"-silent -o {js_nuclei_file}",
            output_file=str(js_nuclei_file)
        )

    # ── 8.9 ADMIN PANELS ─────────────────────────────────────────
    admin_file = findings / "admin_panels.txt"
    if admin_file.exists() and count_lines(admin_file) > 0:
        print_info("Running nuclei on admin panels...")
        admin_nuclei = nuclei_dir / "admin_panels.txt"
        run_cmd_pipe(
            f"nuclei -l {admin_file} -t misconfiguration/default-login/ "
            f"-t http/exposed-panels/ -silent -o {admin_nuclei}",
            output_file=str(admin_nuclei)
        )
        n = count_lines(admin_nuclei)
        if n > 0:
            print_find(f"Admin panel issues: {n}")

    # ── 8.10 LIVE ENDPOINT SCANNING (from GF) ────────────────────
    print_info("Nuclei scan on GF-filtered endpoints...")
    live_endpoints = ws.path("web", "live_endpoints.txt")

    if live_endpoints.exists() and count_lines(live_endpoints) > 0:
        endpoint_nuclei = nuclei_dir / "endpoint_vulns.txt"
        run_cmd_pipe(
            f"nuclei -l {live_endpoints} "
            f"-t http/vulnerabilities/generic/open-redirect-generic.yaml "
            f"-t http/vulnerabilities/generic/generic-lfi.yaml "
            f"-t cves/ {sev_flag} -silent -o {endpoint_nuclei}",
            output_file=str(endpoint_nuclei)
        )
        n = count_lines(endpoint_nuclei)
        if n > 0:
            print_find(f"Endpoint vulnerabilities: {n}")

    # ── 8.11 OPEN REDIRECT CANDIDATES ────────────────────────────
    redirect_file = gf_dir / "open_redirect_candidates.txt"
    if redirect_file.exists() and count_lines(redirect_file) > 0:
        print_info("Testing open redirect candidates...")
        redir_nuclei = nuclei_dir / "open_redirects.txt"
        run_cmd_pipe(
            f"nuclei -l {redirect_file} "
            f"-t http/vulnerabilities/generic/open-redirect-generic.yaml "
            f"-silent -o {redir_nuclei}",
            output_file=str(redir_nuclei)
        )
        n = count_lines(redir_nuclei)
        if n > 0:
            print_find(f"Open redirects confirmed: {n}")

    # ── 8.12 XSS REFLECTION CHECK ─────────────────────────────────
    xss_file = gf_dir / "xss_candidates.txt"
    if xss_file.exists() and count_lines(xss_file) > 0 and which("Gxss"):
        print_info("Checking XSS parameter reflection with Gxss...")
        gxss_file = nuclei_dir / "xss_reflected.txt"
        run_cmd_pipe(
            f"cat {xss_file} | Gxss -p 'HuntN' -o {gxss_file}",
            output_file=str(gxss_file)
        )
        n = count_lines(gxss_file)
        if n > 0:
            print_find(f"XSS-reflected parameters: {n} — manual testing needed")
        print_info("XSS automation disabled — review gxss_file and test manually")

    print_success("Vulnerability scanning complete.\n")
