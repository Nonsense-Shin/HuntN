"""
HuntN — Module 1: Passive OSINT & Domain Intelligence
──────────────────────────────────────────────────────────────────────────────
Covers: WHOIS, DNS, ASN, crt.sh, OTX, VirusTotal, URLScan, Shodan, dork lists
"""

import subprocess
import json
import urllib.request
import urllib.parse
from pathlib import Path
from modules.utils import (
    C, print_info, print_success, print_warning, print_error,
    print_find, print_skip, run_cmd, run_cmd_pipe, which, curl_json
)


def run(ctx):
    target = ctx["target"]
    ws     = ctx["ws"]
    config = ctx["config"]
    apis   = config.get("apis", {})

    # ── 1.1 WHOIS ─────────────────────────────────────────────────────────────
    print_info("WHOIS lookup...")
    if which("whois"):
        run_cmd(
            ["whois", target],
            output_file=str(ws.path("intelligence", "whois.txt"))
        )
        print_success("whois.txt saved")
    else:
        print_skip("whois not found — sudo apt install whois")

    # ── 1.2 DNS RECORDS ───────────────────────────────────────────────────────
    print_info("DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA)...")
    dns_file = ws.path("intelligence", "dns.txt")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
    with open(dns_file, "w") as f:
        for rtype in record_types:
            result = subprocess.run(
                ["dig", "+noall", "+answer", rtype, target],
                capture_output=True, text=True
            )
            if result.stdout.strip():
                f.write(f"\n;; {rtype} Records\n")
                f.write(result.stdout)
    print_success(f"DNS records → {dns_file.name}")

    _check_email_security(target, ws)

    # ── 1.3 ASN MAPPING ───────────────────────────────────────────────────────
    print_info("ASN mapping...")
    asn_file = ws.path("intelligence", "asn.txt")
    if which("asnmap"):
        run_cmd_pipe(
            f"echo {target} | asnmap -silent -json",
            output_file=str(asn_file),
            timeout=120   # asnmap can hang; previous runs showed 600s timeout
        )
        print_success(f"ASN → {asn_file.name}")
    else:
        print_skip("asnmap not installed — go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest")
        with open(asn_file, "w") as f:
            f.write(f"# ASN for {target}\n")
            f.write("# Manual: https://bgp.he.net\n")
            f.write("# Manual: https://dnschecker.org\n")
            f.write("# Manual: https://ipinfo.io\n")

    # ── 1.4 CRT.SH (Certificate Transparency) ─────────────────────────────────
    print_info("Certificate transparency (crt.sh)...")
    crtsh_file = ws.path("intelligence", "crtsh.txt")
    _crtsh_lookup(target, crtsh_file)

    # ── 1.5 INTELLIGENCE SOURCES ──────────────────────────────────────────────
    print_info("AlienVault OTX passive lookup...")
    _otx_lookup(target, ws.path("intelligence", "otx.txt"), apis.get("otx", ""))

    print_info("URLScan.io lookup...")
    _urlscan_lookup(target, ws.path("intelligence", "urlscan.txt"), apis.get("urlscan", ""))

    print_info("VirusTotal passive lookup...")
    _virustotal_lookup(target, ws.path("intelligence", "virustotal.txt"), apis.get("virustotal", ""))

    print_info("Wayback Machine URL collection...")
    _wayback_domains(target, ws.path("intelligence", "wayback_domains.txt"))

    # ── 1.6 SHODAN HINTS ──────────────────────────────────────────────────────
    _shodan_info(target, ws, apis.get("shodan", ""))

    # ── 1.7 OSINT CHECKLIST ───────────────────────────────────────────────────
    _generate_osint_checklist(target, ws)

    # ── 1.8 GOOGLE DORKS ──────────────────────────────────────────────────────
    _generate_google_dorks(target, ws)

    # ── 1.9 GITHUB DORKS ──────────────────────────────────────────────────────
    _generate_github_dorks(target, ws)

    print_success("OSINT stage complete.\n")


# ── HELPERS ────────────────────────────────────────────────────────────────────

def _check_email_security(target, ws):
    """Check SPF, DMARC, DKIM configuration."""
    spf   = subprocess.run(["dig", "+short", "TXT", target],         capture_output=True, text=True)
    dmarc = subprocess.run(["dig", "+short", "TXT", f"_dmarc.{target}"], capture_output=True, text=True)

    spf_records   = [l for l in spf.stdout.splitlines() if "v=spf" in l.lower()]
    dmarc_present = bool(dmarc.stdout.strip())

    report_path = ws.path("intelligence", "email_security.txt")
    with open(report_path, "w") as f:
        f.write(f"# Email Security Analysis: {target}\n\n")
        f.write("## SPF\n")
        f.write("\n".join(spf_records) if spf_records else "NO SPF RECORD FOUND — Potential email spoofing!\n")
        f.write("\n\n## DMARC\n")
        f.write(dmarc.stdout.strip() if dmarc_present else "NO DMARC RECORD FOUND — Potential email spoofing!\n")
        f.write("\n\n## DKIM (manual check)\n")
        f.write("# Common selectors to try:\n")
        for sel in ["default", "google", "mail", "smtp", "k1", "s1", "selector1", "selector2"]:
            f.write(f"#   dig TXT {sel}._domainkey.{target}\n")

    if not spf_records:
        print_find("No SPF record → potential email spoofing target!")
    if not dmarc_present:
        print_find("No DMARC record → potential email spoofing target!")


def _crtsh_lookup(target, output_file):
    """Query crt.sh for certificate transparency data."""
    try:
        url  = f"https://crt.sh/?q=%.{target}&output=json"
        data = curl_json(url, timeout=30)
        if data:
            domains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.").lower()
                    if target in sub:
                        domains.add(sub)
            with open(output_file, "w") as f:
                f.write("\n".join(sorted(domains)))
            print_success(f"crt.sh → {len(domains)} entries")
        else:
            print_warning("crt.sh returned no data (try manually)")
    except Exception as e:
        print_warning(f"crt.sh error: {e}")


def _otx_lookup(target, output_file, api_key=""):
    """Query AlienVault OTX for passive URL list."""
    try:
        headers = {}
        if api_key:
            headers["X-OTX-API-KEY"] = api_key
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/url_list?limit=500&page=1"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read())
        urls = [e.get("url", "") for e in data.get("url_list", []) if e.get("url")]
        with open(output_file, "w") as f:
            f.write("\n".join(urls))
        print_success(f"OTX → {len(urls)} URLs collected")
    except Exception as e:
        print_warning(f"OTX lookup error (non-fatal): {e}")
        with open(output_file, "w") as f:
            f.write(f"# OTX lookup failed: {e}\n")
            f.write(f"# Manual: https://otx.alienvault.com/indicator/domain/{target}/urls\n")


def _urlscan_lookup(target, output_file, api_key=""):
    """Query URLScan.io for historical scans."""
    try:
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["API-Key"] = api_key
        url = f"https://urlscan.io/api/v1/search/?q=domain:{target}&size=100"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read())
        results = data.get("results", [])
        with open(output_file, "w") as f:
            for r in results:
                task = r.get("task", {})
                page = r.get("page", {})
                f.write(f"{task.get('url', '')} | {page.get('ip', '')} | {page.get('server', '')}\n")
        print_success(f"URLScan → {len(results)} results")
    except Exception as e:
        print_warning(f"URLScan error (non-fatal): {e}")
        with open(output_file, "w") as f:
            f.write(f"# Manual: https://urlscan.io/search/#domain:{target}\n")


def _virustotal_lookup(target, output_file, api_key=""):
    """Query VirusTotal for subdomains."""
    if not api_key:
        with open(output_file, "w") as f:
            f.write(f"# VirusTotal requires API key — set in config.yaml\n")
            f.write(f"# Manual: https://www.virustotal.com/gui/domain/{target}/relations\n")
        print_skip("VirusTotal: no API key in config.yaml")
        return
    try:
        url  = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={target}"
        data = curl_json(url, timeout=30)
        if data:
            subdomains = data.get("subdomains", [])
            with open(output_file, "w") as f:
                f.write("\n".join(subdomains))
            print_success(f"VirusTotal → {len(subdomains)} subdomains")
    except Exception as e:
        print_warning(f"VirusTotal error: {e}")


def _wayback_domains(target, output_file):
    """Collect unique URLs from Wayback Machine CDX API."""
    try:
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{target}&fl=original&collapse=urlkey&output=text&limit=2000"
        )
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=45) as resp:   # was 30 — CDX is slow
            lines = resp.read().decode("utf-8", errors="ignore").splitlines()
        with open(output_file, "w") as f:
            f.write("\n".join(lines))
        print_success(f"Wayback CDX → {len(lines)} archived URLs")
    except Exception as e:
        print_warning(f"Wayback CDX error: {e}")


def _shodan_info(target, ws, api_key=""):
    """Provide Shodan recon instructions."""
    shodan_file = ws.path("intelligence", "shodan_hints.txt")
    with open(shodan_file, "w") as f:
        f.write(f"# Shodan Recon for {target}\n\n")
        f.write("## Manual Shodan Queries\n")
        f.write(f'ssl.cert.subject.CN:"{target}"\n')
        f.write(f'hostname:"{target}"\n')
        f.write(f'http.title:"{target}"\n')
        f.write(f'org:"{target}"\n')
        if api_key:
            f.write(f"\n## CLI (with API key)\n")
            f.write(f'shodan search ssl.cert.subject.CN:"{target}" --fields ip_str\n')
            f.write(f'shodan search hostname:"{target}" --fields ip_str,port,transport\n')
        else:
            f.write("\n## Set shodan API key in config.yaml to enable CLI queries\n")
            f.write("## https://account.shodan.io\n")
    print_success("Shodan hints generated")


def _generate_osint_checklist(target, ws):
    """Generate a comprehensive manual OSINT checklist."""
    checklist_file = ws.path("intelligence", "manual_osint_checklist.md")
    with open(checklist_file, "w") as f:
        f.write(f"# Manual OSINT Checklist — {target}\n")
        f.write(f"Generated: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")

        f.write("## 🔍 Domain Intelligence\n")
        f.write(f"- [ ] WHOIS deep dive: https://www.whoxy.com/whois-history/search.php?q={target}\n")
        f.write(f"- [ ] DomainBigData: https://domainbigdata.com/{target}\n")
        f.write(f"- [ ] BGP ASN lookup: https://bgp.he.net/dns/{target}\n")
        f.write(f"- [ ] Kaferjaeger: https://kaferjaeger.gay/sni-ip-list/{target}.json\n\n")

        f.write("## 📧 Employee & Email Recon\n")
        f.write(f"- [ ] Hunter.io: https://hunter.io/domain-search/{target}\n")
        f.write(f"- [ ] Phonebook.cz: https://phonebook.cz/ (search domain)\n")
        f.write(f"- [ ] RocketReach: https://rocketreach.co/search?domain={target}\n")
        f.write(f"- [ ] VoilaNorbert: https://www.voilanorbert.com/ (domain search)\n\n")

        f.write("## 🔓 Breach & Credential Hunting\n")
        f.write(f"- [ ] HaveIBeenPwned: https://haveibeenpwned.com/DomainSearch/{target}\n")
        f.write(f"- [ ] IntelX: https://intelx.io/?s={target}\n")
        f.write(f"- [ ] LeakRadar: https://leakradar.io/ (search domain)\n")
        f.write(f"- [ ] Dehashed: https://dehashed.com/ (search domain emails)\n")
        f.write(f"- [ ] LeakCheck: https://leakcheck.io/ (check emails found)\n\n")

        f.write("## 📸 Wayback & Archive\n")
        f.write(f"- [ ] Wayback: https://web.archive.org/web/*/{target}/*\n")
        f.write(f"- [ ] URLScan: https://urlscan.io/search/#domain:{target}\n")
        f.write(f"- [ ] OTX: https://otx.alienvault.com/indicator/domain/{target}\n\n")

        f.write("## 💼 Job & Social Recon\n")
        f.write(f"- [ ] LinkedIn jobs: Search '{target} engineer developer devops'\n")
        f.write("       — Look for tech stack mentions (AWS, Kubernetes, Laravel...)\n")
        f.write(f"- [ ] GitHub: https://github.com/search?q={target}&type=code\n")
        f.write(f"- [ ] Glassdoor / Indeed tech stack from job postings\n\n")

        f.write("## 🔗 Additional\n")
        f.write(f"- [ ] Censys: https://search.censys.io/?q={target}\n")
        f.write(f"- [ ] Shodan: https://www.shodan.io/search?query={target}\n")
        f.write(f"- [ ] OCCRP Aleph: https://aleph.occrp.org/search?q={target}\n")

    print_success("Manual OSINT checklist generated")


def _generate_google_dorks(target, ws):
    """Write Google dorks tailored to the target."""
    dorks_file = ws.path("intelligence", "google_dorks.txt")
    with open(dorks_file, "w") as f:
        f.write(f"# Google Dorks — {target}\n\n")
        dorks = [
            f'site:{target}',
            f'site:{target} ext:pdf',
            f'site:{target} ext:php',
            f'site:{target} ext:log | ext:txt | ext:conf | ext:json | ext:yaml',
            f'site:{target} inurl:? | inurl:&',
            f'site:{target} (inurl:/signin OR inurl:/login OR inurl:/register)',
            f'site:{target} intitle:"index of"',
            f'site:{target} inurl:swagger | inurl:api-docs | inurl:v1 | inurl:v2 | inurl:graphql',
            f'site:{target} inurl:email= | inurl:id= | inurl:query= | inurl:search=',
            f'site:{target} inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:r=http',
            f'site:{target} intext:"internal use only" | intext:"confidential"',
            f'site:{target} inurl:debug | inurl:error | inurl:test | inurl:config',
            f'site:{target} before:2020-01-01',
            f'site:*.{target}',
            f'site:*.{target} intext:"login" | intitle:"login"',
            f'site:pastebin.com "{target}"',
            f'site:github.com "{target}"',
            f'site:trello.com "{target}"',
            f'site:jira.{target}',
            f'site:confluence.{target}',
        ]
        for d in dorks:
            f.write(d + "\n")
    print_success("Google dorks generated")


def _generate_github_dorks(target, ws):
    """Write GitHub dorking queries."""
    github_file = ws.path("intelligence", "github_dorks.txt")
    org = target.split(".")[0]

    with open(github_file, "w") as f:
        f.write(f"# GitHub Dorks — {target}\n")
        f.write("# Open these at: https://github.com/search?type=code&q=QUERY\n\n")
        dorks = [
            f'"{target}" password',
            f'"{target}" api_key',
            f'"{target}" apikey',
            f'"{target}" secret',
            f'"{target}" token',
            f'"{target}" internal',
            f'"{target}" staging',
            f'"{target}" prod',
            f'"{target}" db_pass',
            f'"{target}" smtp',
            f'"{org}" aws_access_key',
            f'"{org}" "BEGIN RSA PRIVATE KEY"',
            f'"{org}" .env',
            f'org:{org} filename:.env',
            f'org:{org} filename:config.yml',
            f'org:{org} filename:secrets.json',
            f'"{target}" site:github.com',
        ]
        for d in dorks:
            f.write(d + "\n")
    print_success("GitHub dorks generated")
