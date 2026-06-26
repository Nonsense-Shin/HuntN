"""
HuntN — Module 6: JavaScript Analysis & Secret Extraction
Covers: JS file collection, LinkFinder endpoint extraction,
        SecretFinder / custom regex for API keys & secrets,
        source map detection, hardcoded credential patterns
"""

import re
import subprocess
from pathlib import Path
from modules.utils import (
    C, print_info, print_success, print_warning, print_skip, print_find,
    run_cmd, run_cmd_pipe, which, count_lines
)


# Comprehensive secret detection regex patterns
SECRET_PATTERNS = {
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key":       r"AIza[0-9A-Za-z_-]{35}",
    "Google OAuth":         r"ya29\.[0-9A-Za-z_-]+",
    "GitHub Token":         r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
    "Slack Token":          r"xox[baprs]-([0-9a-zA-Z]{10,48})",
    "Stripe Secret Key":    r"sk_(test|live)_[0-9a-zA-Z]{24,}",
    "Stripe Publishable":   r"pk_(test|live)_[0-9a-zA-Z]{24,}",
    "Twilio":               r"AC[a-z0-9]{32}",
    "Firebase URL":         r"https://[a-z0-9-]+\.firebaseio\.com",
    "Firebase Key":         r"(?i)firebase.{0,20}['\"][A-Za-z0-9_-]{32,}['\"]",
    "JWT Token":            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Private Key":          r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY",
    "Generic Secret":       r"(?i)(secret|password|passwd|api_key|apikey|token|auth)['\"]?\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "Generic Bearer":       r"(?i)bearer\s+[A-Za-z0-9_-]{20,}",
    "DB Connection":        r"(?i)(mysql|postgresql|mongodb|redis)://[^\s<>'\"]+",
    "S3 Bucket":            r"s3://[a-z0-9._-]+|[a-z0-9.-]+\.s3\.amazonaws\.com",
    "Azure Key":            r"(?i)azure.{0,30}['\"][a-zA-Z0-9+/]{40,}['\"]",
    "Sendgrid":             r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "Mailgun":              r"key-[0-9a-zA-Z]{32}",
    "Heroku Key":           r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Internal IP":          r"(10\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}",
    "Suspicious Param":     r"(?i)(access_token|refresh_token|client_secret|client_id|auth_token)['\"]?\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "GraphQL Endpoint":     r"(?i)/graphql|graphiql|__schema",
}

# Keywords that suggest interesting endpoints in JS
INTERESTING_KEYWORDS = [
    "api", "endpoint", "token", "secret", "key", "auth", "admin",
    "internal", "debug", "upload", "download", "payment", "billing",
    "webhook", "callback", "redirect", "ssrf", "idor", "config",
    "password", "credential", "export", "import", "backup", "dump",
    "database", "mongo", "mysql", "redis", "elasticsearch",
]


def run(ctx):
    target  = ctx["target"]
    ws      = ctx["ws"]
    config  = ctx["config"]
    threads = ctx["threads"]

    js_dir    = ws.path("js")
    all_urls  = ws.path("web", "all_urls.txt")
    live_file = ws.path("subdomains", "live.txt")

    # ── 6.1 COLLECT JS FILES ─────────────────────────────────────
    print_info("Collecting JavaScript file URLs...")
    js_urls_file = js_dir / "js_files.txt"

    if all_urls.exists():
        run_cmd_pipe(
            f"cat {all_urls} | grep -iE '\\.js(\\?|$)' | sort -u",
            output_file=str(js_urls_file)
        )
        n_js = count_lines(js_urls_file)
        print_success(f"JS files found: {n_js}")
    else:
        print_warning("No all_urls.txt found — run Web Discovery first")
        return

    # Also use katana specifically for JS
    if which("katana") and live_file.exists():
        katana_js = js_dir / "katana_js.txt"
        run_cmd_pipe(
            f"katana -list {live_file} -silent -jc -kf all -c {threads} 2>/dev/null "
            f"| grep -iE '\\.js(\\?|$)'",
            output_file=str(katana_js)
        )
        run_cmd_pipe(
            f"cat {js_urls_file} {katana_js} 2>/dev/null | sort -u",
            output_file=str(js_urls_file)
        )
        print_success(f"Katana JS files added. Total: {count_lines(js_urls_file)}")

    # ── 6.2 CHECK FOR SOURCE MAPS ─────────────────────────────────
    print_info("Checking for exposed source maps (.js.map)...")
    sourcemap_file = js_dir / "source_maps.txt"
    if js_urls_file.exists():
        with open(js_urls_file) as f:
            js_urls = [l.strip() for l in f if l.strip()]
        map_urls = [u + ".map" for u in js_urls]
        with open(sourcemap_file, "w") as f:
            for url in map_urls[:50]:
                try:
                    result = subprocess.run(
                        ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", url],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0 and result.stdout.strip() in ("200", "201"):
                        f.write(url + "\n")
                        print_find(f"Source map exposed: {url}")
                except subprocess.TimeoutExpired:
                    print(f"[-] SKIP: Source map check timed out on {url}")
                    continue
                except Exception as e:
                    print(f"[-] Error checking source map on {url}: {str(e)}")
                    continue

    # ── 6.3 LINKFINDER — ENDPOINT EXTRACTION ─────────────────────
    print_info("Extracting endpoints from JS with LinkFinder...")
    endpoints_file = js_dir / "endpoints.txt"

    linkfinder_path = _find_linkfinder()

    if linkfinder_path and js_urls_file.exists():
        with open(js_urls_file) as f:
            js_urls = [l.strip() for l in f if l.strip()]

        with open(endpoints_file, "w") as out:
            for js_url in js_urls[:200]:  # cap at 200 JS files
                try:
                    result = subprocess.run(
                        ["python3", linkfinder_path, "-i", js_url, "-o", "cli"],
                        capture_output=True, text=True, timeout=30
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        out.write(f"\n# {js_url}\n")
                        out.write(result.stdout)
                except subprocess.TimeoutExpired:
                    print(f"[-] SKIP: LinkFinder processing timed out on {js_url}")
                    continue
                except Exception as e:
                    print(f"[-] Error running LinkFinder on {js_url}: {str(e)}")
                    continue
        print_success(f"LinkFinder → {count_lines(endpoints_file)} lines of endpoints")
    else:
        # Fallback: xnLinkFinder or basic regex
        print_skip("LinkFinder not found — using regex endpoint extraction")
        _regex_endpoint_extraction(js_urls_file, endpoints_file)

    # ── 6.4 SECRET DETECTION ON JS FILES ─────────────────────────
    print_info("Hunting for secrets in JS files...")
    secrets_file = js_dir / "secrets.txt"

    if which("nuclei") and js_urls_file.exists():
        run_cmd_pipe(
            f"nuclei -l {js_urls_file} -t exposures/ -t technologies/ -silent "
            f"-o {js_dir}/nuclei_js.txt",
            output_file=str(js_dir / "nuclei_js.txt")
        )
        print_success("Nuclei JS scan complete")

    # Custom regex secret hunting
    _regex_secret_hunt(js_urls_file, secrets_file)

    # ── 6.5 SECRETFINDER ─────────────────────────────────────────
    secretfinder_path = _find_secretfinder()
    if secretfinder_path and js_urls_file.exists():
        print_info("Running SecretFinder...")
        sf_file = js_dir / "secretfinder.txt"
        with open(js_urls_file) as f:
            js_urls = [l.strip() for l in f if l.strip()]
        with open(sf_file, "w") as out:
            for js_url in js_urls[:100]:
                try:
                    result = subprocess.run(
                        ["python3", secretfinder_path, "-i", js_url, "-o", "cli"],
                        capture_output=True, text=True, timeout=30
                    )
                    if result.returncode == 0 and result.stdout.strip() and "Nothing found" not in result.stdout:
                        out.write(f"\n# {js_url}\n")
                        out.write(result.stdout)
                except subprocess.TimeoutExpired:
                    print(f"[-] SKIP: SecretFinder processing timed out on {js_url}")
                    continue
                except Exception as e:
                    print(f"[-] Error running SecretFinder on {js_url}: {str(e)}")
                    continue
        n_sf = count_lines(sf_file)
        if n_sf > 5:
            print_find(f"SecretFinder findings: {n_sf} lines — check js/secretfinder.txt")

    # ── 6.6 MERGE & FILTER INTERESTING KEYWORDS ──────────────────
    print_info("Filtering JS endpoints by interesting keywords...")
    keywords_file = js_dir / "interesting_keywords.txt"
    kw_pattern = "|".join(INTERESTING_KEYWORDS)
    run_cmd_pipe(
        f"cat {endpoints_file} 2>/dev/null | grep -iE '({kw_pattern})'",
        output_file=str(keywords_file)
    )
    print_success(f"Interesting keyword endpoints: {count_lines(keywords_file)}")

    print_success("JavaScript analysis complete.\n")


def _regex_endpoint_extraction(js_urls_file, output_file):
    """Extract endpoints from JS using regex when LinkFinder isn't available."""
    endpoint_patterns = [
        r'(?:["\'`])(/[a-zA-Z0-9_/.-]+)(?:["\'`])',
        r'(?:api|url|endpoint|path|route)\s*[:=]\s*["\'`](/[^"\'`\s]+)',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'XMLHttpRequest.*open\(["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
    ]

    found = set()
    with open(js_urls_file) as f:
        urls = [l.strip() for l in f if l.strip()]

    for url in urls[:100]:
        try:
            result = subprocess.run(
                ["curl", "-sk", "--max-time", "10", url],
                capture_output=True, text=True, timeout=15
            )
            content = result.stdout
            for pattern in endpoint_patterns:
                matches = re.findall(pattern, content)
                found.update(matches)
        except subprocess.TimeoutExpired:
            print(f"[-] SKIP: Fallback endpoint curl extraction timed out on {url}")
            continue
        except Exception:
            continue

    with open(output_file, "w") as f:
        f.write("\n".join(sorted(found)))

    print_success(f"Regex endpoint extraction → {len(found)} endpoints")


def _regex_secret_hunt(js_urls_file, secrets_file):
    """Download JS files and search for secrets with regex."""
    findings = []
    with open(js_urls_file) as f:
        urls = [l.strip() for l in f if l.strip()]

    print_info(f"Scanning {min(len(urls), 150)} JS files for secrets...")

    for url in urls[:150]:
        try:
            result = subprocess.run(
                ["curl", "-sk", "--max-time", "15", url],
                capture_output=True, text=True, timeout=20
            )
            content = result.stdout
            if not content:
                continue

            for secret_name, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    finding = f"[{secret_name}] in {url}\n  Match: {str(match)[:100]}\n"
                    findings.append(finding)
        except subprocess.TimeoutExpired:
            print(f"[-] SKIP: Fallback secret curl hunt timed out on {url}")
            continue
        except Exception:
            continue

    with open(secrets_file, "w") as f:
        if findings:
            f.write(f"# Secrets Found — {len(findings)} potential findings\n\n")
            f.write("\n".join(findings))
        else:
            f.write("# No secrets found via regex (may still have manual findings)\n")

    if findings:
        print_find(f"SECRETS found: {len(findings)} — check js/secrets.txt IMMEDIATELY")
    else:
        print_success("Regex secret scan complete (no matches)")


def _find_linkfinder():
    """Find LinkFinder installation."""
    candidates = [
        "/opt/LinkFinder/linkfinder.py",
        str(Path.home() / "tools/LinkFinder/linkfinder.py"),
        str(Path.home() / "LinkFinder/linkfinder.py"),
        "/usr/local/bin/linkfinder.py",
    ]
    for path in candidates:
        if Path(path).exists():
            return path
    return None


def _find_secretfinder():
    """Find SecretFinder installation."""
    candidates = [
        "/opt/SecretFinder/SecretFinder.py",
        str(Path.home() / "tools/SecretFinder/SecretFinder.py"),
        str(Path.home() / "SecretFinder/SecretFinder.py"),
    ]
    for path in candidates:
        if Path(path).exists():
            return path
    return None
