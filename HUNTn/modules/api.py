"""
HuntN — Module 5: API Discovery & Fuzzing
Covers: Common API doc paths, GraphQL detection, Swagger/OpenAPI discovery,
        kiterunner route enumeration, ffuf API fuzzing, parameter discovery
"""

import subprocess
from pathlib import Path
from modules.utils import (
    C, print_info, print_success, print_warning, print_skip, print_find,
    run_cmd, run_cmd_pipe, which, count_lines
)


# Common API documentation paths to probe on every host
API_DOC_PATHS = [
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/api-docs",
    "/api-docs.json",
    "/openapi.json",
    "/openapi.yaml",
    "/v1/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/swagger",
    "/docs",
    "/redoc",
    "/api/redoc",
    "/.well-known/openapi",
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/__graphql",
    "/graphql/console",
    "/v1",
    "/v2",
    "/v3",
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/rest",
    "/rest/v1",
    "/rest/v2",
    "/rpc",
    "/json-rpc",
    "/soap",
    "/wsdl",
    "/.well-known/api",
]

GRAPHQL_INTROSPECTION = """{\"query\":\"{__schema{types{name fields{name}}}}\"}"""


def run(ctx):
    target  = ctx["target"]
    ws      = ctx["ws"]
    config  = ctx["config"]
    threads = ctx["threads"]
    token   = ctx.get("token", "")

    api_dir   = ws.path("api")
    live_file = ws.path("subdomains", "live.txt")

    # ── 5.1 PROBE COMMON API DOCUMENTATION PATHS ─────────────────
    print_info("Probing common API doc paths on all live hosts...")
    swagger_file  = api_dir / "swagger_openapi.txt"
    graphql_file  = api_dir / "graphql.txt"

    if live_file.exists() and which("httpx"):
        # Build the probe list
        paths_arg = ",".join(API_DOC_PATHS)
        auth_header = f"-H 'Authorization: Bearer {token}'" if token else ""

        run_cmd_pipe(
            f"httpx -l {live_file} -path {paths_arg} -silent -mc 200,201,301,302,403 "
            f"-title -status-code {auth_header} -threads {threads}",
            output_file=str(api_dir / "api_docs_probe.txt")
        )
        print_success(f"API docs probe → {count_lines(api_dir / 'api_docs_probe.txt')} responses")

        # Separate swagger / graphql
        run_cmd_pipe(
            f"cat {api_dir}/api_docs_probe.txt | grep -iE 'swagger|openapi|api-docs|redoc'",
            output_file=str(swagger_file)
        )
        run_cmd_pipe(
            f"cat {api_dir}/api_docs_probe.txt | grep -iE 'graphql|graphiql'",
            output_file=str(graphql_file)
        )

        n_swagger  = count_lines(swagger_file)
        n_graphql  = count_lines(graphql_file)
        if n_swagger > 0:  print_find(f"Swagger/OpenAPI endpoints: {n_swagger}")
        if n_graphql > 0:  print_find(f"GraphQL endpoints: {n_graphql}")
    else:
        print_skip("httpx not found or no live hosts")

# ── 5.2 GRAPHQL INTROSPECTION TEST ───────────────────────────
    print_info("Testing GraphQL introspection on discovered endpoints...")
    if graphql_file.exists() and count_lines(graphql_file) > 0:
        introspect_file = api_dir / "graphql_introspection.txt"
        with open(graphql_file) as f:
            hosts = [l.split()[0] for l in f if l.strip()]

        with open(introspect_file, "w") as out:
            for host in hosts:
                try:
                    result = subprocess.run(
                        ["curl", "-sk", "-X", "POST", "-H", "Content-Type: application/json",
                         "-d", GRAPHQL_INTROSPECTION, host],
                        capture_output=True, text=True, timeout=10
                    )

                    if result.returncode == 0 and "__schema" in result.stdout:
                        print(f"[★] GraphQL Introspection ENABLED: {host}")
                        out.write(f"ENABLED: {host}\n")

                except subprocess.TimeoutExpired:
                    print(f"[-] SKIP: Introspection timed out on {host} (Server dropped request)")
                    continue
                except Exception as e:
                    print(f"[-] Error parsing {host}: {str(e)}")
                    continue
    # ── 5.3 KITERUNNER API ROUTE DISCOVERY ───────────────────────
    print_info("API route discovery with Kiterunner...")
    kr_file = api_dir / "kiterunner.txt"

    if which("kr") and live_file.exists():
        auth_flag = f"--header 'Authorization: Bearer {token}'" if token else ""
        run_cmd_pipe(
            f"kr scan {live_file} -w routes-large.kite --ignore-length 34 "
            f"--fail-status-codes 429,503 {auth_flag} -o {kr_file}",
            output_file=str(kr_file)
        )
        print_success(f"Kiterunner → {count_lines(kr_file)} routes found")
    else:
        print_skip("kr (kiterunner) — go install github.com/assetnote/kiterunner/cmd/kr@latest")
        print_info("  Download wordlists: https://wordlists.assetnote.io/")
        # Fallback: ffuf API fuzzing
        _api_fuzz_ffuf(target, live_file, api_dir, config, threads, token)

    # ── 5.4 API VERSION ENUMERATION ──────────────────────────────
    print_info("API version enumeration...")
    version_file = api_dir / "api_versions.txt"
    versions = ["/v1", "/v2", "/v3", "/v4", "/api/v1", "/api/v2", "/api/v3"]

    if live_file.exists() and which("httpx"):
        version_paths = ",".join(versions)
        run_cmd_pipe(
            f"httpx -l {live_file} -path {version_paths} -mc 200,201,401,403 "
            f"-title -status-code -silent -threads {threads}",
            output_file=str(version_file)
        )
        print_success(f"API version probing → {count_lines(version_file)} hits")

    # ── 5.5 EXTRACT API ROUTES FROM ENDPOINTS ────────────────────
    print_info("Extracting API endpoints from crawled URLs...")
    api_routes_file = api_dir / "api_routes.txt"
    all_urls = ws.path("web", "all_urls.txt")

    if all_urls.exists():
        run_cmd_pipe(
            f"cat {all_urls} | grep -iE '/api/|/v[0-9]+/|/rest/|/rpc/' | sort -u",
            output_file=str(api_routes_file)
        )
        print_success(f"API routes extracted: {count_lines(api_routes_file)}")

    # ── 5.6 GENERATE MANUAL API TESTING CHECKLIST ────────────────
    _generate_api_checklist(target, ws)

    print_success("API discovery complete.\n")


def _api_fuzz_ffuf(target, live_file, api_dir, config, threads, token):
    """Fallback API fuzzing with ffuf."""
    if not which("ffuf"):
        return

    wl = config.get("wordlists", {}).get("api",
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt")

    if not Path(wl).exists():
        print_warning(f"API wordlist not found: {wl}")
        print_info("  Download: https://wordlists.assetnote.io/ (api.txt)")
        return

    ffuf_file = api_dir / "ffuf_api.txt"
    auth_header = f"-H 'Authorization: Bearer {token}'" if token else ""

    if live_file.exists():
        import subprocess
        with open(live_file) as f:
            hosts = [l.strip() for l in f if l.strip()][:15]  # Cap at 15 hosts

        for host in hosts:
            out = api_dir / f"ffuf_{host.replace('://', '_').replace('/', '_')}.json"
            run_cmd_pipe(
                f"ffuf -u {host}/FUZZ -w {wl} "
                f"-H 'Content-Type: application/json' {auth_header} "
                f"-mc 200,201,204,301,302,401,403 -t {threads} -ac -silent "
                f"-o {out} -of json",
                output_file=str(api_dir / f"ffuf_log_{host.split('//')[1].split('/')[0]}.txt")
            )

    print_success("ffuf API fuzzing complete")


def _generate_api_checklist(target, ws):
    """Generate a comprehensive manual API testing checklist."""
    checklist_file = ws.path("api", "manual_api_checklist.md")

    with open(checklist_file, "w") as f:
        f.write(f"# API Manual Testing Checklist — {target}\n\n")

        f.write("## Documentation to Check\n")
        for path in API_DOC_PATHS:
            f.write(f"- [ ] `https://{target}{path}`\n")

        f.write("\n## Authentication Testing\n")
        f.write("- [ ] JWT algorithm confusion (none, HS256 → RS256 confusion)\n")
        f.write("- [ ] Missing auth on endpoints (remove Authorization header)\n")
        f.write("- [ ] API key in URL params vs headers\n")
        f.write("- [ ] OAuth flow issues (state, redirect_uri, PKCE)\n")
        f.write("- [ ] Token scope escalation\n")

        f.write("\n## Common Vulnerabilities\n")
        f.write("- [ ] IDOR: Change user IDs in API calls\n")
        f.write("- [ ] Mass assignment: Add extra fields in JSON body\n")
        f.write("- [ ] Rate limiting: Rapid-fire requests on auth endpoints\n")
        f.write("- [ ] GraphQL introspection: `{__schema{types{name}}}`\n")
        f.write("- [ ] GraphQL batch attacks\n")
        f.write("- [ ] REST verb tampering (GET → POST → PUT → DELETE)\n")
        f.write("- [ ] Content-type confusion: JSON → XML → form-data\n")

        f.write("\n## Tools\n")
        f.write("- Swagger-EZ — https://github.com/RhinoSecurityLabs/swagger-ez\n")
        f.write("- swagroutes — https://github.com/mrjinks/swagroutes\n")
        f.write("- APIKit — https://github.com/zhangchenchen/APIKit\n")
        f.write("- MindAPI — https://github.com/dsopas/MindAPI\n")
        f.write("- graphql-cop — python3 graphql-cop.py -t https://TARGET/graphql\n")

    print_success("Manual API checklist → api/manual_api_checklist.md")
