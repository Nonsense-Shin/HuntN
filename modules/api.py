"""
HuntN — Module 5: API Discovery & Fuzzing
"Ask, and it will be given to you; seek, and you will find." — Matthew 7:7
"""

import subprocess
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.utils import (
    C, print_info, print_success, print_warning, print_skip, print_find,
    run_cmd, run_cmd_pipe, which, count_lines
)

API_DOC_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger-ui.html", "/swagger-ui/",
    "/api-docs", "/api-docs.json", "/openapi.json", "/openapi.yaml",
    "/v1/swagger.json", "/v2/api-docs", "/v3/api-docs", "/api/swagger",
    "/docs", "/redoc", "/api/redoc", "/.well-known/openapi", "/graphql",
    "/graphiql", "/api/graphql", "/__graphql", "/graphql/console", "/v1",
    "/v2", "/v3", "/api", "/api/v1", "/api/v2", "/api/v3", "/rest",
    "/rest/v1", "/rest/v2", "/rpc", "/json-rpc", "/soap", "/wsdl",
    "/.well-known/api",
]

GRAPHQL_INTROSPECTION = '{"query":"{__schema{types{name fields{name}}}}"}'


def test_single_graphql(host, timeout=10):
    try:
        result = subprocess.run(
            ["curl", "-sk", "-X", "POST", "-H", "Content-Type: application/json",
             "-d", GRAPHQL_INTROSPECTION, "--max-time", str(timeout), host],
            capture_output=True, text=True, timeout=timeout + 3
        )
        if result.returncode == 0 and "__schema" in result.stdout:
            return True, host
    except Exception:
        pass
    return False, host


def fuzz_single_host_ffuf(host, wl, threads, auth_header, api_dir):
    safe_name = host.replace('://', '_').replace('/', '_').replace(':', '_')
    out     = api_dir / f"ffuf_{safe_name}.json"
    log_out = api_dir / f"ffuf_log_{safe_name}.txt"
    cmd = (
        f"ffuf -u {host}/FUZZ -w {wl} -H 'Content-Type: application/json' {auth_header} "
        f"-mc 200,201,204,301,302,401,403 -t {threads} -ac -silent -o {out} -of json -timeout 15"
    )
    run_cmd_pipe(cmd, output_file=str(log_out))
    return host


def run(ctx):
    target  = ctx["target"]
    ws      = ctx["ws"]
    config  = ctx["config"]
    threads = ctx["threads"]
    token   = ctx.get("token", "")

    api_dir   = ws.path("api")
    live_file = ws.path("subdomains", "live.txt")
    api_dir.mkdir(parents=True, exist_ok=True)

    # ── 5.1 PROBE COMMON API DOCUMENTATION PATHS ──────────────────────────
    print_info("Probing common API doc paths on all live hosts...")
    swagger_file = api_dir / "swagger_openapi.txt"
    graphql_file = api_dir / "graphql.txt"
    probe_output = api_dir / "api_docs_probe.txt"

    if live_file.exists() and which("httpx"):
        paths_arg   = ",".join(API_DOC_PATHS)
        auth_header = f"-H 'Authorization: Bearer {token}'" if token else ""
        run_cmd_pipe(
            f"httpx -l {live_file} -path {paths_arg} -silent "
            f"-mc 200,201,301,302,403 -title -status-code {auth_header} "
            f"-threads {threads} -retries 2 -timeout 15",
            output_file=str(probe_output)
        )
        print_success(f"API docs probe → {count_lines(probe_output)} responses")

        if not probe_output.exists() or probe_output.stat().st_size == 0:
            print_warning("No API endpoints detected during probe.")
            swagger_file.touch()
            graphql_file.touch()
        else:
            swagger_regex = re.compile(r'swagger|openapi|api-docs|redoc', re.IGNORECASE)
            graphql_regex = re.compile(r'graphql|graphiql', re.IGNORECASE)
            with open(probe_output, "r", errors="ignore") as f, \
                 open(swagger_file, "w") as sw_out, \
                 open(graphql_file, "w") as gq_out:
                for line in f:
                    if swagger_regex.search(line):
                        sw_out.write(line)
                    if graphql_regex.search(line):
                        gq_out.write(line)

        n_swagger = count_lines(swagger_file)
        n_graphql = count_lines(graphql_file)
        if n_swagger > 0: print_find(f"Swagger/OpenAPI endpoints: {n_swagger}")
        if n_graphql > 0: print_find(f"GraphQL endpoints: {n_graphql}")
    else:
        print_skip("httpx not found or no live hosts")

    # ── 5.2 GRAPHQL INTROSPECTION ─────────────────────────────────────────
    print_info("Testing GraphQL introspection on discovered endpoints...")
    if graphql_file.exists() and count_lines(graphql_file) > 0:
        introspect_file = api_dir / "graphql_introspection.txt"
        with open(graphql_file) as f:
            hosts = [line.split()[0] for line in f if line.strip()]
        max_workers = min(50, max(5, threads // 2))
        with open(introspect_file, "w") as out, ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_host = {executor.submit(test_single_graphql, host): host for host in hosts}
            for future in as_completed(future_to_host):
                success, host = future.result()
                if success:
                    print_find(f"GraphQL Introspection ENABLED: {host}")
                    out.write(f"ENABLED: {host}\n")
                    out.flush()

    # ── 5.3 KITERUNNER API ROUTE DISCOVERY ───────────────────────────────
    print_info("API route discovery with Kiterunner...")
    kr_file = api_dir / "kiterunner.txt"
    if which("kr") and live_file.exists():
        auth_flag = f"--header 'Authorization: Bearer {token}'" if token else ""
        run_cmd_pipe(
            f"kr scan {live_file} -w routes-large.kite --ignore-length 34 "
            f"--fail-status-codes 429,503 {auth_flag} -o {kr_file}",
            output_file=str(kr_file),
            timeout=900
        )
        print_success(f"Kiterunner → {count_lines(kr_file)} routes found")
    else:
        print_skip("kr (kiterunner) not available — falling back to parallel FFUF...")
        _api_fuzz_ffuf(target, live_file, api_dir, config, threads, token)

    # ── 5.4 API VERSION ENUMERATION ──────────────────────────────────────
    print_info("API version enumeration...")
    version_file = api_dir / "api_versions.txt"
    versions     = ["/v1", "/v2", "/v3", "/v4", "/api/v1", "/api/v2", "/api/v3"]
    if live_file.exists() and which("httpx"):
        run_cmd_pipe(
            f"httpx -l {live_file} -path {','.join(versions)} "
            f"-mc 200,201,401,403 -title -status-code -silent "
            f"-threads {threads} -retries 2 -timeout 15",
            output_file=str(version_file)
        )
        print_success(f"API version probing → {count_lines(version_file)} hits")

    # ── 5.5 API ROUTE EXTRACTION FROM CRAWLED URLS ───────────────────────
    print_info("Extracting API endpoints from crawled URL corpus...")
    api_routes_file = api_dir / "api_routes.txt"
    all_urls        = ws.path("web", "all_urls.txt")
    if all_urls.exists():
        api_pattern = re.compile(r'/api/|/v[0-9]+/|/rest/|/rpc/', re.IGNORECASE)
        seen = set()
        with open(all_urls, "r", errors="ignore") as f, open(api_routes_file, "w") as out:
            for line in f:
                cleaned = line.strip()
                if cleaned and api_pattern.search(cleaned) and cleaned not in seen:
                    seen.add(cleaned)
                    out.write(cleaned + "\n")
        print_success(f"API routes extracted: {count_lines(api_routes_file)}")

    _generate_api_checklist(target, ws)
    print_success("API discovery complete.\n")


def _api_fuzz_ffuf(target, live_file, api_dir, config, threads, token):
    if not which("ffuf"):
        return
    wl = config.get("wordlists", {}).get("api", "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt")
    if not Path(wl).exists():
        print_warning(f"API wordlist not found: {wl}")
        return
    auth_header = f"-H 'Authorization: Bearer {token}'" if token else ""
    if live_file.exists():
        with open(live_file) as f:
            hosts = [l.strip() for l in f if l.strip()]
        max_parallel_hosts = min(5, len(hosts))
        threads_per_host   = max(2, threads // max_parallel_hosts)
        with ThreadPoolExecutor(max_workers=max_parallel_hosts) as executor:
            futures = {
                executor.submit(fuzz_single_host_ffuf, host, wl, threads_per_host, auth_header, api_dir): host
                for host in hosts
            }
            for future in as_completed(futures):
                pass
    print_success("Parallel FFUF API fuzzing complete")


def _generate_api_checklist(target, ws):
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
        f.write("- graphql-cop — python3 graphql-cop.py -t https://TARGET/graphql\n")
        f.write("- APIKit — https://github.com/zhangchenchen/APIKit\n")
    print_success("Manual API checklist → api/manual_api_checklist.md")
