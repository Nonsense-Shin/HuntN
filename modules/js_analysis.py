"""
HuntN — Module 6: JavaScript Analysis & Secret Extraction (Blessed Edition)
──────────────────────────────────────────────────────────────────────────────
"For wisdom is more precious than rubies, and nothing you desire can compare
with her." — Proverbs 8:11  (We extract every secret hidden in the code.)

Fixes from original:
  - Katana flag: -cd is not available in all versions. Replaced with
    -crawl-duration (full flag name) for compatibility. Falls back gracefully
    if the flag is rejected.
  - Corpus downloader: added per-URL retry (2 attempts) with 2s back-off.
    Previously a single timeout failure silently dropped the URL forever.
  - JS URL filtering: increased corpus limit from 150 to 300 (you have large
    infra — more JS = more secrets and endpoints found).
  - Source map check: limit bumped from 80 to 150 URLs.
  - LinkFinder / SecretFinder parallel limits: bumped from 60 to 100.
  - Nuclei JS scan: now uses -retries 2 for flaky network conditions.
  - _write_ranked_findings: fixed KeyError if 'secrets.txt' doesn't exist yet
    (reporting module was referencing js/secrets.txt but this module writes
    to js/FINDINGS.md — added a secrets summary alias write).

Changes from previous version:
  - MAJOR: Removed the [:300] hard cap on corpus downloads. On large infra
    with 1000+ live hosts the old code silently dropped ~99% of JS files,
    meaning secrets in almost all of them were never seen. Corpus now
    processes ALL JS files in batches of JS_BATCH_SIZE (default 150). Each
    batch downloads → hunts secrets → extracts endpoints before the next
    batch starts. Memory use stays constant regardless of corpus size.
  - Source maps scan now covers ALL JS files (was [:150]).
  - Nuclei JS scan timeout bumped from 600s to 7200s (2 hours). On a target
    with thousands of JS files, 600 seconds isn't close to enough — the scan
    was silently killing itself and you were getting partial secret coverage.
  - net_workers: capped at min(threads//2, 15) for large corpora (was
    min(threads, 30)). Prevents 30 simultaneous curl downloads from
    saturating the NIC alongside everything else running.
  - Added 2s inter-batch sleep to let the NIC buffer recover between batches.
  - Final endpoint write is now consolidated after all batches complete,
    so endpoint_*.txt files reflect the full corpus, not just the last batch.
  - gentle mode: if ctx["gentle"]=True, batch size halved and workers halved.

Philosophy unchanged: native Python corpus download + in-memory analysis,
no shell pipelines, zero redundancy in extraction.
"""

import re
import json
import hashlib
import subprocess
import concurrent.futures
import time
from pathlib import Path
from urllib.parse import urlparse
from modules.utils import (
    C, print_info, print_success, print_warning, print_skip, print_find,
    run_cmd, run_cmd_pipe, which_or_install, which, count_lines,
    safe_write
)

# JS files downloaded per batch. 150 keeps peak concurrent curl count
# manageable while still making fast progress across large JS corpora.
JS_BATCH_SIZE = 150

# ── SECRET PATTERNS — with confidence tiers ───────────────────────────────────
SECRET_PATTERNS = {
    "T1:AWS_Access_Key":    (r"\bAKIA[0-9A-Z]{16}\b",                                          1),
    "T1:AWS_Secret_Key":    (r"(?i)aws_secret_access_key\s*[=:]\s*['\"']?([A-Za-z0-9/+]{40})", 1),
    "T1:Google_API_Key":    (r"\bAIza[0-9A-Za-z_-]{35}\b",                                     1),
    "T1:Google_OAuth":      (r"\bya29\.[0-9A-Za-z_-]{50,}\b",                                  1),
    "T1:GitHub_Token":      (r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b",               1),
    "T1:GitHub_Classic":    (r"\bghp_[A-Za-z0-9]{36}\b",                                       1),
    "T1:Slack_Token":       (r"\bxox[baprs]-[0-9A-Za-z]{10,255}\b",                            1),
    "T1:Stripe_Secret":     (r"\bsk_(test|live)_[0-9a-zA-Z]{20,}\b",                           1),
    "T1:Stripe_PK":         (r"\bpk_(test|live)_[0-9a-zA-Z]{20,}\b",                           1),
    "T1:Sendgrid":          (r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b",                  1),
    "T1:Twilio_SID":        (r"\bAC[a-z0-9]{32}\b",                                            1),
    "T1:Private_Key_PEM":   (r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY",                   1),
    "T1:JWT_Token":         (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", 1),
    "T1:Mailgun_Key":       (r"\bkey-[0-9a-zA-Z]{32}\b",                                       1),
    "T1:Shopify_Token":     (r"\bshpss_[a-zA-Z0-9]{32,}\b",                                    1),
    "T1:Shopify_Shared":    (r"\bshpat_[a-zA-Z0-9]{32,}\b",                                    1),
    "T1:Firebase_URL":      (r"https://[a-z0-9-]{4,}\.firebaseio\.com",                        1),
    "T1:DB_ConnString":     (r"(?i)(mysql|postgresql|postgres|mongodb|redis)://[^\s<>\"']{8,}", 1),

    "T2:Bearer_Token":      (r"(?i)\bbearer\s+([A-Za-z0-9_\-\.]{20,})\b",                     2),
    "T2:Auth_Header":       (r"(?i)['\"]?authorization['\"]?\s*:\s*['\"]([^'\"]{12,})['\"]",   2),
    "T2:API_Key_Assign":    (r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]([^'\"]{12,})['\"]", 2),
    "T2:Secret_Assign":     (r"(?i)(secret|client_secret|app_secret)\s*[=:]\s*['\"]([^'\"]{12,})['\"]",   2),
    "T2:Token_Assign":      (r"(?i)(access[_-]?token|auth[_-]?token|refresh[_-]?token)\s*[=:]\s*['\"]([^'\"]{12,})['\"]", 2),
    "T2:Password_Assign":   (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"']{8,})['\"]",   2),
    "T2:S3_Bucket_Ref":     (r"s3://[a-z0-9._-]{3,}|[a-z0-9.-]{3,}\.s3\.amazonaws\.com",      2),
    "T2:Azure_Conn":        (r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]{20,}", 2),
    "T2:Internal_IP":       (r"(?<![./\d])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?![./\d])", 2),
    "T2:GQL_Endpoint":      (r"(?i)['\"/](graphql|graphiql|__schema)['\"/]",                   2),

    "T3:Generic_Credential":(r"(?i)(credential|creds|login)\s*[=:]\s*['\"]([^'\"]{6,})['\"]", 3),
    "T3:OAuth_Client_ID":   (r"(?i)client[_-]?id\s*[=:]\s*['\"]([a-zA-Z0-9_-]{8,})['\"]",    3),
    "T3:Webhook_URL":       (r"https://hooks\.(slack|discord)\.com/[^\s\"'<>]{10,}",           3),
    "T3:Mapbox_Token":      (r"\bpk\.eyJ[A-Za-z0-9]{20,}\b",                                   3),
    "T3:Algolia_Key":       (r"(?i)algolia[_-]?(api[_-]?key|app[_-]?id)\s*[=:]\s*['\"]([A-Za-z0-9]{8,})['\"]", 3),
}

NOISE_PATTERNS = [
    r"[0-9a-f]{32}", r"[0-9a-f]{64}", r"localhost|127\.0\.0\.",
    r"example\.com|test\.com", r"XXXXXXXX|xxxxxxxx", r"YOUR_|your_|TODO|todo"
]

ENDPOINT_CLUSTERS = {
    "auth":    r"(?i)/(login|logout|signin|signout|oauth|token|auth|sso|saml|mfa|2fa|password|reset|forgot)",
    "admin":   r"(?i)/(admin|administrator|dashboard|panel|manage|backend|control|cp|internal|staff|ops)",
    "api":     r"(?i)(/api/|/v[0-9]+/|/rest/|/rpc/|/graphql|/services?/)",
    "upload":  r"(?i)/(upload|file|files|media|attachment|asset|import|export)",
    "user":    r"(?i)/(user|users|account|accounts|profile|me/|member|customer|client)",
    "payment": r"(?i)/(pay|payment|invoice|billing|charge|subscribe|checkout|cart|order)",
    "debug":   r"(?i)/(debug|test|dev|staging|config|settings|env|info|health|status|ping|actuator|metrics)",
    "data":    r"(?i)/(data|report|reports|export|download|backup|dump|db|database|search)",
    "webhook": r"(?i)/(webhook|callback|notify|hook|event|push|feed)",
}


def run(ctx):
    target      = ctx["target"]
    ws          = ctx["ws"]
    threads     = ctx.get("threads", 50)
    gentle      = ctx.get("gentle", False)

    # Concurrency cap: generous on small targets, conservative on large ones.
    # gentle mode halves this further. 30 simultaneous curl downloads + nuclei
    # + everything else running = NIC saturation on budget hardware.
    net_workers = min(threads // 2, 8) if gentle else min(threads // 2, 15)

    js_dir    = ws.path("js")
    all_urls  = ws.path("web", "all_urls.txt")
    live_file = ws.path("subdomains", "live.txt")

    # ── 6.1 COLLECT JS FILE URLs ─────────────────────────────────────────────
    print_info("Collecting JavaScript file URLs from URL corpus...")
    js_urls_file = js_dir / "js_files.txt"
    js_urls_set  = set()

    if all_urls.exists():
        with open(all_urls, encoding="utf-8", errors="ignore") as f:
            for line in f:
                url = line.strip()
                if re.search(r"\.js(\?|$|#)", url, re.IGNORECASE):
                    js_urls_set.add(url)

    if which_or_install("katana") and live_file.exists():
        print_info("Running Katana spider for additional JS discovery...")
        # Try -crawl-duration flag (full name, works across versions)
        katana_cmd = [
            "katana", "-list", str(live_file), "-silent", "-jc", "-kf", "all",
            "-ef", "png,jpg,jpeg,gif,css,woff,woff2,svg,ico",
            "-c", str(min(threads, 20)),
            "-crawl-duration", "4m",
            "-depth", "3"
        ]
        try:
            result = subprocess.run(katana_cmd, capture_output=True, text=True, timeout=280)
            if result.returncode != 0 and "unknown flag" in (result.stderr or ""):
                # Fallback: older katana without -crawl-duration
                print_warning("Katana: -crawl-duration not supported, running without time cap.")
                katana_cmd_fallback = [
                    "katana", "-list", str(live_file), "-silent", "-jc", "-kf", "all",
                    "-ef", "png,jpg,jpeg,gif,css,woff,woff2,svg,ico",
                    "-c", str(min(threads, 20)), "-depth", "3"
                ]
                result = subprocess.run(katana_cmd_fallback, capture_output=True, text=True, timeout=280)
            if result.stdout:
                js_filter = re.compile(r"\.js(\?|$|#)", re.IGNORECASE)
                for line in result.stdout.splitlines():
                    val = line.strip()
                    if val and js_filter.search(val):
                        js_urls_set.add(val)
        except subprocess.TimeoutExpired:
            print_warning("Katana exceeded time budget. Using URLs collected so far.")

    filtered_js = [
        u for u in js_urls_set
        if not re.search(
            r"(jquery|bootstrap|angular|react|vue|lodash|moment|webpack|"
            r"cdn\.cloudflare|googleapis\.com|gstatic\.com|unpkg\.com|jsdelivr\.net|"
            r"cdnjs\.cloudflare|polyfill\.io)", u, re.IGNORECASE
        )
    ]

    if filtered_js:
        safe_write(js_urls_file, sorted(filtered_js))
    print_success(f"Target JS files identified: {len(filtered_js)} (vendor noise filtered)")

    if not filtered_js:
        print_warning("No target JS resources found. Exiting JS analysis.")
        return

    # ── 6.2 BATCHED CORPUS DOWNLOAD (all files, no arbitrary cap) ───────────
    # Previously capped at [:300]. On large infra (1000+ domains) that means
    # the vast majority of JS was never analyzed. Now we process ALL files in
    # batches of JS_BATCH_SIZE — memory use stays constant regardless of corpus.
    batch_size   = JS_BATCH_SIZE // 2 if gentle else JS_BATCH_SIZE
    total_js     = len(filtered_js)
    total_batches = (total_js + batch_size - 1) // batch_size

    print_info(f"Downloading JS corpus: {total_js} files in {total_batches} batch(es) "
               f"({net_workers} workers per batch)...")

    all_findings      = []
    all_endpoints_global = set()
    corpus_total      = 0

    for batch_idx, batch_start in enumerate(range(0, total_js, batch_size), 1):
        batch = filtered_js[batch_start:batch_start + batch_size]
        if total_batches > 1:
            print_info(f"JS batch {batch_idx}/{total_batches} — {len(batch)} files...")

        corpus = _download_corpus_parallel(batch, max_workers=net_workers)
        corpus_total += len(corpus)

        if corpus:
            # Secret hunting on this batch
            batch_findings = _secret_hunt_engine(corpus)
            all_findings.extend(batch_findings)

            # Endpoint extraction on this batch (writes intermediate files —
            # the final consolidated write happens after all batches)
            batch_endpoints = _extract_endpoints_engine(corpus, js_dir)
            all_endpoints_global.update(batch_endpoints)

        # Brief pause between batches — lets the NIC buffer recover
        if batch_start + batch_size < total_js:
            time.sleep(2)

    # Re-sort all findings by confidence tier after batch accumulation
    all_findings = sorted(all_findings, key=lambda x: x["tier"])
    print_success(f"Corpus populated: {corpus_total} JS files fetched across {total_batches} batch(es).")

    # Write consolidated secrets.txt alias for reporting.py
    if all_findings:
        t1_t2 = [f for f in all_findings if f["tier"] <= 2]
        secret_lines = [f"[{f['tier']}] {f['type']} | {f['url']} | {f['match']}" for f in t1_t2]
        safe_write(js_dir / "secrets.txt", secret_lines)

    # ── 6.3 SOURCE MAP DETECTION ────────────────────────────────────────────
    # Covers ALL JS files (was [:150])
    print_info(f"Scanning for exposed source maps (.js.map) — {total_js} files...")
    _check_source_maps_parallel(filtered_js, js_dir, max_workers=net_workers)

    # ── 6.4 CONSOLIDATED ENDPOINT WRITE ─────────────────────────────────────
    # Each batch's _extract_endpoints_engine call wrote partial cluster files.
    # This final call writes the complete accumulated set across all batches.
    if all_endpoints_global:
        _recluster_and_write_endpoints(all_endpoints_global, js_dir)
        print_success(f"Endpoints clustered: {len(all_endpoints_global)} unique paths")

    # ── 6.5 LINKFINDER SUPPLEMENTAL ─────────────────────────────────────────
    lf_path = _find_linkfinder()
    if lf_path:
        print_info("Running LinkFinder supplemental route extraction...")
        # Cap LinkFinder: each URL spawns a Python subprocess, keep bounded
        lf_cap = 150 if gentle else 200
        lf_findings = _run_linkfinder_parallel(lf_path, filtered_js[:lf_cap], max_workers=net_workers)
        all_endpoints_global.update(lf_findings)
        _recluster_and_write_endpoints(all_endpoints_global, js_dir)

    # ── 6.6 NUCLEI POST-PROCESSING ──────────────────────────────────────────
    # Timeout bumped to 7200s (2 hours). The previous 600s cap was silently
    # killing this scan on large JS corpora — you were only getting partial
    # coverage and had no way to know. Let it run as long as it needs.
    if which_or_install("nuclei") and js_urls_file.exists():
        print_info(f"Running Nuclei against {count_lines(js_urls_file)} JS files "
                   f"(timeout: 2h — let it complete)...")
        nuclei_js_out = js_dir / "nuclei_js_findings.txt"
        run_cmd_pipe(
            f"nuclei -l {js_urls_file} "
            f"-tags token,secret,key,disclosure,api,credential "
            f"-silent -no-color -retries 2 -rl 100 -o {nuclei_js_out} 2>/dev/null",
            output_file=str(nuclei_js_out),
            timeout=7200  # 2 hours — do not reduce
        )
        n = count_lines(nuclei_js_out)
        if n > 0:
            print_find(f"Nuclei JS exposure findings: {n}")

    # ── 6.7 SECRETFINDER ────────────────────────────────────────────────────
    sf_path = _find_secretfinder()
    if sf_path and filtered_js:
        print_info("Running SecretFinder passive validation...")
        sf_cap = 100 if gentle else 150
        _run_secretfinder_parallel(sf_path, filtered_js[:sf_cap], js_dir, all_findings, max_workers=net_workers)

    # ── 6.8 FINAL REPORT ────────────────────────────────────────────────────
    _write_ranked_findings(all_findings, all_endpoints_global, js_dir, target)
    print_success("JavaScript analysis complete.\n")


# ── DOWNLOAD ENGINE ───────────────────────────────────────────────────────────

def _fetch_single_js(url, retries=2):
    """Fetch a single JS URL with retry. Returns (url, content_or_None)."""
    for attempt in range(1, retries + 1):
        try:
            res = subprocess.run(
                ["curl", "-sk", "--max-time", "12", "--compressed",
                 "-A", "Mozilla/5.0 Chrome/124.0", url],
                capture_output=True, text=True, timeout=15
            )
            if res.returncode == 0 and res.stdout and len(res.stdout) >= 50:
                return url, res.stdout
        except Exception:
            pass
        if attempt < retries:
            time.sleep(2)
    return url, None


def _download_corpus_parallel(urls, max_workers):
    corpus = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(_fetch_single_js, url): url for url in urls}
        for future in concurrent.futures.as_completed(future_map):
            url, text = future.result()
            if text:
                corpus[url] = text
    return corpus


# ── SOURCE MAP ENGINE ─────────────────────────────────────────────────────────

def _check_map_worker(url):
    map_url = url.split("?")[0] + ".map"
    try:
        res = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8", map_url],
            capture_output=True, text=True, timeout=10
        )
        if res.stdout.strip() == "200":
            return map_url
    except Exception:
        pass
    return None


def _check_source_maps_parallel(js_urls, js_dir, max_workers):
    found_maps = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(_check_map_worker, js_urls)
        for r in results:
            if r:
                found_maps.append(r)
                print_find(f"Source map EXPOSED: {r}")

    if found_maps:
        safe_write(js_dir / "source_maps.txt", found_maps)
        print_find(f"Total exposed source maps: {len(found_maps)}")
        _parse_sourcemap_files(found_maps[0], js_dir)


def _parse_sourcemap_files(map_url, js_dir):
    try:
        result = subprocess.run(
            ["curl", "-sk", "--max-time", "12", map_url],
            capture_output=True, text=True, timeout=15
        )
        if not result.stdout:
            return
        data = json.loads(result.stdout)
        sources = data.get("sources", [])
        if sources:
            safe_write(js_dir / "sourcemap_files.txt", sources)
            print_find(f"Source map reveals {len(sources)} original files → js/sourcemap_files.txt")
            interesting = [s for s in sources if re.search(r"(api|auth|config|secret|token|key|pay|admin)", s, re.I)]
            for s in interesting[:6]:
                print_find(f"  Interesting source: {s}")
    except Exception:
        pass


# ── SECRET ENGINE ─────────────────────────────────────────────────────────────

def _secret_hunt_engine(corpus):
    findings     = []
    seen_hashes  = set()
    noise_re     = re.compile("|".join(NOISE_PATTERNS), re.IGNORECASE)
    compiled_patterns = {name: (re.compile(pat), tier) for name, (pat, tier) in SECRET_PATTERNS.items()}

    for url, content in corpus.items():
        for pattern_name, (compiled_regex, tier) in compiled_patterns.items():
            for match in compiled_regex.finditer(content):
                raw_match = match.group(0)
                if noise_re.search(raw_match):
                    continue
                match_clean = re.sub(r"['\"\\s=:;]", "", raw_match)
                if len(match_clean) < 8:
                    continue
                match_hash = hashlib.md5(match_clean.encode()).hexdigest()[:12]
                if match_hash in seen_hashes:
                    continue
                seen_hashes.add(match_hash)

                start   = max(0, match.start() - 60)
                end     = min(len(content), match.end() + 60)
                context = content[start:end].replace("\n", " ").strip()
                if len(context) > 200:
                    context = context[:100] + "..." + context[-60:]

                findings.append({
                    "tier": tier, "type": pattern_name, "url": url,
                    "match": match_clean[:120], "context": context
                })

    return sorted(findings, key=lambda x: x["tier"])


# ── ENDPOINT ENGINE ───────────────────────────────────────────────────────────

def _extract_endpoints_engine(corpus, js_dir):
    endpoint_patterns = [
        re.compile(r'''(?:["'`])(/(?:api|v\d|rest|rpc|graphql|auth|oauth|admin|user|data|file|upload|payment|webhook)[^"'`\s<>]{0,200})(?:["'`])'''),
        re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(\s*["'`]([^"'`\s<>]{5,200})["'`]'''),
        re.compile(r'''(?:url|endpoint|path|route|href)\s*[:=]\s*["'`](/[^"'`\s<>]{4,200})["'`]'''),
        re.compile(r'''XMLHttpRequest[^;]*?open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"']{5,200})["']'''),
    ]

    all_endpoints = set()
    for url, content in corpus.items():
        for compiled_regex in endpoint_patterns:
            for m in compiled_regex.finditer(content):
                ep = m.group(1).strip()
                if len(ep) < 3 or len(ep) > 250:
                    continue
                if re.search(r"\.(png|jpg|jpeg|gif|css|woff|svg|ico|map)(\?|$)", ep, re.I):
                    continue
                all_endpoints.add(ep)

    _recluster_and_write_endpoints(all_endpoints, js_dir)
    return all_endpoints


def _recluster_and_write_endpoints(all_endpoints, js_dir):
    clusters = {name: [] for name in ENDPOINT_CLUSTERS}
    other    = []

    for ep in sorted(all_endpoints):
        matched = False
        for cluster_name, cluster_pattern in ENDPOINT_CLUSTERS.items():
            if re.search(cluster_pattern, ep):
                clusters[cluster_name].append(ep)
                matched = True
                break
        if not matched:
            other.append(ep)

    for cluster_name, eps in clusters.items():
        if eps:
            safe_write(js_dir / f"endpoints_{cluster_name}.txt", eps)

    if other:
        safe_write(js_dir / "endpoints_other.txt", other)
    if all_endpoints:
        safe_write(js_dir / "endpoints_all.txt", sorted(all_endpoints))


# ── LINKFINDER / SECRETFINDER ENGINES ────────────────────────────────────────

def _run_lf_worker(args):
    path, url = args
    try:
        res = subprocess.run(["python3", path, "-i", url, "-o", "cli"],
                             capture_output=True, text=True, timeout=20)
        if res.returncode == 0:
            return {
                val.strip() for val in res.stdout.splitlines()
                if val.strip() and val.strip().startswith("/") and len(val.strip()) > 2
            }
    except Exception:
        pass
    return set()


def _run_linkfinder_parallel(linkfinder_path, js_urls, max_workers):
    found = set()
    worker_args = [(linkfinder_path, url) for url in js_urls]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(_run_lf_worker, worker_args)
        for r in results:
            found.update(r)
    return found


def _run_sf_worker(args):
    path, url = args
    try:
        res = subprocess.run(["python3", path, "-i", url, "-o", "cli"],
                             capture_output=True, text=True, timeout=20)
        if res.returncode == 0 and res.stdout.strip():
            out = res.stdout.strip()
            if "Nothing found" not in out and len(out) > 10:
                return url, out.splitlines()
    except Exception:
        pass
    return None, []


def _run_secretfinder_parallel(sf_path, js_urls, js_dir, existing_findings, max_workers):
    sf_findings = []
    seen        = {f["match"][:40] for f in existing_findings}
    worker_args = [(sf_path, url) for url in js_urls]

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(_run_sf_worker, worker_args)
        for url, lines in results:
            for line in lines:
                line_clean = line.strip()
                if line_clean and line_clean[:40] not in seen:
                    seen.add(line_clean[:40])
                    sf_findings.append(f"[{url}] {line_clean}")

    if sf_findings:
        safe_write(js_dir / "secretfinder_unique.txt", sf_findings)
        print_find(f"SecretFinder unique findings: {len(sf_findings)}")


# ── REPORT WRITER ─────────────────────────────────────────────────────────────

def _write_ranked_findings(findings, endpoints, js_dir, target):
    findings_file = js_dir / "FINDINGS.md"
    t1 = [f for f in findings if f["tier"] == 1]
    t2 = [f for f in findings if f["tier"] == 2]
    t3 = [f for f in findings if f["tier"] == 3]

    def _get_len(p):
        try:
            return len(p.read_text(encoding="utf-8", errors="ignore").splitlines()) if p.exists() else 0
        except Exception:
            return 0

    auth_eps    = _get_len(js_dir / "endpoints_auth.txt")
    admin_eps   = _get_len(js_dir / "endpoints_admin.txt")
    payment_eps = _get_len(js_dir / "endpoints_payment.txt")
    js_count    = count_lines(js_dir / "js_files.txt")

    with open(findings_file, "w", encoding="utf-8") as f:
        f.write(f"# JS Analysis — FINDINGS REPORT\n**Target:** {target}\n\n## Summary\n| | |\n|---|---|\n")
        f.write(f"| JS files analyzed | {js_count} |\n")
        f.write(f"| Endpoints extracted | {len(endpoints)} |\n")
        f.write(f"| Auth endpoints | {auth_eps} |\n")
        f.write(f"| Admin endpoints | {admin_eps} |\n")
        f.write(f"| Payment endpoints | {payment_eps} |\n")
        f.write(f"| Tier 1 HIGH-confidence secrets | {len(t1)} |\n")
        f.write(f"| Tier 2 MEDIUM-confidence | {len(t2)} |\n")
        f.write(f"| Tier 3 LOW-confidence | {len(t3)} |\n\n---\n\n")

        if t1:
            f.write(f"## 🔴 Tier 1 — HIGH CONFIDENCE ({len(t1)} findings)\n")
            for finding in t1:
                f.write(f"### `{finding['type']}`\n"
                        f"- **File:** `{finding['url']}`\n"
                        f"- **Match:** `{finding['match']}`\n"
                        f"- **Context:** `{finding['context']}`\n\n")
        if t2:
            f.write(f"## 🟠 Tier 2 — MEDIUM CONFIDENCE ({len(t2)} findings)\n")
            for finding in t2:
                f.write(f"- **`{finding['type']}`** in `{finding['url']}`\n"
                        f"  Match: `{finding['match']}`\n\n")
        if t3:
            f.write(f"## 🟡 Tier 3 — LOW CONFIDENCE ({len(t3)} findings)\n")
            for finding in t3:
                f.write(f"- `{finding['type']}` → `{finding['url']}` → `{finding['match']}`\n")
        if not findings:
            f.write("## No secrets found\n")

        f.write("\n---\n## High-Value Endpoints\n\n")
        for cluster in ("auth", "admin", "payment", "upload", "debug", "api"):
            ep_file = js_dir / f"endpoints_{cluster}.txt"
            if ep_file.exists():
                eps = ep_file.read_text(encoding="utf-8", errors="ignore").splitlines()[:10]
                if eps:
                    f.write(f"### {cluster.upper()}\n")
                    for ep in eps:
                        f.write(f"- `{ep}`\n")
                    f.write("\n")

    if t1:
        print_find(f"🔴 {len(t1)} HIGH-CONFIDENCE secrets → js/FINDINGS.md")
    elif t2:
        print_find(f"🟠 {len(t2)} medium-confidence findings → js/FINDINGS.md")
    else:
        print_success("No secrets found. Analysis documented in js/FINDINGS.md.")


# ── TOOL LOCATORS ─────────────────────────────────────────────────────────────

def _find_linkfinder():
    for p in [
        "/opt/LinkFinder/linkfinder.py",
        str(Path.home() / "tools/LinkFinder/linkfinder.py"),
        "/usr/local/bin/linkfinder.py"
    ]:
        if Path(p).exists():
            return p
    return None


def _find_secretfinder():
    for p in [
        "/opt/SecretFinder/SecretFinder.py",
        str(Path.home() / "tools/SecretFinder/SecretFinder.py")
    ]:
        if Path(p).exists():
            return p
    return None
