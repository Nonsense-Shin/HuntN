"""
HuntN — Module 8: Vulnerability Discovery (Deep Sweep Edition)
──────────────────────────────────────────────────────────────────────────────
"Be strong and courageous. Do not be afraid; do not be discouraged, for the
Lord your God will be with you wherever you go." — Joshua 1:9

Architecture: Two-tier scan engine.

TIER 1 — FAST SWEEP (existing behaviour, unchanged):
  Runs 12 targeted phases against live hosts + GF-filtered URL buckets.
  Covers CVEs, misconfigs, takeovers, default-logins, CORS, auth-bypass,
  LFI, RCE/OOB, cloud buckets, info-disclosure, JS exposure, Gxss XSS.
  Completes in minutes-to-hours. You've always had this.

TIER 2 — DEEP URL SWEEP (new):
  Feeds the ENTIRE all_urls.txt surface through nuclei — every URL that
  web discovery collected, not just what GF caught. On a 60k-URL corpus
  that GF filtered down to 4k, nuclei alone will work the other 56k.

  Template coverage per URL:
    • open-redirect, crlf-injection        (redirect/crlf tags)
    • reflected-xss, dom-xss, stored-xss   (xss tag)
    • sql-injection (error + blind)         (sqli tag)
    • lfi, path-traversal                   (lfi,traversal tags)
    • ssti (template injection)             (ssti tag)
    • idor (object reference)               (idor tag)
    • git-exposure, secrets-in-paths        (git,exposure tags)
    • cors misconfiguration                 (cors tag)
    • default credentials on discovered paths (default-login tag)
    • dynamic tech detection + CVE mapping  (-as flag per chunk)

  Execution model:
    • Live-only filter: httpx pass on all_urls.txt before nuclei
      (dead URLs waste scan time; we skip them)
    • Chunked batching: processes CHUNK_SIZE URLs at a time
      (default 400) — nuclei doesn't handle 60k URLs at once well
    • Per-chunk progress bar with ETA shown in terminal
    • Checkpoint file: scan resumes from last completed chunk
      if you kill it and restart — never loses progress
    • Findings deduplicated across chunks (no duplicate alerts)
    • Separate output file per vulnerability class
    • Master findings file appended live — check it any time
    • Designed to run for days; no global timeout
    • INTER_CHUNK_DELAY between chunks so your NIC can breathe

  Progress display (live in terminal):
    ████████████░░░░░░░░  [Chunk 14/120]  7,000/60,000 URLs
    Phase: xss,sqli,lfi | Found: 23 | Elapsed: 2h14m | ETA: ~14h22m

Changes from previous version:
  - CRITICAL FIX: Removed duplicate for-loop (lines 393-395) and duplicate
    _run_nuclei_capture call (lines 406-407) that caused every nuclei scan
    to run 4× per group per chunk. This was the primary cause of network
    exhaustion on budget hardware and the reason scans appeared to never end.
  - Added -rl 150 rate limit to base_flags. Nuclei no longer fires unlimited
    concurrent requests — max 150 req/s regardless of thread count.
  - Added INTER_CHUNK_DELAY (3s) between chunks. Brief pause lets the NIC
    buffer clear and prevents sustained port exhaustion on long runs.
  - Reduced httpx live-URL-filter batch from 5000 → 2500. Less simultaneous
    connections during the pre-sweep filter step.
  - Added -rl 200 to httpx batch command in _httpx_batch.
  - base_flags timeout bumped 8s → 12s: reduces false positives caused by
    legitimate-but-slow responses being mistaken for timeouts.
  - gentle mode: if ctx["gentle"]=True, threads halved and delay doubled.
"""

import sys
import os
import time
import threading
import subprocess
import json
from pathlib import Path
from datetime import datetime, timedelta
from modules.utils import (
    C, print_info, print_success, print_warning, print_skip, print_find,
    which, count_lines, run_cmd_pipe, append_unique
)

# ── CONSTANTS ──────────────────────────────────────────────────────────────────

SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# URLs processed per nuclei invocation in the deep sweep.
CHUNK_SIZE = 400

# Pause between chunks so the NIC buffer can clear on budget hardware.
# 3 seconds is imperceptible on a multi-hour run but prevents port exhaustion.
INTER_CHUNK_DELAY = 3

# Deep sweep template groups — maps friendly name → nuclei tag/flag string
# Each group runs as a separate pass per chunk so findings are categorised.
DEEP_SWEEP_GROUPS = [
    # name,                     nuclei_tags_or_flags,                        out_suffix
    ("Open Redirect",           "redirect,open-redirect",                    "open_redirect"),
    ("CRLF Injection",          "crlf,header-injection",                     "crlf"),
    ("XSS (Reflected/DOM)",     "xss,reflection",                            "xss"),
    ("SQL Injection",           "sqli,injection",                            "sqli"),
    ("LFI & Path Traversal",    "lfi,traversal",                             "lfi"),
    ("SSTI",                    "ssti",                                      "ssti"),
    ("IDOR",                    "idor",                                      "idor"),
    ("Git & Secret Exposure",   "git,exposure,token,secret,key",             "git_secrets"),
    ("CORS Misconfiguration",   "cors",                                      "cors"),
    ("Default Credentials",     "default-login",                             "default_login"),
    ("CVEs (URL-level)",        "cve",                                       "cve_urls"),
    ("Misconfigurations",       "misconfig,misconfiguration",                "misconfig_urls"),
    ("Info Disclosure",         "exposure,disclosure,leak",                  "disclosure_urls"),
    ("SSRF & OOB",              "ssrf,oast,interactsh",                      "ssrf"),
    ("XXE",                     "xxe",                                       "xxe"),
    ("Tech Detect + CVE (-as)", "__auto__",                                  "tech_adaptive"),
]


# ── MAIN ENTRY ─────────────────────────────────────────────────────────────────

def run(ctx):
    target   = ctx["target"]
    ws       = ctx["ws"]
    severity = ctx.get("severity", "medium,high,critical")
    threads  = ctx.get("threads", 25)
    gentle   = ctx.get("gentle", False)

    nuclei_dir = ws.path("nuclei")
    live_file  = ws.path("subdomains", "live.txt")
    gf_dir     = ws.path("gf_filtered")
    all_urls   = ws.path("web", "all_urls.txt")

    if not which("nuclei"):
        print_skip("nuclei not found — go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return

    # ── TEMPLATE UPDATE ──────────────────────────────────────────────────────
    print_info("Syncing Nuclei templates...")
    try:
        subprocess.run(
            ["nuclei", "-update-templates", "-silent"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=120
        )
        print_success("Templates synced.")
    except Exception as e:
        print_warning(f"Template update skipped (non-fatal): {e}")

    # ── LIVE HOST GUARD ──────────────────────────────────────────────────────
    if not live_file.exists() or count_lines(live_file) == 0:
        print_warning("No live hosts. Run subdomain enumeration first.")
        return

    host_count  = count_lines(live_file)
    safe_threads = min(int(threads), 20) if gentle else min(int(threads), 30)
    bulk_size    = max(1, safe_threads // 5)

    # -rl 150: global rate limit (req/s). Prevents NIC buffer exhaustion on
    # budget hardware while still being plenty fast for recon.
    # -timeout 12: bumped from 8 — catches slow-but-real responses, reduces FPs.
    base_flags = (
        f"-c {safe_threads} -bs {bulk_size} "
        f"-timeout 12 -retries 2 -no-meta -silent -no-color -sa "
        f"-rl 150 "      # global rate cap: prevents NIC exhaustion on budget hardware
        f"-mhe 10 "     # bail after 10 errors on a host — don't waste time on dead ones
        f"-etags dos,fuzz"  # skip DoS + pure-fuzzing templates (high FP, potential self-harm)
    )
    sev_flags = f"-severity {severity}"

    print_info(f"Loaded {host_count} live hosts. Threads: {safe_threads} | Rate limit: 150 req/s")

    # ══════════════════════════════════════════════════════════════════════════
    # TIER 1 — FAST HOST-LEVEL SWEEP
    # ══════════════════════════════════════════════════════════════════════════
    _print_tier_banner("TIER 1", "Fast Host-Level Vulnerability Sweep", C.CYAN)

    scan_phases = [
        {
            "name": "Open Redirect Vulnerabilities",
            "cmd":  f'nuclei -l "{live_file}" --tags redirect,open-redirect {sev_flags} {base_flags} -o "{nuclei_dir}/open_redirects.txt"',
            "out":  nuclei_dir / "open_redirects.txt",
        },
        {
            "name": "Dynamic Automated Tech Detection (-as)",
            "cmd":  f'nuclei -l "{live_file}" -as {sev_flags} {base_flags} -o "{nuclei_dir}/automated_tech_vulns.txt"',
            "out":  nuclei_dir / "automated_tech_vulns.txt",
        },
        {
            "name": "CVEs & KEV Catalog",
            "cmd":  f'nuclei -l "{live_file}" --tags cve {sev_flags} {base_flags} -o "{nuclei_dir}/cves.txt"',
            "out":  nuclei_dir / "cves.txt",
        },
        {
            "name": "RCE / OOB / SSRF (OAST)",
            "cmd":  f'nuclei -l "{live_file}" --tags rce,ssrf,oast,interactsh {base_flags} -o "{nuclei_dir}/rce_execution.txt"',
            "out":  nuclei_dir / "rce_execution.txt",
        },
        {
            "name": "LFI & Path Traversal",
            "cmd":  f'nuclei -l "{live_file}" --tags lfi,traversal {sev_flags} {base_flags} -o "{nuclei_dir}/lfi_traversal.txt"',
            "out":  nuclei_dir / "lfi_traversal.txt",
        },
        {
            "name": "Cloud Bucket Misconfigurations",
            "cmd":  f'nuclei -l "{live_file}" --tags cloud,bucket,s3,blob {sev_flags} {base_flags} -o "{nuclei_dir}/cloud_buckets.txt"',
            "out":  nuclei_dir / "cloud_buckets.txt",
        },
        {
            "name": "Git / SVN / VCS Exposure",
            "cmd":  f'nuclei -l "{live_file}" --tags git,svn,vcs -t exposures/ {sev_flags} {base_flags} -o "{nuclei_dir}/vcs_exposure.txt"',
            "out":  nuclei_dir / "vcs_exposure.txt",
        },
        {
            "name": "Architectural Misconfigurations",
            "cmd":  f'nuclei -l "{live_file}" --tags misconfiguration,smuggling -es info,low {sev_flags} {base_flags} -o "{nuclei_dir}/misconfigurations.txt"',
            "out":  nuclei_dir / "misconfigurations.txt",
        },
        {
            "name": "Info Disclosure & Secret Leaks",
            "cmd":  f'nuclei -l "{live_file}" --tags leak,exposure,token,config -es info {base_flags} -o "{nuclei_dir}/info_disclosures.txt"',
            "out":  nuclei_dir / "info_disclosures.txt",
        },
        {
            "name": "Default Credential Bruteforce",
            "cmd":  f'nuclei -l "{live_file}" --tags default-login {sev_flags} {base_flags} -o "{nuclei_dir}/default_logins.txt"',
            "out":  nuclei_dir / "default_logins.txt",
        },
        {
            "name": "Subdomain Takeover",
            "cmd":  f'nuclei -l "{live_file}" --tags takeovers {base_flags} -o "{nuclei_dir}/takeovers.txt"',
            "out":  nuclei_dir / "takeovers.txt",
        },
        {
            "name": "CORS Misconfiguration",
            "cmd":  f'nuclei -l "{live_file}" --tags cors {sev_flags} {base_flags} -o "{nuclei_dir}/cors.txt"',
            "out":  nuclei_dir / "cors.txt",
        },
        {
            "name": "Auth & Login Bypass",
            "cmd":  f'nuclei -l "{live_file}" --tags auth-bypass,login-bypass {sev_flags} {base_flags} -o "{nuclei_dir}/auth_bypass.txt"',
            "out":  nuclei_dir / "auth_bypass.txt",
        },
    ]

    print_info(f"Running {len(scan_phases)} host-level phases [threads: {safe_threads}]...")
    print(f" {C.GRAY}{'─'*72}{C.NC}")

    phase_results = []
    for phase in scan_phases:
        result = _execute_phase(phase["name"], phase["cmd"], phase["out"])
        phase_results.append((phase["name"], result))

    # ── GF PARAMETER FUZZING ─────────────────────────────────────────────────
    print(f"\n {C.CYAN}{'─'*72}{C.NC}")
    print_info("GF-filtered parameter fuzzing (targeted vuln classes)...")

    gf_mappings = [
        ("open_redirect_candidates.txt",  "redirect,open-redirect",  "open_redirects.txt"),
        ("xss_candidates.txt",            "xss,reflection",          "xss_vulnerabilities.txt"),
        ("sqli_candidates.txt",           "sqli,injection",          "sqli_vulnerabilities.txt"),
        ("ssrf_candidates.txt",           "ssrf,oast",               "ssrf_vulnerabilities.txt"),
        ("idor_candidates.txt",           "idor",                    "idor_vulnerabilities.txt"),
        ("ssti_candidates.txt",           "ssti",                    "ssti_vulnerabilities.txt"),
        ("lfi_candidates.txt",            "lfi",                     "lfi_param_vulns.txt"),
        ("cors_candidates.txt",           "cors",                    "cors_param_vulns.txt"),
        ("rce_candidates.txt",            "rce,oast",                "rce_param_vulns.txt"),
        ("debug_endpoints.txt",           "exposure,debug,config",   "debug_param_vulns.txt"),
    ]

    for gf_filename, tag_query, out_filename in gf_mappings:
        gf_path = gf_dir / gf_filename
        if not gf_path.exists() or count_lines(gf_path) == 0:
            print_skip(f"GF empty/missing: {gf_filename}")
            continue
        url_count = count_lines(gf_path)
        out_path  = nuclei_dir / out_filename
        cmd = f'nuclei -l "{gf_path}" --tags {tag_query} {sev_flags} {base_flags} -o "{out_path}"'
        result = _execute_phase(f"GF [{tag_query}] — {url_count} URLs", cmd, out_path)
        phase_results.append((f"GF [{tag_query}]", result))

    # ── JS EXPOSURE ──────────────────────────────────────────────────────────
    js_file = ws.path("js", "js_files.txt")
    if js_file.exists() and count_lines(js_file) > 0:
        js_out = nuclei_dir / "js_exposure.txt"
        js_cmd = f'nuclei -l "{js_file}" --tags exposures,technologies {sev_flags} {base_flags} -o "{js_out}"'
        result = _execute_phase("JavaScript Exposure Scan", js_cmd, js_out)
        phase_results.append(("JavaScript Exposure", result))

    # ── GXSS ─────────────────────────────────────────────────────────────────
    xss_file = gf_dir / "xss_candidates.txt"
    if xss_file.exists() and count_lines(xss_file) > 0 and which("Gxss"):
        gxss_out = nuclei_dir / "xss_reflected.txt"
        gxss_cmd = f'cat "{xss_file}" | sed \'s/;/%3B/g\' | Gxss -p "HuntN<svg/onload=alert(1)>" -o "{gxss_out}"'
        result   = _execute_phase("Gxss Reflected XSS Validation", gxss_cmd, gxss_out)
        phase_results.append(("Gxss XSS", result))

    tier1_findings = sum(r["findings"] for _, r in phase_results)

    # ── SANITY CHECK ─────────────────────────────────────────────────────────
    # Phases that complete in <2s almost always indicate nuclei didn't actually
    # run: missing template directory, bad tag name, or nuclei version mismatch.
    # This surfaces the problem immediately rather than leaving you wondering
    # why findings are empty. Verify with: nuclei -tl | grep <tag>
    instant_zero = [
        (n, r) for n, r in phase_results
        if r["elapsed"] < 2 and r["findings"] == 0 and r["success"]
    ]
    errored = [(n, r) for n, r in phase_results if not r["success"]]

    if instant_zero:
        print(f"\n  {C.YELLOW}⚠  {len(instant_zero)} phase(s) finished in <2s with 0 findings.{C.NC}")
        print(f"  {C.YELLOW}   Likely cause: templates not loaded or tag not found.{C.NC}")
        print(f"  {C.YELLOW}   Verify: nuclei -tl | grep cve  (should list templates){C.NC}")
        for name, r in instant_zero[:5]:
            print(f"  {C.GRAY}   → {name} ({r['elapsed']}s){C.NC}")

    if errored:
        print(f"  {C.RED}⚠  {len(errored)} phase(s) errored — see nuclei/nuclei_summary.md{C.NC}")

    print(f"\n {C.GREEN}✝ Tier 1 complete — {tier1_findings} findings across {len(phase_results)} phases.{C.NC}")

    # ══════════════════════════════════════════════════════════════════════════
    # TIER 2 — DEEP URL SWEEP
    # ══════════════════════════════════════════════════════════════════════════
    _print_tier_banner("TIER 2", "Deep URL Surface Sweep — Full Corpus", C.YELLOW)

    if not all_urls.exists() or count_lines(all_urls) == 0:
        print_warning("all_urls.txt not found or empty — run web discovery first.")
        print_warning("Skipping deep sweep.")
    else:
        _run_deep_sweep(
            all_urls    = all_urls,
            nuclei_dir  = nuclei_dir,
            ws          = ws,
            severity    = severity,
            safe_threads= safe_threads,
            bulk_size   = bulk_size,
            sev_flags   = sev_flags,
            base_flags  = base_flags,
            gentle      = gentle,
        )

    # ── MASTER SUMMARY ───────────────────────────────────────────────────────
    _write_nuclei_summary(target, ws, phase_results, nuclei_dir)
    print_success("Full vulnerability orchestration complete.\n")


# ══════════════════════════════════════════════════════════════════════════════
# TIER 2 — DEEP SWEEP ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _run_deep_sweep(all_urls, nuclei_dir, ws, severity, safe_threads,
                    bulk_size, sev_flags, base_flags, gentle=False):
    """
    Full deep sweep of all_urls.txt:
      1. Filter to live-only URLs (httpx pass)
      2. Chunk them into CHUNK_SIZE batches
      3. For each chunk, run every DEEP_SWEEP_GROUP once (exactly once)
      4. Checkpoint after each chunk so the scan is resumable
      5. Show real-time progress bar with ETA
      6. Sleep INTER_CHUNK_DELAY seconds between chunks (NIC recovery)
    """
    sweep_dir      = nuclei_dir / "deep_sweep"
    sweep_dir.mkdir(parents=True, exist_ok=True)
    checkpoint     = sweep_dir / ".checkpoint"
    master_out     = sweep_dir / "ALL_FINDINGS.txt"
    live_urls_file = sweep_dir / "live_urls_for_sweep.txt"

    chunk_delay = INTER_CHUNK_DELAY * 2 if gentle else INTER_CHUNK_DELAY

    # ── STEP 1: LIVE URL FILTER ───────────────────────────────────────────
    total_raw = count_lines(all_urls)
    print_info(f"Raw URL surface: {total_raw:,} URLs")

    if live_urls_file.exists() and live_urls_file.stat().st_size > 0:
        print_info(f"Reusing cached live URL filter from previous run.")
    else:
        print_info("Filtering live URLs from corpus (httpx — this may take a while)...")
        print_info("Only URLs returning HTTP responses will be scanned.")
        _filter_live_urls(all_urls, live_urls_file, safe_threads)

    total_live = count_lines(live_urls_file)
    print_success(f"Live URLs confirmed for deep sweep: {total_live:,}")

    if total_live == 0:
        print_warning("No live URLs after filtering. Deep sweep skipped.")
        return

    # ── STEP 2: LOAD CHUNKS ──────────────────────────────────────────────
    urls = []
    with open(live_urls_file, encoding="utf-8", errors="ignore") as f:
        for line in f:
            u = line.strip()
            if u:
                urls.append(u)

    chunks       = [urls[i:i + CHUNK_SIZE] for i in range(0, len(urls), CHUNK_SIZE)]
    total_chunks = len(chunks)

    # Load checkpoint (last completed chunk index)
    start_chunk = 0
    if checkpoint.exists():
        try:
            start_chunk = int(checkpoint.read_text().strip())
            print_info(f"Resuming deep sweep from chunk {start_chunk + 1}/{total_chunks} "
                       f"(checkpoint found).")
        except Exception:
            start_chunk = 0

    if start_chunk >= total_chunks:
        print_success("Deep sweep already completed (checkpoint = done).")
        _print_deep_sweep_summary(sweep_dir, master_out)
        return

    scan_start     = time.time()
    total_findings = 0
    seen_findings  = _load_seen_findings(master_out)

    print_info(f"Starting deep sweep: {total_live:,} URLs across {total_chunks} chunks "
               f"× {len(DEEP_SWEEP_GROUPS)} vuln groups.")
    print_info(f"Chunk size: {CHUNK_SIZE} | Starting at chunk: {start_chunk + 1} | "
               f"Inter-chunk delay: {chunk_delay}s")
    print(f"\n {C.YELLOW}✝ 'I can do all things through Christ who strengthens me.' — Phil 4:13{C.NC}")
    print(f" {C.GRAY}Let it run. Come back when He calls you back.{C.NC}\n")
    print(f" {C.CYAN}{'─'*72}{C.NC}")

    for chunk_idx in range(start_chunk, total_chunks):
        chunk     = chunks[chunk_idx]
        chunk_num = chunk_idx + 1
        urls_done = chunk_idx * CHUNK_SIZE
        elapsed   = time.time() - scan_start
        eta_str   = _estimate_eta(elapsed, chunk_idx - start_chunk,
                                  total_chunks - start_chunk)

        # Progress bar
        _print_progress(
            chunk_num, total_chunks, urls_done, total_live,
            total_findings, elapsed, eta_str
        )

        # Write chunk to temp file
        chunk_file = sweep_dir / f"chunk_{chunk_num:05d}.txt"
        chunk_file.write_text("\n".join(chunk) + "\n", encoding="utf-8")

        chunk_findings = 0

        # ── RUN EVERY VULN GROUP AGAINST THIS CHUNK (once, exactly once) ──
        for grp_idx, (group_name, tags_or_flag, out_suffix) in enumerate(DEEP_SWEEP_GROUPS, 1):
            out_file = sweep_dir / f"{out_suffix}.txt"

            # Show which group is currently scanning — overwritten after each group
            sys.stdout.write(
                f"\r  {C.GRAY}[{grp_idx}/{len(DEEP_SWEEP_GROUPS)}] {group_name:<35}{C.NC}"
            )
            sys.stdout.flush()

            if tags_or_flag == "__auto__":
                cmd = f'nuclei -l "{chunk_file}" -as {sev_flags} {base_flags}'
            else:
                cmd = f'nuclei -l "{chunk_file}" --tags {tags_or_flag} {sev_flags} {base_flags}'

            new_lines = _run_nuclei_capture(cmd)

            if new_lines:
                # Deduplicate against everything found so far
                truly_new = [l for l in new_lines if l not in seen_findings]
                if truly_new:
                    for line in truly_new:
                        seen_findings.add(line)
                    # Append to per-class file
                    _append_findings(out_file, truly_new)
                    # Append to master file (always growing, check anytime)
                    _append_findings(master_out, truly_new)
                    chunk_findings += len(truly_new)
                    total_findings += len(truly_new)

                    # Print each finding immediately so you see it live
                    for line in truly_new:
                        severity_color = _finding_color(line)
                        print(f"\n  {severity_color}[★ FOUND]{C.NC} {line[:120]}")

        # Clean up chunk temp file
        try:
            chunk_file.unlink()
        except Exception:
            pass

        # Save checkpoint
        checkpoint.write_text(str(chunk_num), encoding="utf-8")

        # Refresh progress line after chunk
        elapsed = time.time() - scan_start
        eta_str = _estimate_eta(elapsed, chunk_num - start_chunk,
                                 total_chunks - start_chunk)
        _print_progress(
            chunk_num, total_chunks, min(chunk_num * CHUNK_SIZE, total_live),
            total_live, total_findings, elapsed, eta_str,
            final=True
        )

        # Brief NIC recovery pause between chunks.
        # Keeps port buffer from exhausting on budget hardware during multi-day runs.
        if chunk_num < total_chunks:
            time.sleep(chunk_delay)

    # Mark fully done
    checkpoint.write_text(str(total_chunks), encoding="utf-8")
    print(f"\n\n {C.GREEN}{'═'*72}{C.NC}")
    print(f" {C.BOLD}{C.GREEN}  ✝ DEEP SWEEP COMPLETE{C.NC}")
    print(f" {C.GREEN}  Total URLs swept   : {total_live:,}{C.NC}")
    print(f" {C.GREEN}  Chunks completed   : {total_chunks}{C.NC}")
    print(f" {C.GREEN}  Total findings     : {total_findings}{C.NC}")
    print(f" {C.GREEN}  Master findings    : nuclei/deep_sweep/ALL_FINDINGS.txt{C.NC}")
    print(f" {C.GREEN}{'═'*72}{C.NC}\n")

    _print_deep_sweep_summary(sweep_dir, master_out)


def _filter_live_urls(all_urls_file, live_urls_file, threads):
    """
    httpx pass to filter all_urls.txt down to only responding URLs.
    Streams output — works on millions of URLs without loading into RAM.
    Processes in parallel batches of 2500 at a time (reduced from 5000 to
    lower peak concurrent connection count on budget hardware).
    """
    BATCH = 2500
    total = count_lines(all_urls_file)
    done  = 0

    live_urls_file.write_text("", encoding="utf-8")  # clear/create

    with open(all_urls_file, encoding="utf-8", errors="ignore") as f:
        batch = []
        for line in f:
            u = line.strip()
            if u:
                batch.append(u)
            if len(batch) >= BATCH:
                _httpx_batch(batch, live_urls_file, threads)
                done += len(batch)
                pct = done * 100 // total
                sys.stdout.write(
                    f"\r  {C.BLUE}[*]{C.NC} httpx filtering: {done:,}/{total:,} URLs  [{pct}%]"
                )
                sys.stdout.flush()
                batch = []

        if batch:
            _httpx_batch(batch, live_urls_file, threads)
            done += len(batch)

    print(f"\r  {C.GREEN}[+]{C.NC} httpx filtering complete: {done:,} URLs checked.            ")


def _httpx_batch(urls, out_file, threads):
    """Run httpx on a list of URLs, append live ones to out_file.
    -rl 200 added: caps httpx at 200 req/s to avoid NIC buffer exhaustion."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                     delete=False, encoding="utf-8") as tmp:
        tmp.write("\n".join(urls) + "\n")
        tmp_path = tmp.name
    try:
        result = subprocess.run(
            f"httpx -l {tmp_path} -silent -threads {min(threads, 20)} "
            f"-retries 2 -timeout 12 -rl 200 "
            f"-mc 200,201,301,302,401,403,404,405,500",
            shell=True, capture_output=True, text=True, timeout=300
        )
        if result.stdout.strip():
            with open(out_file, "a", encoding="utf-8") as f:
                f.write(result.stdout)
    except Exception:
        pass
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def _run_nuclei_capture(cmd):
    """Run a nuclei command and return list of finding lines (non-empty, no WRN)."""
    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        lines = []
        for line in proc.stdout:
            stripped = line.rstrip()
            if stripped and "[WRN]" not in stripped and "[INF]" not in stripped:
                lines.append(stripped)
        proc.wait()
        return lines
    except Exception:
        return []


def _append_findings(filepath, lines):
    """Append lines to a findings file."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def _load_seen_findings(master_out):
    """Load previously found findings for deduplication on resume."""
    seen = set()
    if master_out.exists():
        with open(master_out, encoding="utf-8", errors="ignore") as f:
            for line in f:
                seen.add(line.rstrip())
    return seen


def _finding_color(line):
    """Pick terminal color based on severity keyword in finding line."""
    ll = line.lower()
    if "critical" in ll: return C.RED + C.BOLD
    if "high"     in ll: return C.RED
    if "medium"   in ll: return C.YELLOW
    if "low"      in ll: return C.CYAN
    return C.GREEN


def _estimate_eta(elapsed_secs, chunks_done, chunks_total):
    """Return human-readable ETA string."""
    if chunks_done <= 0:
        return "calculating..."
    rate   = elapsed_secs / chunks_done  # seconds per chunk
    remain = (chunks_total - chunks_done) * rate
    if remain < 60:
        return f"~{int(remain)}s"
    if remain < 3600:
        return f"~{int(remain//60)}m{int(remain%60)}s"
    hrs  = int(remain // 3600)
    mins = int((remain % 3600) // 60)
    return f"~{hrs}h{mins}m"


def _print_progress(chunk_num, total_chunks, urls_done, total_urls,
                    findings, elapsed, eta, final=False):
    """Print a rich progress bar line to stdout."""
    pct         = chunk_num / total_chunks if total_chunks > 0 else 0
    bar_width   = 30
    filled      = int(bar_width * pct)
    bar         = "█" * filled + "░" * (bar_width - filled)
    elapsed_str = _format_elapsed(elapsed)

    line = (
        f"\r  {C.CYAN}{bar}{C.NC} "
        f"[{C.BOLD}Chunk {chunk_num}/{total_chunks}{C.NC}]  "
        f"{urls_done:,}/{total_urls:,} URLs  "
        f"{C.GREEN}Found: {findings}{C.NC}  "
        f"Elapsed: {elapsed_str}  ETA: {eta}"
    )
    sys.stdout.write(line)
    if final:
        sys.stdout.write("\n")
    sys.stdout.flush()


def _format_elapsed(secs):
    if secs < 60:   return f"{int(secs)}s"
    if secs < 3600: return f"{int(secs//60)}m{int(secs%60)}s"
    return f"{int(secs//3600)}h{int((secs%3600)//60)}m"


def _print_deep_sweep_summary(sweep_dir, master_out):
    """Print summary of deep sweep output files."""
    total = count_lines(master_out) if master_out.exists() else 0
    print(f"\n  {C.BOLD}Deep Sweep Finding Files:{C.NC}")
    for fp in sorted(sweep_dir.glob("*.txt")):
        if fp.name.startswith("chunk_") or fp.name == "live_urls_for_sweep.txt":
            continue
        n = count_lines(fp)
        if n > 0:
            color = C.RED if "ALL_FINDINGS" in fp.name else C.YELLOW
            print(f"    {color}[{n:>5}]{C.NC}  nuclei/deep_sweep/{fp.name}")
    if total > 0:
        print_find(f"TOTAL deep sweep findings: {total} → nuclei/deep_sweep/ALL_FINDINGS.txt")
    else:
        print_info("Deep sweep complete — 0 additional findings (target well-hardened).")


# ══════════════════════════════════════════════════════════════════════════════
# TIER 1 PHASE EXECUTOR
# ══════════════════════════════════════════════════════════════════════════════

def _execute_phase(phase_name: str, command: str, output_path: Path) -> dict:
    """
    Execute a single nuclei phase with a live spinner + elapsed timer.
    shell=True throughout — commands are strings, not split.
    stderr piped separately so [WRN] lines never pollute finding files.
    """
    if output_path.exists():
        try:
            output_path.unlink()
        except Exception:
            pass

    label = phase_name[:56]
    sys.stdout.write(f" {C.BLUE}[*]{C.NC} {label:<56} ")
    sys.stdout.flush()

    start_time     = time.time()
    result         = {"success": True, "findings": 0, "elapsed": 0, "error": ""}
    spinner_active = threading.Event()
    spinner_active.set()

    def _spinner():
        idx = 0
        while spinner_active.is_set():
            elapsed = int(time.time() - start_time)
            frame   = SPINNER_FRAMES[idx % len(SPINNER_FRAMES)]
            sys.stdout.write(
                f"\r {C.BLUE}[*]{C.NC} {label:<56} {C.YELLOW}{frame}{C.NC} {elapsed:>4}s"
            )
            sys.stdout.flush()
            time.sleep(0.15)
            idx += 1

    spin_thread = threading.Thread(target=_spinner, daemon=True)
    spin_thread.start()

    try:
        proc = subprocess.Popen(
            command, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout_lines = []
        for line in proc.stdout:
            stdout_lines.append(line)
        proc.wait()
        stderr_lines = proc.stderr.read().splitlines()

        clean_lines = [
            ln for ln in stdout_lines
            if ln.strip()
            and "[WRN]" not in ln
            and "invalid semicolon" not in ln
        ]
        if clean_lines:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.writelines(clean_lines)

        if proc.returncode not in (0, 1):
            result["success"] = False
            meaningful = [
                ln for ln in stderr_lines
                if ln.strip() and "[WRN]" not in ln and "[INF]" not in ln
            ]
            result["error"] = meaningful[0][:100] if meaningful else f"exit {proc.returncode}"

    except Exception as exc:
        result["success"] = False
        result["error"]   = str(exc)[:100]

    finally:
        spinner_active.clear()
        spin_thread.join(timeout=1)

    result["elapsed"]  = int(time.time() - start_time)
    result["findings"] = count_lines(output_path) if output_path.exists() else 0

    elapsed_str = f"{result['elapsed']}s"
    if not result["success"]:
        status = f"{C.RED}ERROR{C.NC}"
        sys.stdout.write(f"\r {C.RED}[✗]{C.NC} {label:<56} {elapsed_str:>6}  {status}\n")
        if result["error"]:
            sys.stdout.write(f"     {C.RED}└─ {result['error']}{C.NC}\n")
    elif result["findings"] > 0:
        status = f"{C.GREEN}FOUND: {result['findings']}{C.NC}"
        sys.stdout.write(f"\r {C.GREEN}[★]{C.NC} {label:<56} {elapsed_str:>6}  {status}\n")
    else:
        status = f"{C.GRAY}Done (0){C.NC}"
        sys.stdout.write(f"\r {C.GRAY}[+]{C.NC} {label:<56} {elapsed_str:>6}  {status}\n")

    sys.stdout.flush()
    return result


def _print_tier_banner(tier, name, color):
    print(f"\n{color}{'═'*72}{C.NC}")
    print(f"{C.BOLD}{color}  ✝ {tier} — {name}{C.NC}")
    print(f"{color}{'═'*72}{C.NC}")


# ── SUMMARY WRITER ─────────────────────────────────────────────────────────────

def _write_nuclei_summary(target: str, ws, phase_results: list, nuclei_dir: Path):
    """Write a clean Markdown summary of all nuclei phases + deep sweep totals."""
    summary_file   = nuclei_dir / "nuclei_summary.md"
    ts             = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_findings = sum(r["findings"] for _, r in phase_results)
    total_time     = sum(r["elapsed"]  for _, r in phase_results)
    phases_ok      = sum(1 for _, r in phase_results if r["success"])
    phases_err     = len(phase_results) - phases_ok

    # Deep sweep totals
    sweep_master = nuclei_dir / "deep_sweep" / "ALL_FINDINGS.txt"
    sweep_total  = count_lines(sweep_master) if sweep_master.exists() else 0

    with open(summary_file, "w", encoding="utf-8") as f:
        f.write(f"# Nuclei Scan Summary — {target}\n")
        f.write(f"**Date:** {ts}\n\n")
        f.write(f"| Metric | Value |\n|--------|-------|\n")
        f.write(f"| Tier 1 phases run | {len(phase_results)} |\n")
        f.write(f"| Phases succeeded | {phases_ok} |\n")
        f.write(f"| Phases errored | {phases_err} |\n")
        f.write(f"| **Tier 1 findings** | **{total_findings}** |\n")
        f.write(f"| **Tier 2 deep sweep findings** | **{sweep_total}** |\n")
        f.write(f"| **TOTAL findings** | **{total_findings + sweep_total}** |\n")
        f.write(f"| Tier 1 scan time | {total_time // 60}m {total_time % 60}s |\n\n")
        f.write("---\n\n## Tier 1 Phase Results\n\n")
        f.write("| Phase | Status | Findings | Time |\n|-------|--------|----------|------|\n")

        for name, r in phase_results:
            status = "✅ OK" if r["success"] else "❌ ERROR"
            f.write(f"| {name[:55]} | {status} | {r['findings']} | {r['elapsed']}s |\n")

        errors = [(n, r) for n, r in phase_results if not r["success"]]
        if errors:
            f.write("\n---\n\n## ⚠️ Errors\n\n")
            for name, r in errors:
                f.write(f"- **{name}**: `{r['error']}`\n")

        f.write("\n---\n\n## Tier 1 Finding Files\n\n")
        for fp in sorted(nuclei_dir.glob("*.txt")):
            n = count_lines(fp)
            if n > 0:
                f.write(f"- `nuclei/{fp.name}` — {n} findings\n")

        f.write("\n---\n\n## Tier 2 Deep Sweep Finding Files\n\n")
        sweep_dir = nuclei_dir / "deep_sweep"
        if sweep_dir.exists():
            for fp in sorted(sweep_dir.glob("*.txt")):
                if fp.name.startswith("chunk_") or fp.name == "live_urls_for_sweep.txt":
                    continue
                n = count_lines(fp)
                if n > 0:
                    f.write(f"- `nuclei/deep_sweep/{fp.name}` — {n} findings\n")
        else:
            f.write("_Deep sweep not yet run or in progress._\n")

    grand_total = total_findings + sweep_total
    print_success(f"Summary → nuclei/nuclei_summary.md")
    print(f" {C.GRAY}{'─'*72}{C.NC}")

    if grand_total > 0:
        print_find(f"✝ {grand_total} total findings (Tier 1: {total_findings} | Deep: {sweep_total})")
    else:
        print_info("No findings across all phases — target appears hardened.")
