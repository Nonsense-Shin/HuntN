#!/usr/bin/env python3
"""
██╗  ██╗██╗   ██╗███╗   ██╗████████╗███╗   ██╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝████╗  ██║
███████║██║   ██║██╔██╗ ██║   ██║   ██╔██╗ ██║
██╔══██║██║   ██║██║╚██╗██║   ██║   ██║╚██╗██║
██║  ██║╚██████╔╝██║ ╚████║   ██║   ██║ ╚████║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═══╝

  The Hand of Light Uncovering Darkness
  "Even though I walk through the valley of the shadow of death,
   I will fear no evil, for You are with me." — Psalm 23:4

  Bug Bounty Reconnaissance Framework
  Author: Nonsense Shin and lots of AI | For educational and authorized use only.

Changes from original:
  - import re moved from inside main() to top-level.
  - Added --gentle flag: caps threads to 20, adds STAGE_COOLDOWN seconds of
    sleep between every module run. Use this on budget hardware (i3-N305,
    8 GB RAM) or any target where the previous run saturated your NIC and
    dropped your internet. The scan takes the same amount of work — it just
    breathes between stages so your network stack has time to recover.
  - STAGE_COOLDOWN: 0s by default (no change for normal runs), 5s in gentle
    mode. Prevents ephemeral port exhaustion on long multi-day runs.
  - Renamed `allowed` → `elapsed` in the final summary for clarity.
  - gentle and stage_cooldown passed into scan_context so modules that
    care (nuclei_scan, js_analysis) can tune their own concurrency.
  - IP target detection block cleaned up (was using late import re).
"""

import os
import sys
import re
import yaml
import argparse
import subprocess
import json
import time
import shutil
from pathlib import Path
from datetime import datetime
from modules import (
    osint, infrastructure, subdomains,
    web, api, js_analysis, cloud,
    nuclei_scan, reporting
)
from modules.utils import (
    Colors as C, banner, print_stage, print_info,
    print_success, print_warning, print_error,
    check_tools, load_config, create_workspace,
    ask_yes_no, run_cmd, WorkspaceManager
)

VERSION = "1.0.0"

# Seconds to sleep between module stages.
# 0 = no change from original behaviour.
# Set via --gentle flag (→ 5s) or override here for a permanent custom value.
STAGE_COOLDOWN_DEFAULT  = 0
STAGE_COOLDOWN_GENTLE   = 5

# Thread counts
THREADS_NORMAL  = 50
THREADS_GENTLE  = 20


def parse_args():
    parser = argparse.ArgumentParser(
        description="HuntN — The Hand of Light Uncovering Darkness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 huntn.py example.com
  python3 huntn.py example.com --modules passive,infra,web
  python3 huntn.py example.com --all --token YOUR_API_TOKEN
  python3 huntn.py example.com --all --gentle          # for budget hardware / long runs
  python3 huntn.py --setup
  python3 huntn.py --check-tools
        """
    )
    parser.add_argument("target",         nargs="?",  help="Target domain (e.g., example.com or *.example.com)")
    parser.add_argument("--setup",        action="store_true", help="Install all required tools automatically")
    parser.add_argument("--check-tools",  action="store_true", help="Check which tools are installed")
    parser.add_argument("--config",       default="config.yaml", help="Path to config file (default: config.yaml)")
    parser.add_argument("--all",          action="store_true",   help="Run all modules without prompting")
    parser.add_argument("--modules",      help="Comma-separated list of modules: passive,infra,subs,web,api,js,cloud,nuclei")
    parser.add_argument("--token",        help="Bearer token for authenticated API scanning")
    parser.add_argument("--wordlist",     help="Custom wordlist path for directory/API fuzzing")
    parser.add_argument("--threads",      type=int, default=None,
                        help=f"Thread count (default: {THREADS_NORMAL}, gentle default: {THREADS_GENTLE})")
    parser.add_argument("--resume",       action="store_true", help="Resume a previous scan for this target")
    parser.add_argument("--output-dir",   help="Custom output directory")
    parser.add_argument("--severity",     default="medium,high,critical",
                        help="Nuclei severity filter (default: medium,high,critical)")
    parser.add_argument("--wildcard",     action="store_true",
                        help="Target is a wildcard scope (e.g., *.example.com)")
    parser.add_argument("--passive-only", action="store_true",
                        help="Run only passive/OSINT modules (no active scanning)")
    parser.add_argument("--scope-file",   help="File with in-scope domains/IPs")
    parser.add_argument(
        "--gentle",
        action="store_true",
        help=(
            f"Budget-hardware / long-run mode: caps threads to {THREADS_GENTLE}, "
            f"adds {STAGE_COOLDOWN_GENTLE}s cooldown between stages. "
            "Use when scans are dropping your internet connection "
            "(NIC buffer exhaustion / ephemeral port exhaustion)."
        )
    )

    return parser.parse_args()


def interactive_module_selector():
    """Let the user choose which stages to run interactively."""
    print(f"\n{C.CYAN}{'='*60}{C.NC}")
    print(f"{C.YELLOW}  SELECT MODULES TO RUN  {C.NC}")
    print(f"{C.CYAN}{'='*60}{C.NC}")

    modules_info = [
        ("passive", "1", "Passive OSINT & Intelligence Gathering",  "WHOIS, DNS, crt.sh, OTX, VirusTotal, ASN, Shodan"),
        ("infra",   "2", "Infrastructure Mapping",                   "Port scanning, TLS/SSL, VHost discovery, cloud IP ranges"),
        ("subs",    "3", "Subdomain Enumeration (Passive + Active)", "subfinder, amass, assetfinder, recursive, alterx, dnsx"),
        ("web",     "4", "Web Discovery & Crawling",                 "GAU, waybackurls, katana, feroxbuster, directory bruteforce"),
        ("api",     "5", "API Discovery & Fuzzing",                  "Swagger, OpenAPI, GraphQL, kiterunner, ffuf API routes"),
        ("js",      "6", "JavaScript Analysis & Secrets",            "LinkFinder, SecretFinder, API key regex, endpoints"),
        ("cloud",   "7", "Cloud Asset Discovery",                    "S3, Azure Blob, GCP, Firebase, CloudFront detection"),
        ("nuclei",  "8", "Vulnerability Discovery",                  "CVEs, misconfigs, exposures, default-logins, takeovers"),
    ]

    selected = {}
    for key, num, name, desc in modules_info:
        print(f"\n  {C.BOLD}[{num}] {name}{C.NC}")
        print(f"      {C.GRAY}{desc}{C.NC}")
        choice = input(f"      Run this module? [Y/n]: ").strip().lower()
        selected[key] = choice != 'n'

    return selected


def run_setup():
    """Install all required tools."""
    print_stage("SETUP", "Installing Required Tools")

    go_tools = [
        ("subfinder",   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        ("httpx",       "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        ("naabu",       "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
        ("katana",      "github.com/projectdiscovery/katana/cmd/katana@latest"),
        ("nuclei",      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
        ("dnsx",        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
        ("tlsx",        "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"),
        ("asnmap",      "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"),
        ("alterx",      "github.com/projectdiscovery/alterx/cmd/alterx@latest"),
        ("assetfinder", "github.com/tomnomnom/assetfinder@latest"),
        ("waybackurls", "github.com/tomnomnom/waybackurls@latest"),
        ("anew",        "github.com/tomnomnom/anew@latest"),
        ("gf",          "github.com/tomnomnom/gf@latest"),
        ("gau",         "github.com/lc/gau/v2/cmd/gau@latest"),
        ("Gxss",        "github.com/KathanP19/Gxss@latest"),
        ("kr",          "github.com/assetnote/kiterunner/cmd/kr@latest"),
        ("amass",       "github.com/owasp-amass/amass/v4/...@master"),
        ("ffuf",        "github.com/ffuf/ffuf/v2@latest"),
        ("hakrawler",   "github.com/hakluke/hakrawler@latest"),
        ("chaos",       "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"),
        ("s3scanner",   "github.com/sa7mon/s3scanner@latest"),
    ]

    pip_tools = [
        ("trufflehog",   "trufflehog3"),
        ("linkfinder",   None),   # manual install
        ("secretfinder", None),   # manual install
        ("paramspider",  "paramspider"),
        ("arjun",        "arjun"),
    ]

    apt_tools = [
        "nmap", "whois", "dnsrecon", "curl", "jq",
        "sslscan", "git", "python3-pip", "golang-go"
    ]

    print_info("Installing APT packages...")
    for pkg in apt_tools:
        subprocess.run(["sudo", "apt-get", "install", "-y", "-q", pkg], capture_output=True)
        print_success(f"  apt: {pkg}")

    print_info("Installing Go tools (requires Go in PATH)...")
    if not shutil.which("go"):
        print_error("Go not found! Install from https://go.dev/dl/")
    else:
        for name, pkg in go_tools:
            if shutil.which(name):
                print_success(f"  [already installed] {name}")
                continue
            print_info(f"  Installing {name}...")
            result = subprocess.run(
                ["go", "install", "-v", pkg],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                print_success(f"  {name}")
            else:
                print_warning(f"  {name} failed — try manually:")
                print(f"     go install {pkg}")

    print_info("Installing Python tools...")
    for name, pkg in pip_tools:
        if pkg:
            subprocess.run([sys.executable, "-m", "pip", "install", "-q", pkg])
            print_success(f"  pip: {name}")

    # GF patterns
    print_info("Setting up GF patterns...")
    gf_dir = Path.home() / ".gf"
    gf_dir.mkdir(exist_ok=True)
    subprocess.run(["git", "clone", "-q",
                    "https://github.com/1ndianl33t/Gf-Patterns",
                    "/tmp/gf_patterns"], capture_output=True)
    subprocess.run(["cp", "-r", "/tmp/gf_patterns/.", str(gf_dir)], capture_output=True)

    # Nuclei templates
    print_info("Updating Nuclei templates...")
    subprocess.run(["nuclei", "-update-templates", "-silent"], capture_output=True)

    print_success("\n[✓] Setup complete!")
    print_info("Ensure ~/go/bin is in your PATH:")
    print(f"  {C.CYAN}echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc && source ~/.bashrc{C.NC}")


def _stage_cooldown(cooldown, stage_name):
    """Sleep between stages if cooldown > 0, with a visible countdown."""
    if cooldown <= 0:
        return
    print_info(
        f"Stage cooldown: {cooldown}s (--gentle mode — letting NIC recover after {stage_name})"
    )
    for remaining in range(cooldown, 0, -1):
        sys.stdout.write(f"\r  {C.GRAY}Resuming in {remaining}s...{C.NC} ")
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\r" + " " * 40 + "\r")
    sys.stdout.flush()


def main():
    args   = parse_args()
    config = load_config(args.config)

    banner()

    # ── SETUP MODE ────────────────────────────────────────────────────────────
    if args.setup:
        run_setup()
        return

    # ── CHECK TOOLS MODE ──────────────────────────────────────────────────────
    if args.check_tools:
        check_tools(verbose=True)
        return

    # ── TARGET REQUIRED FROM HERE ─────────────────────────────────────────────
    if not args.target:
        print_error("No target specified. Usage: python3 huntn.py <target>")
        print(f"  Run {C.CYAN}python3 huntn.py --help{C.NC} for options")
        sys.exit(1)

    # ── GENTLE MODE SETUP ─────────────────────────────────────────────────────
    gentle         = args.gentle
    stage_cooldown = STAGE_COOLDOWN_GENTLE if gentle else STAGE_COOLDOWN_DEFAULT

    # Thread count: CLI arg overrides gentle default
    if args.threads is not None:
        threads = args.threads
    else:
        threads = THREADS_GENTLE if gentle else THREADS_NORMAL

    if gentle:
        print(f"\n{C.YELLOW}[♦] GENTLE MODE — threads: {threads}, stage cooldown: {stage_cooldown}s{C.NC}")
        print(f"{C.GRAY}    Use this to prevent NIC saturation on budget hardware.{C.NC}\n")

    # ── TARGET PARSING ────────────────────────────────────────────────────────
    raw_target  = args.target
    target      = raw_target.lstrip("*.").lower().strip()
    is_wildcard = raw_target.startswith("*.") or args.wildcard

    print(f"\n{C.GREEN}[+] Target  : {C.BOLD}{target}{C.NC}")
    print(f"{C.GREEN}[+] Wildcard: {C.BOLD}{is_wildcard}{C.NC}")
    print(f"{C.GREEN}[+] Threads : {C.BOLD}{threads}{C.NC}")
    print(f"{C.GREEN}[+] Time    : {C.BOLD}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.NC}")
    if args.token:
        print(f"{C.GREEN}[+] Token   : {C.BOLD}{'*' * 12 + args.token[-4:]}{C.NC}")

    # ── WORKSPACE ─────────────────────────────────────────────────────────────
    output_base = args.output_dir or config.get("output_dir", ".")
    ws = WorkspaceManager(target, base_dir=output_base, resume=args.resume)
    ws.create_all()
    print(f"{C.GREEN}[+] Output  : {C.BOLD}{ws.root}{C.NC}\n")

    tool_status = check_tools(verbose=False)

    # ── MODULE SELECTION ──────────────────────────────────────────────────────
    all_keys = ["passive", "infra", "subs", "web", "api", "js", "cloud", "nuclei"]

    if args.all:
        selected = {k: True for k in all_keys}
    elif args.modules:
        requested = [m.strip() for m in args.modules.split(",")]
        selected  = {k: k in requested for k in all_keys}
    elif args.passive_only:
        selected  = {k: k in ("passive", "subs") for k in all_keys}
    else:
        selected  = interactive_module_selector()

    # ── IP TARGET SHORTCUT ────────────────────────────────────────────────────
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        print_info("Target is a raw IP — seeding live.txt directly, skipping passive DNS.")
        live_dir  = ws.path("subdomains")
        live_file = live_dir / "live.txt"
        live_file.write_text(f"{target}\n", encoding="utf-8")
        if selected.get("subs"):
            print_warning("Subdomain enumeration skipped (no domain to enumerate).")
            selected["subs"] = False

    # ── SCAN CONTEXT ──────────────────────────────────────────────────────────
    scan_context = {
        "target":       target,
        "raw_target":   raw_target,
        "is_wildcard":  is_wildcard,
        "ws":           ws,
        "config":       config,
        "tool_status":  tool_status,
        "threads":      threads,
        "token":        args.token,
        "wordlist":     args.wordlist,
        "severity":     args.severity,
        "scope_file":   args.scope_file,
        "gentle":       gentle,            # consumed by nuclei_scan, js_analysis
        "stage_cooldown": stage_cooldown,  # available to modules that want extra breathing room
    }

    start_time = time.time()

    # ══════════════════════════════════════════════════════════════════════════
    # STAGE RUNNER — each stage followed by optional cooldown
    # ══════════════════════════════════════════════════════════════════════════

    if selected.get("passive"):
        print_stage("1", "Passive Open Source Domain Intelligence")
        osint.run(scan_context)
        _stage_cooldown(stage_cooldown, "OSINT")

    if selected.get("subs"):
        print_stage("2", "Subdomain Enumeration")
        subdomains.run(scan_context)
        _stage_cooldown(stage_cooldown, "Subdomains")

    if selected.get("infra"):
        print_stage("3", "Infrastructure Mapping")
        infrastructure.run(scan_context)
        _stage_cooldown(stage_cooldown, "Infrastructure")

    if selected.get("web"):
        print_stage("4", "Web Discovery")
        web.run(scan_context)
        _stage_cooldown(stage_cooldown, "Web Discovery")

    if selected.get("api"):
        print_stage("5", "API Discovery")
        api.run(scan_context)
        _stage_cooldown(stage_cooldown, "API")

    if selected.get("js"):
        print_stage("6", "JavaScript & Secrets")
        js_analysis.run(scan_context)
        _stage_cooldown(stage_cooldown, "JS Analysis")

    if selected.get("cloud"):
        print_stage("7", "Cloud Asset Discovery")
        cloud.run(scan_context)
        _stage_cooldown(stage_cooldown, "Cloud")

    if selected.get("nuclei"):
        print_stage("8", "Vulnerability Discovery")
        nuclei_scan.run(scan_context)
        # No cooldown after nuclei — it's the last active stage

    # ── FINAL REPORT ──────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    print_stage("REPORT", "Attack Surface Report")
    reporting.run(scan_context, elapsed=elapsed)

    print(f"\n{C.GREEN}{'='*60}{C.NC}")
    print(f"{C.GREEN}  Hunt complete for {C.BOLD}{target}{C.NC}")
    print(f"{C.GREEN}  Duration : {elapsed/60:.1f} minutes{C.NC}")
    print(f"{C.GREEN}  Output   : {ws.root}/{C.NC}")
    print(f"{C.GREEN}{'='*60}{C.NC}\n")


if __name__ == "__main__":
    main()
