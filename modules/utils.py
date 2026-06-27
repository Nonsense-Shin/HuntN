"""
HuntN Utilities — Shared helpers used by all modules.

"For I know the plans I have for you, declares the Lord, plans to prosper
you and not to harm you, plans to give you hope and a future." — Jer 29:11

"""

import os
import sys
import subprocess
import shutil
import yaml
import json
import time
from pathlib import Path
from datetime import datetime


class Colors:
    RED     = '\033[0;31m'
    GREEN   = '\033[0;32m'
    YELLOW  = '\033[1;33m'
    BLUE    = '\033[0;34m'
    CYAN    = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    WHITE   = '\033[1;37m'
    BOLD    = '\033[1m'
    GRAY    = '\033[0;90m'
    GOLD    = '\033[0;33m'
    NC      = '\033[0m'

C = Colors


def banner():
    print(f"""{C.CYAN}
 ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███╗   ██╗
 ██║  ██║██║   ██║████╗  ██║╚══██╔══╝████╗  ██║
 ███████║██║   ██║██╔██╗ ██║   ██║   ██╔██╗ ██║
 ██╔══██║██║   ██║██║╚██╗██║   ██║   ██║╚██╗██║
 ██║  ██║╚██████╔╝██║ ╚████║   ██║   ██║ ╚████║
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═══╝{C.NC}

{C.YELLOW}         "And you shall know the truth, and the truth shall set you free."{C.NC}
{C.YELLOW}                                                             — John 8:32{C.NC}
{C.GRAY}
                                      ✝     ✝
                                      ✝     ✝
                                      ✝     ✝
                                      ✝     ✝
                                      ✝  ✝  ✝
  ✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝     ✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝
  "Trust in the Lord with all your heart and lean not on your own understanding;
   in all your ways submit to Him, and He will make your paths straight."
                                                            — Proverbs 3:5-6
  ✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝     ✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝✝
                                      ✝     ✝
                                      ✝     ✝
                                      ✝     ✝
                                      ✝     ✝ 
                                      ✝     ✝
                                      ✝     ✝
                                      ✝     ✝
                                      ✝     ✝
                                      ✝     ✝{C.NC}

{C.YELLOW}                         The Hand of Light Uncovering Darkness{C.NC}
{C.RED}                                Stay ethical. Stay blessed.{C.NC}
""")

def print_stage(num, name):
    print(f"\n{C.CYAN}{'═'*65}{C.NC}")
    print(f"{C.BOLD}{C.YELLOW}  [{num}] {name.upper()}{C.NC}")
    print(f"{C.CYAN}{'═'*65}{C.NC}")

def print_info(msg):    print(f"{C.BLUE}[*]{C.NC} {msg}")
def print_success(msg): print(f"{C.GREEN}[+]{C.NC} {msg}")
def print_warning(msg): print(f"{C.YELLOW}[!]{C.NC} {msg}")
def print_error(msg):   print(f"{C.RED}[✗]{C.NC} {msg}")
def print_find(msg):    print(f"{C.MAGENTA}[★]{C.NC} {msg}")
def print_skip(msg):    print(f"{C.GRAY}[-] SKIP: {msg}{C.NC}")


def ask_yes_no(prompt, default=True):
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        val = input(f"{C.YELLOW}  {prompt} {suffix}: {C.NC}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return default
    if val == "":
        return default
    return val in ("y", "yes")


# ── TOOL INSTALL HELPERS ───────────────────────────────────────────────────────

TOOL_INSTALL_MAP = {
    "subfinder":    ("github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",   "go"),
    "httpx":        ("github.com/projectdiscovery/httpx/cmd/httpx@latest",               "go"),
    "naabu":        ("github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",            "go"),
    "katana":       ("github.com/projectdiscovery/katana/cmd/katana@latest",             "go"),
    "nuclei":       ("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",          "go"),
    "dnsx":         ("github.com/projectdiscovery/dnsx/cmd/dnsx@latest",                 "go"),
    "tlsx":         ("github.com/projectdiscovery/tlsx/cmd/tlsx@latest",                 "go"),
    "asnmap":       ("github.com/projectdiscovery/asnmap/cmd/asnmap@latest",             "go"),
    "alterx":       ("github.com/projectdiscovery/alterx/cmd/alterx@latest",             "go"),
    "assetfinder":  ("github.com/tomnomnom/assetfinder@latest",                          "go"),
    "waybackurls":  ("github.com/tomnomnom/waybackurls@latest",                          "go"),
    "anew":         ("github.com/tomnomnom/anew@latest",                                 "go"),
    "gf":           ("github.com/tomnomnom/gf@latest",                                   "go"),
    "gau":          ("github.com/lc/gau/v2/cmd/gau@latest",                              "go"),
    "Gxss":         ("github.com/KathanP19/Gxss@latest",                                 "go"),
    "kr":           ("github.com/assetnote/kiterunner/cmd/kr@latest",                    "go"),
    "ffuf":         ("github.com/ffuf/ffuf/v2@latest",                                   "go"),
    "amass":        ("github.com/owasp-amass/amass/v4/...@master",                       "go"),
    "s3scanner":    ("github.com/sa7mon/s3scanner@latest",                               "go"),
    "chaos":        ("github.com/projectdiscovery/chaos-client/cmd/chaos@latest",        "go"),
    "hakrawler":    ("github.com/hakluke/hakrawler@latest",                              "go"),
    "uro":          ("github.com/s0md3v/uro@latest",                                     "go"),
    "nmap":         ("nmap",                                                              "apt"),
    "whois":        ("whois",                                                             "apt"),
    "curl":         ("curl",                                                              "apt"),
    "jq":           ("jq",                                                                "apt"),
    "sslscan":      ("sslscan",                                                           "apt"),
    "git":          ("git",                                                               "apt"),
    "feroxbuster":  ("feroxbuster",                                                       "cargo"),
    "arjun":        ("arjun",                                                             "pip"),
    "paramspider":  ("paramspider",                                                       "pip"),
}

TOOL_PURPOSE = {
    "subfinder":   "passive subdomain enumeration",
    "httpx":       "live host filtering & tech detection",
    "naabu":       "fast port scanning",
    "katana":      "active web crawling",
    "nuclei":      "vulnerability scanning",
    "dnsx":        "DNS resolution & bruteforce",
    "tlsx":        "TLS/SSL certificate recon",
    "asnmap":      "ASN IP range mapping",
    "alterx":      "subdomain permutation generation",
    "assetfinder": "passive subdomain enumeration",
    "waybackurls": "Wayback Machine URL collection",
    "anew":        "deduplication of results",
    "gf":          "URL pattern filtering (XSS/SQLi/SSRF/etc)",
    "gau":         "archived URL collection (multi-provider)",
    "Gxss":        "XSS parameter reflection check",
    "kr":          "API route discovery (kiterunner)",
    "ffuf":        "directory & API fuzzing",
    "amass":       "deep passive/active subdomain enumeration",
    "s3scanner":   "S3 bucket enumeration",
    "chaos":       "ProjectDiscovery chaos dataset",
    "hakrawler":   "supplemental web crawling",
    "uro":         "URL deduplication & normalization",
    "nmap":        "service version detection",
    "whois":       "WHOIS domain lookups",
    "curl":        "HTTP requests",
    "jq":          "JSON parsing",
    "sslscan":     "SSL cipher suite analysis",
    "git":         "git operations",
    "feroxbuster": "recursive directory bruteforce",
    "arjun":       "HTTP parameter discovery",
    "paramspider": "URL parameter extraction",
}


def prompt_install(tool_name):
    """
    If a tool is missing, ask the user if they want to install it now.
    Returns True if the tool is now available.
    """
    if which(tool_name):
        return True

    purpose      = TOOL_PURPOSE.get(tool_name, "recon")
    install_info = TOOL_INSTALL_MAP.get(tool_name)

    if not install_info:
        print_skip(f"{tool_name} — no automatic installer, install manually")
        return False

    pkg, install_type = install_info

    print(f"\n{C.YELLOW}[?] {C.BOLD}{tool_name}{C.NC}{C.YELLOW} is not installed.{C.NC}")
    print(f"    Purpose : {purpose}")

    if install_type == "go":
        print(f"    Command : {C.CYAN}go install {pkg}{C.NC}")
    elif install_type == "apt":
        print(f"    Command : {C.CYAN}sudo apt install -y {pkg}{C.NC}")
    elif install_type == "pip":
        print(f"    Command : {C.CYAN}pip3 install {pkg}{C.NC}")
    elif install_type == "cargo":
        print(f"    Command : {C.CYAN}cargo install {pkg}{C.NC}")

    if not ask_yes_no(f"Install {tool_name} now?", default=True):
        print_skip(f"{tool_name} — skipping")
        return False

    print_info(f"Installing {tool_name}...")

    try:
        if install_type == "go":
            if not shutil.which("go"):
                print_error("Go not in PATH. Install from https://go.dev/dl/ then re-run.")
                return False
            result = subprocess.run(["go", "install", pkg], capture_output=False, text=True, timeout=300)
        elif install_type == "apt":
            result = subprocess.run(["sudo", "apt", "install", "-y", pkg], capture_output=False, text=True, timeout=300)
        elif install_type == "pip":
            result = subprocess.run([sys.executable, "-m", "pip", "install", pkg], capture_output=False, text=True, timeout=300)
        elif install_type == "cargo":
            if not shutil.which("cargo"):
                print_error("cargo not found. Install Rust: https://rustup.rs/")
                return False
            result = subprocess.run(["cargo", "install", pkg], capture_output=False, text=True, timeout=600)
        else:
            print_warning(f"Manual install required: {pkg}")
            return False

        if result.returncode == 0 and which(tool_name):
            print_success(f"{tool_name} installed successfully!")
            return True
        else:
            print_error(f"Installation returned code {result.returncode}. Check errors above.")
            return False

    except subprocess.TimeoutExpired:
        print_error(f"Installation timed out for {tool_name}")
        return False
    except Exception as e:
        print_error(f"Installation failed: {e}")
        return False


def which(tool):
    """Check if a tool is available in PATH."""
    return shutil.which(tool) is not None


def which_or_install(tool):
    """
    Check if tool is available; if not, prompt to install.
    Returns True if tool is now usable.
    Use this instead of bare `which()` in module run() calls.
    """
    if which(tool):
        return True
    return prompt_install(tool)


# ── SAFE FILE WRITING ──────────────────────────────────────────────────────────

def safe_write(filepath, lines_or_content):
    """
    Write content to filepath ONLY if there is actual content.
    Does NOT overwrite with empty — preserves existing data if nothing new.
    Returns number of lines/bytes written, or 0 if skipped.
    """
    path = Path(filepath)
    if isinstance(lines_or_content, list):
        content_lines = [l for l in lines_or_content if str(l).strip()]
        if not content_lines:
            return 0
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(content_lines) + "\n", encoding="utf-8")
        return len(content_lines)
    else:
        text = str(lines_or_content).strip()
        if not text:
            return 0
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
        return len(text.splitlines())


def safe_append(filepath, line):
    """Append a single non-empty line to a file."""
    line = str(line).strip()
    if not line:
        return
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# ── COMMAND RUNNERS ────────────────────────────────────────────────────────────

def run_cmd(cmd, output_file=None, timeout=600, shell=False, silent=False):
    """
    Run a command (list or string), optionally writing stdout to output_file.

    Normalisation rules:
      - string + shell=False → wrap in ['sh', '-c', cmd]
      - list → always shell=False
      - string + shell=True → pass as-is

    Rate-limit detection: if stderr contains "429" or "rate limit", warns
    but does not fail — the caller decides how to handle it.
    """
    if not silent:
        cmd_display = cmd if isinstance(cmd, str) else " ".join(cmd)
        print_info(f"Running: {C.CYAN}{cmd_display}{C.NC}")

    if isinstance(cmd, str) and not shell:
        actual_cmd = ["sh", "-c", cmd]
        use_shell  = False
    elif isinstance(cmd, list):
        actual_cmd = cmd
        use_shell  = False
    else:
        actual_cmd = cmd
        use_shell  = shell

    try:
        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                result = subprocess.run(
                    actual_cmd, shell=use_shell, stdout=f,
                    stderr=subprocess.PIPE, text=True, timeout=timeout
                )
            _cleanup_empty_file(output_file)
            stderr = result.stderr or ""
        else:
            result = subprocess.run(
                actual_cmd, shell=use_shell,
                capture_output=True, text=True, timeout=timeout
            )
            stderr = result.stderr or ""

        # Surface rate-limit signals without crashing
        if "429" in stderr or "rate limit" in stderr.lower():
            print_warning("Rate limit detected — tool may have been throttled.")

        return result.returncode, result.stdout, stderr

    except subprocess.TimeoutExpired:
        print_warning(f"Command timed out after {timeout}s")
        return -1, "", "timeout"
    except FileNotFoundError as e:
        print_error(f"Binary not found: {e}")
        return -2, "", str(e)
    except Exception as e:
        print_error(f"Command error: {e}")
        return -3, "", str(e)


def run_cmd_pipe(cmd_str, output_file, timeout=600):
    """
    Run a piped shell command string and write stdout to file.
    stderr is discarded (warnings from Go tools don't belong in data files).
    Auto-removes empty output files.

    Handles rate-limiting: if the command exits with indication of rate limit,
    logs a warning but still saves whatever was collected.
    Returns returncode (int).
    """
    print_info(f"Running: {C.CYAN}{cmd_str}{C.NC}")
    try:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            result = subprocess.run(
                cmd_str, shell=True, stdout=f,
                stderr=subprocess.DEVNULL,
                text=True, timeout=timeout
            )
        _cleanup_empty_file(output_file)
        return result.returncode
    except subprocess.TimeoutExpired:
        print_warning(f"Command timed out after {timeout}s — partial results saved: {cmd_str[:60]}")
        # Don't clean up on timeout — partial results are valuable
        return -1
    except Exception as e:
        print_error(f"Pipe command error: {e}")
        return -1


def run_cmd_with_retry(cmd_str, output_file, timeout=600, retries=3, backoff_base=5):
    """
    Run a shell command with exponential back-off retry on failure.
    Use this for network-dependent commands that may hit rate limits or
    transient errors on large infrastructure.

    Back-off schedule: 5s, 10s, 20s (base * 2^attempt).
    Returns returncode of the last attempt.
    """
    for attempt in range(1, retries + 1):
        rc = run_cmd_pipe(cmd_str, output_file, timeout=timeout)
        if rc == 0:
            return 0
        if attempt < retries:
            wait = backoff_base * (2 ** (attempt - 1))
            print_warning(f"Attempt {attempt}/{retries} failed (rc={rc}). "
                          f"Retrying in {wait}s...")
            time.sleep(wait)
        else:
            print_warning(f"All {retries} attempts failed for: {cmd_str[:60]}")
    return rc


def run_cmd_live(cmd_str, label=None, timeout=600):
    """
    Run a shell command and stream its stdout line-by-line to the terminal.
    Useful for long-running tools where you want to see progress.
    Returns (returncode, list_of_output_lines).
    """
    if label:
        print_info(label)
    lines = []
    try:
        proc = subprocess.Popen(
            cmd_str, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True
        )
        for line in proc.stdout:
            stripped = line.rstrip()
            if stripped:
                print(f"  {C.GRAY}{stripped}{C.NC}")
                lines.append(stripped)
        proc.wait(timeout=timeout)
        return proc.returncode, lines
    except subprocess.TimeoutExpired:
        print_warning(f"Live command timed out after {timeout}s")
        return -1, lines
    except Exception as e:
        print_error(f"Live command error: {e}")
        return -1, lines


def _cleanup_empty_file(filepath):
    """Delete a file if it is empty or contains only whitespace."""
    try:
        p = Path(filepath)
        if not p.exists():
            return
        if p.stat().st_size == 0:
            p.unlink()
            return
        content = p.read_text(encoding="utf-8", errors="ignore").strip()
        if not content:
            p.unlink()
    except (PermissionError, OSError):
        pass
    except Exception:
        pass


# ── TOOL CHECK ─────────────────────────────────────────────────────────────────

REQUIRED_TOOLS = {
    "subfinder":    ("go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "passive subs"),
    "httpx":        ("go install github.com/projectdiscovery/httpx/cmd/httpx@latest", "live host filtering"),
    "naabu":        ("go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "port scanning"),
    "katana":       ("go install github.com/projectdiscovery/katana/cmd/katana@latest", "web crawling"),
    "nuclei":       ("go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "vuln scanning"),
    "dnsx":         ("go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "DNS resolution"),
    "tlsx":         ("go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest", "TLS recon"),
    "asnmap":       ("go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest", "ASN mapping"),
    "alterx":       ("go install github.com/projectdiscovery/alterx/cmd/alterx@latest", "subdomain permutations"),
    "assetfinder":  ("go install github.com/tomnomnom/assetfinder@latest", "passive subs"),
    "waybackurls":  ("go install github.com/tomnomnom/waybackurls@latest", "archive URLs"),
    "anew":         ("go install github.com/tomnomnom/anew@latest", "deduplication"),
    "gf":           ("go install github.com/tomnomnom/gf@latest", "pattern filtering"),
    "gau":          ("go install github.com/lc/gau/v2/cmd/gau@latest", "archive URLs multi-provider"),
    "Gxss":         ("go install github.com/KathanP19/Gxss@latest", "XSS reflection check"),
    "kr":           ("go install github.com/assetnote/kiterunner/cmd/kr@latest", "API discovery"),
    "ffuf":         ("go install github.com/ffuf/ffuf/v2@latest", "fuzzing"),
    "amass":        ("go install github.com/owasp-amass/amass/v4/...@master", "deep sub enum"),
    "s3scanner":    ("go install github.com/sa7mon/s3scanner@latest", "S3 discovery"),
    "chaos":        ("go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest", "chaos recon"),
    "uro":          ("go install github.com/s0md3v/uro@latest", "URL normalization"),
    "nmap":         ("sudo apt install nmap", "port scanning"),
    "whois":        ("sudo apt install whois", "WHOIS lookups"),
    "curl":         ("sudo apt install curl", "HTTP requests"),
    "jq":           ("sudo apt install jq", "JSON parsing"),
    "sslscan":      ("sudo apt install sslscan", "SSL analysis"),
    "git":          ("sudo apt install git", "git operations"),
    "python3":      ("system", "required"),
    "arjun":        ("pip3 install arjun", "parameter discovery"),
    "paramspider":  ("pip3 install paramspider", "parameter spider"),
}


def check_tools(verbose=True):
    """Check all tools, return dict of {name: bool}."""
    status  = {}
    found   = []
    missing = []

    for tool, (install_cmd, purpose) in REQUIRED_TOOLS.items():
        installed = which(tool)
        status[tool] = installed
        if installed:
            found.append(tool)
        else:
            missing.append((tool, install_cmd, purpose))

    if verbose:
        print(f"\n{C.GREEN}[+] Installed ({len(found)}){C.NC}")
        for t in found:
            print(f"  {C.GREEN}✓{C.NC}  {t}")

        if missing:
            print(f"\n{C.YELLOW}[!] Missing ({len(missing)}){C.NC}")
            for t, cmd, purpose in missing:
                print(f"  {C.RED}✗{C.NC}  {t:<18} {C.GRAY}# {purpose}{C.NC}")
                print(f"     {C.CYAN}Install: {cmd}{C.NC}")

    return status


# ── CONFIG & WORKSPACE ─────────────────────────────────────────────────────────

def load_config(path="config.yaml"):
    """Load YAML config, return merged defaults if not found."""
    defaults = {
        "output_dir": ".",
        "threads": 50,
        "timeout": 600,
        "wordlists": {
            "directories": "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
            "subdomains":  "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
            "api":         "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
            "vhosts":      "/usr/share/seclists/Discovery/DNS/subdomains-top1million-50000.txt",
        },
        "apis": {
            "shodan":     "",
            "virustotal": "",
            "chaos":      "",
            "urlscan":    "",
            "otx":        "",
        }
    }
    try:
        with open(path) as f:
            user_cfg = yaml.safe_load(f)
            if user_cfg:
                for key in ("wordlists", "apis"):
                    if key in user_cfg:
                        defaults[key].update(user_cfg.pop(key))
                defaults.update(user_cfg)
    except FileNotFoundError:
        pass
    except Exception as e:
        print_warning(f"Config load warning: {e} — using defaults")
    return defaults


def create_workspace(target):
    """Create the directory structure (legacy helper)."""
    base = Path(f"HuntN_{target}")
    dirs = [
        "intelligence", "subdomains", "subdomains/raw",
        "infrastructure", "web", "web/raw",
        "api", "js", "cloud", "findings",
        "nuclei", "reports", "gf_filtered", "secrets",
    ]
    for d in dirs:
        (base / d).mkdir(parents=True, exist_ok=True)
    return base


class WorkspaceManager:
    """Manages the output directory structure."""

    def __init__(self, target, base_dir=".", resume=False):
        self.target = target
        self.root   = Path(base_dir) / f"HuntN_{target}"
        self.resume = resume

    def create_all(self):
        dirs = [
            "intelligence", "subdomains", "subdomains/raw",
            "infrastructure", "web", "web/raw",
            "api", "js", "cloud", "findings",
            "nuclei", "reports", "gf_filtered", "secrets",
        ]
        for d in dirs:
            (self.root / d).mkdir(parents=True, exist_ok=True)

    def path(self, *parts):
        return self.root / Path(*parts)

    def file_exists(self, *parts):
        p = self.path(*parts)
        return p.exists() and p.stat().st_size > 0

    def read(self, *parts):
        p = self.path(*parts)
        if p.exists():
            text = p.read_text(encoding="utf-8", errors="ignore")
            text = text.lstrip("\ufeff")
            return [l for l in text.strip().splitlines() if l.strip()]
        return []

    def count_lines(self, *parts):
        return len(self.read(*parts))


def count_lines(filepath):
    """Count non-empty lines in a file. Accepts str or Path."""
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            return sum(1 for l in f if l.strip())
    except Exception:
        return 0


def append_unique(filepath, lines):
    """
    Append unique lines to a file.
    Buffered for large files — reads existing set once, then writes new lines.
    """
    existing = set()
    fp = Path(filepath)
    if fp.exists():
        with open(fp, encoding="utf-8", errors="ignore") as f:
            for line in f:
                existing.add(line.rstrip("\n"))
    new_lines = [l for l in lines if l.strip() and l not in existing]
    if new_lines:
        fp.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "a", encoding="utf-8") as f:
            f.write("\n".join(new_lines) + "\n")
    return len(new_lines)


def curl_json(url, timeout=30, retries=2):
    """
    Fetch JSON from a URL via curl. Returns parsed dict/list or None.
    Retries with back-off on failure. Sends a browser User-Agent to
    avoid WAF blocks on some hosts.
    """
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
    for attempt in range(1, retries + 1):
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", str(timeout),
                 "-A", ua, url],
                capture_output=True, text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
        except Exception:
            pass
        if attempt < retries:
            time.sleep(2 ** attempt)
    return None
