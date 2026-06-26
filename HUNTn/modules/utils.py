"""
HuntN Utilities — Shared helpers used by all modules.
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
    NC      = '\033[0m'

C = Colors


def banner():
    print(f"""{C.CYAN}
 ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███╗   ██╗
 ██║  ██║██║   ██║████╗  ██║╚══██╔══╝████╗  ██║
 ███████║██║   ██║██╔██╗ ██║   ██║   ██╔██╗ ██║
 ██╔══██║██║   ██║██║╚██╗██║   ██║   ██║╚██╗██║
 ██║  ██║╚██████╔╝██║ ╚████║   ██║   ██║ ╚████║
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═══╝
{C.NC}
{C.YELLOW}   The Hand of Light Uncovering Darkness{C.NC}
{C.GRAY}   "Even though I walk through the valley of the shadow of death,
    I will fear no evil, for You are with me." — Psalm 23:4{C.NC}
{C.GREEN}    Pause for a minute. {C.NC}
{C.RED}    Stay ethical. Stay blessed.{C.NC}
""")


def print_stage(num, name):
    print(f"\n{C.CYAN}{'='*65}{C.NC}")
    print(f"{C.BOLD}{C.YELLOW}  [{num}] {name.upper()}{C.NC}")
    print(f"{C.CYAN}{'='*65}{C.NC}")

def print_info(msg):    print(f"{C.BLUE}[*]{C.NC} {msg}")
def print_success(msg): print(f"{C.GREEN}[+]{C.NC} {msg}")
def print_warning(msg): print(f"{C.YELLOW}[!]{C.NC} {msg}")
def print_error(msg):   print(f"{C.RED}[✗]{C.NC} {msg}")
def print_find(msg):    print(f"{C.MAGENTA}[★]{C.NC} {msg}")
def print_skip(msg):    print(f"{C.GRAY}[-] SKIP: {msg}{C.NC}")


def ask_yes_no(prompt, default=True):
    suffix = "[Y/n]" if default else "[y/N]"
    val = input(f"{C.YELLOW}  {prompt} {suffix}: {C.NC}").strip().lower()
    if val == "": return default
    return val in ("y", "yes")


def run_cmd(cmd, output_file=None, timeout=600, shell=False, silent=False):
    """Run a command, optionally writing stdout to output_file. Returns (returncode, stdout, stderr)."""
    if not silent:
        print_info(f"Running: {C.CYAN}{cmd if isinstance(cmd, str) else ' '.join(cmd)}{C.NC}")
    try:
        if output_file:
            with open(output_file, "w") as f:
                result = subprocess.run(
                    cmd, shell=shell, stdout=f,
                    stderr=subprocess.PIPE, text=True, timeout=timeout
                )
        else:
            result = subprocess.run(
                cmd, shell=shell, capture_output=True, text=True, timeout=timeout
            )
        return result.returncode, result.stdout, result.stderr
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
    """Run a piped shell command and write to file."""
    print_info(f"Running: {C.CYAN}{cmd_str}{C.NC}")
    try:
        with open(output_file, "w") as f:
            result = subprocess.run(
                cmd_str, shell=True, stdout=f,
                stderr=subprocess.PIPE, text=True, timeout=timeout
            )
        return result.returncode
    except Exception as e:
        print_error(f"Pipe command error: {e}")
        return -1


def which(tool):
    return shutil.which(tool) is not None


REQUIRED_TOOLS = {
    # Core
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
    "gau":          ("go install github.com/lc/gau/v2/cmd/gau@latest", "archive URLs"),
    "Gxss":         ("go install github.com/KathanP19/Gxss@latest", "XSS reflection check"),
    "kr":           ("go install github.com/assetnote/kiterunner/cmd/kr@latest", "API discovery"),
    "ffuf":         ("go install github.com/ffuf/ffuf/v2@latest", "fuzzing"),
    "amass":        ("go install github.com/owasp-amass/amass/v4/...@master", "deep sub enum"),
    "s3scanner":    ("go install github.com/sa7mon/s3scanner@latest", "S3 discovery"),
    "chaos":        ("go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest", "chaos recon"),
    # System
    "nmap":         ("sudo apt install nmap", "port scanning"),
    "whois":        ("sudo apt install whois", "WHOIS lookups"),
    "curl":         ("sudo apt install curl", "HTTP requests"),
    "jq":           ("sudo apt install jq", "JSON parsing"),
    "sslscan":      ("sudo apt install sslscan", "SSL analysis"),
    "git":          ("sudo apt install git", "git operations"),
    "python3":      ("system", "required"),
    # Python
    "arjun":        ("pip3 install arjun", "parameter discovery"),
    "paramspider":  ("pip3 install paramspider", "parameter spider"),
}


def check_tools(verbose=True):
    """Check all tools, return dict of {name: bool}."""
    status = {}
    found = []
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


def load_config(path="config.yaml"):
    """Load YAML config, return defaults if not found."""
    defaults = {
        "output_dir": ".",
        "threads": 50,
        "timeout": 600,
        "wordlists": {
            "directories": "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
            "subdomains": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
            "api": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
            "vhosts": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-50000.txt",
        },
        "apis": {
            "shodan": "",
            "virustotal": "",
            "chaos": "",
            "urlscan": "",
        }
    }
    try:
        with open(path) as f:
            user_cfg = yaml.safe_load(f)
            defaults.update(user_cfg or {})
    except FileNotFoundError:
        pass
    return defaults


def create_workspace(target):
    """Create the directory structure."""
    base = Path(f"HuntN_{target}")
    dirs = [
        "intelligence",
        "subdomains",
        "infrastructure",
        "web",
        "api",
        "js",
        "cloud",
        "findings",
        "nuclei",
        "reports",
        "gf_filtered",
    ]
    for d in dirs:
        (base / d).mkdir(parents=True, exist_ok=True)
    return base


class WorkspaceManager:
    """Manages the output directory structure."""

    def __init__(self, target, base_dir=".", resume=False):
        self.target = target
        self.root = Path(base_dir) / f"HuntN_{target}"
        self.resume = resume

    def create_all(self):
        dirs = [
            "intelligence",
            "subdomains",
            "infrastructure",
            "web",
            "api",
            "js",
            "cloud",
            "findings",
            "nuclei",
            "reports",
            "gf_filtered",
            "secrets",
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
            return p.read_text(encoding="utf-8", errors="ignore").strip().splitlines()
        return []

    def count_lines(self, *parts):
        lines = self.read(*parts)
        return len([l for l in lines if l.strip()])


def count_lines(filepath):
    try:
        with open(filepath) as f:
            return sum(1 for l in f if l.strip())
    except:
        return 0


def append_unique(filepath, lines):
    """Append unique lines to a file."""
    existing = set()
    if Path(filepath).exists():
        existing = set(Path(filepath).read_text().splitlines())
    new_lines = [l for l in lines if l.strip() and l not in existing]
    if new_lines:
        with open(filepath, "a") as f:
            f.write("\n".join(new_lines) + "\n")
    return len(new_lines)


def curl_json(url, timeout=30):
    """Fetch JSON from a URL via curl."""
    try:
        result = subprocess.run(
            ["curl", "-s", "--max-time", str(timeout), url],
            capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout)
    except:
        pass
    return None
