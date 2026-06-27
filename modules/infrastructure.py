"""
HuntN — Module 3: Infrastructure Mapping
──────────────────────────────────────────────────────────────────────────────
Covers: naabu port scanning, nmap service detection, TLS/SSL (tlsx, sslscan),
        VHost discovery, ASN IP space, reverse DNS
"""

import subprocess
from pathlib import Path
from modules.utils import (
    C, print_info, print_success, print_warning, print_skip,
    run_cmd, run_cmd_pipe, which, which_or_install, count_lines
)


def run(ctx):
    target  = ctx["target"]
    ws      = ctx["ws"]
    config  = ctx["config"]
    threads = ctx["threads"]

    infra_dir = ws.path("infrastructure")
    live_file = ws.path("subdomains", "live.txt")

    # ── 3.1 PORT SCANNING WITH NAABU ──────────────────────────────────────────
    print_info("Port scanning with naabu...")
    ports_file = infra_dir / "ports.txt"

    if which_or_install("naabu"):
        if live_file.exists():
            run_cmd_pipe(
                f"naabu -l {live_file} -p - -s -c {threads} -silent -o {ports_file}",
                output_file=str(ports_file),
                timeout=900
            )
        else:
            run_cmd_pipe(
                f"echo {target} | naabu -p - -s -c {threads} -silent",
                output_file=str(ports_file),
                timeout=900
            )
        print_success(f"Port scan → {count_lines(ports_file)} open ports found")
    else:
        print_skip("naabu — go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
        # Fallback nmap
        if which_or_install("nmap") and live_file.exists():
            print_info("Fallback: nmap top-1000 ports...")
            run_cmd_pipe(
                f"nmap -iL {live_file} --open -T4 --top-ports 1000 -oG -",
                output_file=str(ports_file),
                timeout=900
            )
            print_success("nmap port scan done")

    # ── 3.2 NMAP SERVICE DETECTION ────────────────────────────────────────────
    print_info("Service version detection with nmap...")
    services_file = infra_dir / "services.txt"
    ips_file      = infra_dir / "ips.txt"

    if which_or_install("nmap") and ports_file.exists():
        run_cmd_pipe(
            f"cat {ports_file} 2>/dev/null | grep -oE '([0-9]{{1,3}}\\.?){{4}}' | sort -u",
            output_file=str(ips_file)
        )
        if count_lines(ips_file) > 0:
            run_cmd_pipe(
                f"nmap -iL {ips_file} -sV -sC -T4 --open -oN {services_file}",
                output_file=str(services_file),
                timeout=900
            )
            print_success("Service detection done")
        else:
            print_warning("No IPs found for nmap service scan")
    else:
        print_skip("nmap — sudo apt install nmap")

    # ── 3.3 TLS/SSL RECON ─────────────────────────────────────────────────────
    print_info("TLS/SSL recon with tlsx...")
    tls_file = infra_dir / "tls.txt"

    if which_or_install("tlsx") and live_file.exists():
        run_cmd_pipe(
            f"cat {live_file} | tlsx -silent -san -cn -json",
            output_file=str(tls_file),
            timeout=300
        )
        print_success(f"TLS recon → {tls_file.name}")

        # Extract SANs as an extra subdomain source
        san_file = ws.path("subdomains", "tls_san.txt")
        run_cmd_pipe(
            f"cat {tls_file} | python3 -c \""
            f"import sys,json; [print(s) for l in sys.stdin "
            f"for d in [json.loads(l) if l.strip() else {{}}] "
            f"for s in d.get('san',[]) if s]\" 2>/dev/null",
            output_file=str(san_file)
        )
        if count_lines(san_file) > 0:
            print_success(f"SAN domains extracted → subdomains/tls_san.txt")
    else:
        print_skip("tlsx — go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest")
        if which_or_install("sslscan"):
            print_info("Fallback: sslscan on target...")
            run_cmd_pipe(
                f"sslscan {target}:443",
                output_file=str(tls_file),
                timeout=60
            )

    # ── 3.4 VIRTUAL HOST DISCOVERY ────────────────────────────────────────────
    print_info("Virtual host discovery with ffuf...")
    vhosts_file = infra_dir / "vhosts.txt"
    vhost_wl    = config.get("wordlists", {}).get(
        "vhosts",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-50000.txt"
    )

    if which_or_install("ffuf") and Path(vhost_wl).exists():
        # Resolve target to an IP for VHost bruteforce
        ip_result = subprocess.run(
            ["dig", "+short", "A", target],
            capture_output=True, text=True
        )
        ip = ip_result.stdout.strip().splitlines()
        ip = ip[0] if ip else target

        # FIX: -w -:FUZZ with stdin wordlist pipe (correct ffuf vhost syntax)
        run_cmd_pipe(
            f"cat {vhost_wl} | ffuf -w -:FUZZ -u http://{ip}/ "
            f"-H 'Host: FUZZ.{target}' -ac -silent -o {vhosts_file} -of csv",
            output_file=str(vhosts_file),
            timeout=600
        )
        if count_lines(vhosts_file) > 0:
            print_success(f"VHost discovery → {vhosts_file.name}")
        else:
            print_info("VHost discovery complete — no unique vhosts found.")
    elif not which("ffuf"):
        print_skip("ffuf — go install github.com/ffuf/ffuf/v2@latest")
    else:
        print_warning(f"VHost wordlist not found: {vhost_wl}")

    # ── 3.5 ASN IP RANGE MAPPING ──────────────────────────────────────────────
    print_info("ASN IP space mapping with asnmap...")
    asn_file = infra_dir / "asn_ranges.txt"

    if which_or_install("asnmap"):
        run_cmd_pipe(
            f"echo {target} | asnmap -silent",
            output_file=str(asn_file),
            timeout=120   # asnmap is known to hang; cap it
        )
        print_success(f"ASN IP ranges → {asn_file.name}")
        print_info("Tip: Run naabu against these ranges: naabu -l asn_ranges.txt -p 80,443,8080,8443 -silent")
    else:
        print_skip("asnmap — go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest")

    # ── 3.6 REVERSE DNS ───────────────────────────────────────────────────────
    print_info("Reverse DNS on discovered IPs...")
    rdns_file = infra_dir / "reverse_dns.txt"

    if ips_file.exists() and count_lines(ips_file) > 0:
        run_cmd_pipe(
            f"cat {ips_file} | xargs -P 20 -I {{}} sh -c 'echo \"=== {{}} ===\"; host {{}};' 2>/dev/null",
            output_file=str(rdns_file),
            timeout=120
        )
        print_success(f"Reverse DNS → {rdns_file.name}")

    print_success("Infrastructure mapping complete.\n")
