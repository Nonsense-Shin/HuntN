"""
HuntN — Module 7: Cloud Asset Discovery
Covers: S3 bucket enumeration, Azure Blob, GCP Storage, Firebase, CloudFront
"""

import re
import subprocess
from pathlib import Path
from modules.utils import (
    C, print_info, print_success, print_warning, print_skip, print_find,
    run_cmd, run_cmd_pipe, which, count_lines
)


def run(ctx):
    target  = ctx["target"]
    ws      = ctx["ws"]
    config  = ctx["config"]

    cloud_dir = ws.path("cloud")
    all_urls  = ws.path("web", "all_urls.txt")
    js_dir    = ws.path("js")

    # ── 7.1 S3 BUCKET DISCOVERY ──────────────────────────────────
    print_info("S3 bucket discovery...")
    s3_file = cloud_dir / "s3_buckets.txt"

    # Generate permutations of likely bucket names
    org = target.split(".")[0]
    parts = target.replace("-", ".").replace("_", ".").split(".")
    bucket_names = _generate_bucket_names(org, parts)

    # Write candidate names
    candidates_file = cloud_dir / "bucket_candidates.txt"
    with open(candidates_file, "w") as f:
        f.write("\n".join(bucket_names))
    print_info(f"Generated {len(bucket_names)} bucket name candidates")

    if which("s3scanner"):
        run_cmd_pipe(
            f"s3scanner scan --bucket-file {candidates_file} 2>/dev/null",
            output_file=str(s3_file)
        )
        print_success(f"s3scanner → {count_lines(s3_file)} results")
    else:
        print_skip("s3scanner — go install github.com/sa7mon/s3scanner@latest")
        # Manual curl check for most likely names
        _manual_s3_check(bucket_names[:30], s3_file)

    # Extract S3 references from crawled content
    if all_urls.exists():
        s3_refs_file = cloud_dir / "s3_references.txt"
        run_cmd_pipe(
            f"cat {all_urls} {js_dir}/*.txt 2>/dev/null | "
            f"grep -iEo 's3://[a-z0-9._-]+|[a-z0-9.-]+\\.s3\\.amazonaws\\.com[^\"\\s]*' | sort -u",
            output_file=str(s3_refs_file)
        )
        n_refs = count_lines(s3_refs_file)
        if n_refs > 0:
            print_find(f"S3 references in crawled content: {n_refs}")

    # ── 7.2 AZURE BLOB DISCOVERY ─────────────────────────────────
    print_info("Azure Blob storage discovery...")
    azure_file = cloud_dir / "azure_blobs.txt"
    azure_names = _generate_azure_names(org, parts)

    azure_found = []
    for name in azure_names[:50]:
        url = f"https://{name}.blob.core.windows.net"
        try:
            result = subprocess.run(
                ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", url],
                capture_output=True, text=True, timeout=10
            )
            code = result.stdout.strip()
            if code in ("200", "400", "403", "409"):  # 400/403 = exists but restricted
                azure_found.append(f"{url} (HTTP {code})")
                if code == "200":
                    print_find(f"Azure Blob OPEN: {url}")
        except subprocess.TimeoutExpired:
            print(f"[-] SKIP: Azure endpoint timed out on {url}")
            continue
        except Exception as e:
            print(f"[-] Error probing Azure endpoint {url}: {str(e)}")
            continue

    with open(azure_file, "w") as f:
        f.write("\n".join(azure_found))
    print_success(f"Azure Blob scan → {len(azure_found)} hits")

    # ── 7.3 GCP STORAGE DISCOVERY ────────────────────────────────
    print_info("GCP Cloud Storage discovery...")
    gcp_file = cloud_dir / "gcp_storage.txt"
    gcp_found = []

    for name in bucket_names[:40]:
        url = f"https://storage.googleapis.com/{name}"
        try:
            result = subprocess.run(
                ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", url],
                capture_output=True, text=True, timeout=10
            )
            code = result.stdout.strip()
            if code in ("200", "403"):
                gcp_found.append(f"{url} (HTTP {code})")
                if code == "200":
                    print_find(f"GCP Storage OPEN: {url}")
        except subprocess.TimeoutExpired:
            print(f"[-] SKIP: GCP storage timed out on {url}")
            continue
        except Exception as e:
            print(f"[-] Error probing GCP storage {url}: {str(e)}")
            continue

    with open(gcp_file, "w") as f:
        f.write("\n".join(gcp_found))
    print_success(f"GCP Storage scan → {len(gcp_found)} hits")

    # ── 7.4 FIREBASE DETECTION ───────────────────────────────────
    print_info("Firebase detection...")
    firebase_file = cloud_dir / "firebase.txt"
    firebase_found = []

    fb_names = [org] + [f"{org}-{s}" for s in ["app", "prod", "dev", "staging", "api", "web"]]
    for name in fb_names:
        url = f"https://{name}.firebaseio.com/.json"
        try:
            result = subprocess.run(
                ["curl", "-sk", "--max-time", "10", url],
                capture_output=True, text=True, timeout=15
            )
            if result.stdout and "error" not in result.stdout.lower()[:50]:
                firebase_found.append(f"OPEN DB: {url}\n{result.stdout[:200]}")
                print_find(f"Firebase DB OPEN: {url}")
            elif result.returncode == 0:
                firebase_found.append(f"EXISTS (secured): {name}.firebaseio.com")
        except subprocess.TimeoutExpired:
            print(f"[-] SKIP: Firebase DB endpoint timed out on {url}")
            continue
        except Exception:
            continue

    # Firebase storage
    for name in fb_names:
        url = f"https://firebasestorage.googleapis.com/v0/b/{name}.appspot.com/o"
        try:
            result = subprocess.run(
                ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", url],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip() in ("200", "403"):
                firebase_found.append(f"Firebase Storage: {url} (HTTP {result.stdout.strip()})")
        except subprocess.TimeoutExpired:
            print(f"[-] SKIP: Firebase storage endpoint timed out on {url}")
            continue
        except Exception:
            continue

    with open(firebase_file, "w") as f:
        f.write("\n".join(firebase_found))

    # ── 7.5 CLOUDFRONT / CDN DETECTION ───────────────────────────
    print_info("CloudFront/CDN detection from live hosts...")
    cdn_file = cloud_dir / "cdn_detection.txt"
    live_file = ws.path("subdomains", "live.txt")

    if live_file.exists():
        run_cmd_pipe(
            f"cat {live_file} | xargs -P 10 -I {{}} sh -c "
            f"\"curl -sk -I {{}} 2>/dev/null | grep -i 'x-amz\\|cloudfront\\|cloudflare\\|fastly\\|akamai\\|cdn' | "
            f"sed 's/^/{{}} | /'\"",
            output_file=str(cdn_file)
        )
        print_success(f"CDN detection → {cdn_file.name}")

    # ── 7.6 CLOUD METADATA SSRF HINTS ────────────────────────────
    _generate_cloud_ssrf_hints(target, ws)

    print_success("Cloud discovery complete.\n")


def _generate_bucket_names(org, parts):
    """Generate likely S3 bucket name candidates."""
    suffixes = ["", "-dev", "-staging", "-prod", "-backup", "-data", "-assets",
                "-static", "-media", "-upload", "-downloads", "-files", "-logs",
                "-archive", "-temp", "-test", "-public", "-private", "-internal",
                "-api", "-web", "-app", "-store", "-storage", "-content"]
    prefixes = ["", "dev-", "staging-", "prod-", "backup-", "static-", "assets-",
                "media-", "upload-", "downloads-", "api-", "app-"]

    names = set()
    base_names = [org] + parts[:2]

    for base in base_names:
        for suffix in suffixes:
            for prefix in prefixes:
                name = f"{prefix}{base}{suffix}".lower()
                name = re.sub(r'[^a-z0-9.-]', '-', name)
                if 3 <= len(name) <= 63:
                    names.add(name)

    return sorted(names)


def _generate_azure_names(org, parts):
    """Generate Azure storage account name candidates."""
    names = set()
    for base in [org] + parts[:2]:
        for suffix in ["", "dev", "prod", "staging", "backup", "data", "storage"]:
            name = (base + suffix).lower()
            name = re.sub(r'[^a-z0-9]', '', name)[:24]
            if 3 <= len(name) <= 24:
                names.add(name)
    return sorted(names)


def _manual_s3_check(bucket_names, output_file):
    """Manually check S3 buckets via curl."""
    found = []
    for name in bucket_names:
        url = f"https://{name}.s3.amazonaws.com"
        try:
            result = subprocess.run(
                ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", url],
                capture_output=True, text=True, timeout=10
            )
            code = result.stdout.strip()
            if code == "200":
                found.append(f"[OPEN] {url}")
                print_find(f"S3 OPEN: {url}")
            elif code == "403":
                found.append(f"[EXISTS-PRIVATE] {url}")
            elif code == "301":
                found.append(f"[REDIRECT] {url}")
        except subprocess.TimeoutExpired:
            print(f"[-] SKIP: Manual S3 query timed out on {url}")
            continue
        except Exception:
            continue

    with open(output_file, "w") as f:
        f.write("\n".join(found))


def _generate_cloud_ssrf_hints(target, ws):
    """Generate SSRF → cloud metadata hints."""
    hints_file = ws.path("cloud", "ssrf_cloud_hints.md")
    with open(hints_file, "w") as f:
        f.write(f"# Cloud SSRF Hunting Hints — {target}\n\n")
        f.write("## AWS EC2 Metadata\n")
        f.write("  SSRF → http://169.254.169.254/latest/meta-data/\n")
        f.write("  SSRF → http://169.254.169.254/latest/meta-data/iam/security-credentials/\n")
        f.write("  IMDSv2: First get token, then use it in header\n\n")
        f.write("## GCP Metadata\n")
        f.write("  SSRF → http://metadata.google.internal/computeMetadata/v1/\n")
        f.write("  Header required: Metadata-Flavor: Google\n\n")
        f.write("## Azure IMDS\n")
        f.write("  SSRF → http://169.254.169.254/metadata/instance?api-version=2021-02-01\n")
        f.write("  Header required: Metadata: true\n\n")
        f.write("## DigitalOcean\n")
        f.write("  SSRF → http://169.254.169.254/metadata/v1.json\n\n")
        f.write("## Common SSRF Entry Points\n")
        f.write("  - URL params: ?url=, ?redirect=, ?src=, ?img=, ?file=, ?path=\n")
        f.write("  - Webhooks: POST body with URL\n")
        f.write("  - PDF/image generators\n")
        f.write("  - Import/export features\n")
    print_success("SSRF cloud metadata hints → cloud/ssrf_cloud_hints.md")
