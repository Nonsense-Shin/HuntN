# 🛰️ HUNTn: The Hand of Light Uncovering Darkness

> **HUNTn** is a automated intelligence gathering, attack surface mapping and vulnerability scanning framework engineered specifically for **Ethical Hackers**. 

<img width="1000" height="1000" alt="Screenshot 2026-06-20 154735" src="https://github.com/user-attachments/assets/212aecd9-11b5-45c2-ab06-1699621b1ca8" />


>  **Design Philosophy:** `HUNTn` intentionally avoids reckless exploit automation—allowing the tool to map vectors silently, scanning and findings vulnerabilities for manual human intelligence. *It's a tool that uses tools*

---

## 🛠️ Installation & Architecture Deployment

Execute the following deployment sequences in your terminal to initialize the core environment, build dependency structures, and download necessary target intelligence vectors.

### 1. Environment & Vector Setup

*Initialize and activate isolated virtual environment*

```bash
python3 -m venv venv
source venv/bin/activate

# Install essential execution libraries
pip install pyyaml requests
```

### 2. Binary & Go Dependencies

*Verify Go compilation engine availability*

```
go version  # If missing, retrieve from: https://go.dev/dl/
```

*Map compiled Go binaries to active terminal pathing*

```
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc && source ~/.bashrc
```

### 3. Engine Initialization

*Execute internal component installation pipeline*

```
python3 huntn.py --setup
```

### 4. Pattern Profiles & Wordlists Configuration

*Install grep-find patterns for injection vector profiling (XSS/SQLi/SSRF)*

```
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp && cp /tmp/gfp/*.json ~/.gf/
```

*Deploy standard discovery wordlists to system shares*

```
sudo git clone https://github.com/danielmiessler/SecLists /usr/share/seclists
```

### 5. Integrity Validation
*Ensure all passive footprinting engines and active scanners are fully operational:*
```
python3 huntn.py --check-tools
```

### RUN
```
python3 huntn.py target.com --all
```
---

---
### 🤝 Contributions & Upgrades
This framework was fully vibe-coded to eliminate time waste during continuous recon rotations by myself [ **Nonsense Shin** ]. If you want to expand the hunting patterns, tune the regex structures, or integrate additional modules, feel free to modify it to your liking.
