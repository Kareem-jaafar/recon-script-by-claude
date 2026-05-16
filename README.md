# recon-script-by-claude

Professional Automated Reconnaissance Pipeline for Bug Bounty, External Recon, and Surface Discovery.

---

# Features

- Subdomain Enumeration
- DNS Resolution
- Live Host Detection
- Historical URL Collection
- JavaScript Analysis
- Parameter Discovery
- XSS Detection
- Content Discovery & Fuzzing
- Vulnerability Scanning
- Subdomain Takeover Detection
- Port Scanning
- Sensitive File Discovery

---

# Project Structure

```bash
recon/
│
├── subs/
├── live/
├── crawl/
├── params/
├── js/
├── scan/
├── ports/
├── fuzz/
└── takeover/
```

---

# Required Tools

Make sure the following tools are installed before running the script:

| Tool | Purpose |
|------|----------|
| subfinder | Subdomain enumeration |
| amass | Passive enumeration |
| dnsx | DNS resolution |
| httpx | Live host probing |
| gau | Historical URLs |
| katana | Web crawling |
| nuclei | Vulnerability scanning |
| ffuf | Content discovery |
| naabu | Port scanning |
| nmap | Service detection |
| dalfox | XSS scanning |
| gf | Pattern filtering |
| uro | URL deduplication |
| unfurl | URL parsing |
| jq | JSON parsing |

---

# Verify Installed Tools

Run the following command to check missing dependencies:

```bash
for tool in subfinder amass dnsx httpx gau katana nuclei ffuf naabu nmap dalfox gf uro unfurl jq; do
    which $tool >/dev/null || echo "$tool NOT INSTALLED"
done
```

---

# Installation

## Clone Repository

```bash
git clone https://github.com/kareem-jaafar/REPOSITORY.git
cd REPOSITORY
```

---

# Make Script Executable

```bash
chmod +x recon.sh
```

---

# Usage

## Basic Usage

```bash
./recon.sh example.com
```

---

# Run in Background (Recommended)

## Using tmux

```bash
tmux new -s recon
./recon.sh example.com
```

Detach session:

```bash
CTRL+B then D
```

Resume session:

```bash
tmux attach -t recon
```

---

# Output Files

| File | Description |
|------|-------------|
| subs/resolved.txt | Valid subdomains |
| live/live_urls.txt | Live web services |
| crawl/all_urls.txt | Collected URLs |
| js/js_secrets.txt | Potential JS secrets |
| scan/xss.txt | XSS results |
| scan/nuclei.txt | Vulnerability results |
| takeover/takeovers.txt | Takeover findings |
| ports/nmap.txt | Open ports & services |
| scan/sensitive_files.txt | Sensitive files |

---

# Telegram Notifications (Optional)

Install notify:

```bash
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
```

Configure:

```bash
~/.config/notify/provider-config.yaml
```

Example:

```yaml
telegram:
  - id: "recon"
    telegram_api_key: "BOT_TOKEN"
    telegram_chat_id: "CHAT_ID"
```

Usage:

```bash
cat scan/nuclei.txt | notify -provider telegram
```

---



Your Name

---
