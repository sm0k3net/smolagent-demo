# Pentest.Systems Assistant - Professional Penetration Testing

An AI-powered penetration testing assistant built with smolagents. Features a professional web UI with real-time activity monitoring, OSINT tools, security scanners, and automated report generation.

## 🎯 Key Features

### Professional Web UI
- **Real-time Activity Sidebar**: Expandable sidebar showing agent's current activity, steps, and tool usage
- **Report Mode Toggle**: Enable to collect findings for professional HTML/PDF reports
- **Chat Export**: Download chat history as TXT
- **HTML Report Preview**: View generated reports in new browser tab

### OSINT & Passive Reconnaissance
- **VirusTotal**: Domain/IP reputation and analysis
- **Shodan**: Host information, open ports, services, vulnerabilities
- **Hunter.io**: Email pattern and contact discovery
- **SecurityTrails**: DNS history and infrastructure data
- **crt.sh**: Subdomain discovery via certificate transparency
- **WHOIS**: Domain registration information
- **Have I Been Pwned**: Breach monitoring

### Active Scanning Tools (CLI wrappers)
- **dnsrecon**: DNS enumeration and zone transfers
- **dirb/gobuster**: Directory and file enumeration
- **nikto**: Web vulnerability scanning
- **OWASP ZAP**: Baseline security scanning
- **nuclei**: Template-based vulnerability detection
- **whatweb**: Technology fingerprinting
- **sslyze/testssl**: SSL/TLS configuration analysis
- **wpscan**: WordPress vulnerability scanning
- **subfinder/httpx**: Subdomain discovery and probing

### Browser Automation (Playwright)
- Human-like browsing behavior
- Form interaction and submission
- Screenshot capture
- Network request interception
- Console error detection
- Link and form extraction

### Professional Reporting
- Enable Report Mode to collect findings automatically
- Generate professional HTML reports with:
  - Executive summary
  - Scope and methodology
  - Detailed findings with severity ratings
  - OWASP Top 10 classification
  - Remediation recommendations
- PDF export via Playwright

### Integrations
- **DefectDojo**: Track findings in enterprise vulnerability management
- **DeepSeek LLM**: Powered by DeepSeek via OpenAI-compatible API
- **SearXNG**: Privacy-respecting web search

## 🚀 Quick Start

```powershell
# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -e .

# Install Playwright browsers
python -m playwright install chromium

# Configure environment
$env:DEEPSEEK_API_KEY = "sk-..."
$env:DEEPSEEK_API_BASE = "https://api.deepseek.com/v1"

# Optional API keys for OSINT tools
$env:VIRUSTOTAL_API_KEY = "..."
$env:SHODAN_API_KEY = "..."
$env:HUNTER_API_KEY = "..."
$env:SECURITYTRAILS_API_KEY = "..."

# Optional: SearXNG instance
$env:SEARXNG_BASE_URL = "https://searxng.example.org"

# Optional: DefectDojo integration
$env:DEFECTDOJO_BASE_URL = "https://dojo.example.com"
$env:DEFECTDOJO_API_KEY = "token-from-dojo"

# Run the server
uvicorn app.main:app --reload
```

Navigate to http://127.0.0.1:8000

## 📦 Installing Pentest Tools (Linux/WSL)

```bash
# Basic tools
sudo apt-get update && sudo apt-get install -y \
    nmap dnsrecon dirb nikto whatweb gobuster

# OWASP ZAP
sudo snap install zaproxy --classic

# Go-based tools (requires Go 1.21+)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# WPScan (requires Ruby)
gem install wpscan

# testssl.sh
git clone https://github.com/drwetter/testssl.sh.git

# SSLyze
pip install sslyze
```

## 📋 Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DEEPSEEK_API_KEY` | Yes | DeepSeek API key |
| `DEEPSEEK_API_BASE` | Yes | API base URL (default: https://api.deepseek.com/v1) |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal API key for domain/IP analysis |
| `SHODAN_API_KEY` | No | Shodan API key for host reconnaissance |
| `HUNTER_API_KEY` | No | Hunter.io API key for email discovery |
| `SECURITYTRAILS_API_KEY` | No | SecurityTrails API key |
| `WHOISXML_API_KEY` | No | WhoisXML API key for WHOIS lookups |
| `HIBP_API_KEY` | No | Have I Been Pwned API key (paid) |
| `WPSCAN_API_TOKEN` | No | WPScan API token for vulnerability data |
| `SEARXNG_BASE_URL` | No | Self-hosted SearXNG instance URL |
| `DEFECTDOJO_BASE_URL` | No | DefectDojo server URL |
| `DEFECTDOJO_API_KEY` | No | DefectDojo API token |

## 🔧 Troubleshooting

### DeepSeek API
Ensure `DEEPSEEK_API_KEY` and `DEEPSEEK_API_BASE` are set correctly.

### Playwright
```bash
python -m playwright install chromium --with-deps
```

### WSL Playwright
May need additional packages:
```bash
sudo apt-get install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libgbm1 libasound2
```

### nmap
```bash
sudo apt-get install -y nmap
```

## ⚠️ Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before testing. Not an official OWASP project. Validate results manually.

## 📝 License

MIT
