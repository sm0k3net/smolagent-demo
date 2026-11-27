# OWASP Helper

OWASP Helper is a self-hosted AI-assisted security assessment workspace built with FastAPI and `smolagents`. It combines a browser UI, chat/task tracking, optional reconnaissance and scanning tools, report generation, and external integrations. It is an operator-controlled assistant, not an authorization system and not an official OWASP project.

> **Authorized use only.** Test only systems for which you have written authorization and a defined scope. Active scans can disrupt services, trigger alerts, or access sensitive data. Review proposed actions and validate generated findings manually. This application can run external scanner programs; isolate it from sensitive networks and do not expose it publicly without a separately reviewed deployment.

## Guides

- [Installation](docs/INSTALL.md)
- [Usage](docs/USAGE.md)
- [Security and deployment](docs/SECURITY.md)

## Requirements

- Python 3.10 or newer (Python 3.11/3.12 recommended), or Docker with Compose.
- An LLM API key: DeepSeek (default) or OpenRouter.
- Chromium for browser automation and PDF report generation. Scanner binaries are optional and must be installed separately unless using the full Docker image.
- Optional integrations (VirusTotal, Shodan, Hunter, SecurityTrails, HIBP, DefectDojo, Telegram, Slack, SearXNG, and PenDoc) require separate keys or services.

## Quick start: Linux and macOS

```bash
git clone https://github.com/sm0k3net/smolagent-demo.git
cd smolagent-demo/owasp-helper-demo1
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
python -m playwright install chromium
cp .env.example .env
```

Edit `.env` and configure one provider:

```dotenv
LLM_PROVIDER=deepseek
DEEPSEEK_API_KEY=your-provider-key
# Optional; defaults to https://api.deepseek.com/v1
DEEPSEEK_API_BASE=https://api.deepseek.com/v1
```

For OpenRouter instead:

```dotenv
LLM_PROVIDER=openrouter
OPENROUTER_API_KEY=your-openrouter-key
```

Start from the `owasp-helper-demo1` directory:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. Stop the server with `Ctrl+C`.

## Windows PowerShell

```powershell
git clone https://github.com/sm0k3net/smolagent-demo.git
Set-Location smolagent-demo\owasp-helper-demo1
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
python -m playwright install chromium
Copy-Item .env.example .env
notepad .env
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
If PowerShell prevents activation, follow your organization's policy or use `.venv\Scripts\python.exe -m pip ...` and `.venv\Scripts\uvicorn.exe ...` directly.

## Docker Compose

From `owasp-helper-demo1`:

```bash
cp .env.example .env
# Edit .env: configure a provider key and APP_USERNAME/APP_PASSWORD.
# Compose requires credentials because the container sees a non-loopback peer.
docker compose build
docker compose up -d
docker compose logs -f owasp-agent
```

Open <http://127.0.0.1:8000> and authenticate with the configured `APP_USERNAME` and `APP_PASSWORD`. The app listens on the container network so the published port works; Compose binds application and optional SearXNG host ports to loopback by default. Stop with `docker compose down`; named volumes remain. `docker compose down --volumes` deletes persisted container data and should only be used intentionally.

`Dockerfile` builds the larger image with scanner tooling; `Dockerfile.lite` is a smaller alternative. Image bases, Go tools, and templates are not currently locked to immutable versions. Review them before production use. Do not mount the Docker socket into the app container.

## Access control and safe deployment

The app does not implement accounts or role-based authorization. Its API can manage provider keys, integrations, task history, reports, and scanner operations. The standalone server command binds to loopback; inside Docker, the app listens on container interfaces while Compose publishes host ports on loopback by default. When `APP_USERNAME` and `APP_PASSWORD` are both set, HTTP Basic authentication is required for non-health HTTP routes and WebSocket clients. Without credentials, only loopback clients are permitted. `/health` and `/api/health` are intentionally unauthenticated liveness probes.

Before remote exposure:

1. Set a unique `APP_USERNAME` and long random `APP_PASSWORD` in a private environment file or secret manager; never commit `.env`.
2. Use HTTPS at a trusted reverse proxy, restrict inbound networks, and do not trust arbitrary proxy-forwarded client addresses. Basic credentials are only safe over TLS.
3. Do not expose this service to the internet without a full security review. Basic authentication is a deployment gate, not multi-user authorization.
4. Use an isolated host/container, least-privilege credentials, network egress controls, resource limits, backups, and retention rules. Treat prompts, reports, screenshots, uploads, and scan outputs as sensitive.
5. Configure only authorized test targets. Scanner binaries can reach internal services; use firewall/egress controls. Keep TLS verification enabled for integrations.

Changing Docker's loopback host-port mapping is an explicit operator decision requiring the controls above. The service does not provide per-user permissions or target-scope enforcement for every tool.

## Configuration reference

| Variable | Purpose |
| --- | --- |
| `LLM_PROVIDER` | `deepseek` (default) or `openrouter` |
| `DEEPSEEK_API_KEY` | DeepSeek API credential |
| `DEEPSEEK_API_BASE` | Optional DeepSeek-compatible API base URL |
| `OPENROUTER_API_KEY` | OpenRouter credential when that provider is selected |
| `SEARXNG_BASE_URL` | Optional SearXNG service URL |
| `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`, `HUNTER_API_KEY`, `SECURITYTRAILS_API_KEY`, `WHOISXML_API_KEY`, `HIBP_API_KEY`, `WPSCAN_API_TOKEN` | Optional provider credentials |
| `DEFECTDOJO_BASE_URL`, `DEFECTDOJO_API_KEY`, `DEFECTDOJO_VERIFY_SSL` | DefectDojo connection settings; keep verification enabled |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Optional Telegram integration |
| `SLACK_WEBHOOK_URL`, `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`, `SLACK_CHANNEL` | Optional Slack integration |
| `PENDOC_API_TOKEN`, `PENDOC_BASE_URL` | Optional PenDoc integration; app settings may also be used |
| `APP_USERNAME`, `APP_PASSWORD` | Set together for non-loopback access |
| `HOST`, `PORT` | Bind address and port; defaults are loopback and `8000` |
| `PROMPT_PATH` | Optional custom agent prompt path |
| `AGENT_MAX_STEPS` | Optional maximum agent step count |

`.env.example` contains placeholders, not credentials. Never paste secrets into issue reports or commit them. Revoke and rotate any exposed key with its provider.

## Optional scanner tools

Local scanner availability depends on OS, PATH, permissions, and tool setup. Examples include `nmap`, `nikto`, `dirb`, `gobuster`, `nuclei`, `subfinder`, `httpx`, `ffuf`, `sqlmap`, `whatweb`, `testssl.sh`, and OWASP ZAP. Install each from its official source and comply with its license and usage requirements. A tool appearing in the UI does not mean its executable or credentials are present. Begin with one scanner and review its target and impact.

For WSL, `scripts/setup_wsl.sh` assists with Python environment setup; review it before execution. It does not install every scanner or configure every external service. Install Chromium with `python -m playwright install chromium` after Python dependencies.

## How to use

1. Configure a provider key and restart the server after changing environment variables.
2. Describe the task and authorized scope in the UI. Avoid sending secrets or unnecessary personal data.
3. Review task progress and proposed scanner actions. Treat agent output as suggestions; verify targets and commands before execution.
4. Add evidence and findings to a report, check scope and severity, then export it. Independently validate findings before sharing.
5. Configure optional integrations only when needed; verify destination URLs and TLS settings before sending data.

Application data is written beneath the runtime working directory, including task state and potentially sensitive output. Restrict filesystem access, back up only necessary data, and apply a retention policy.

## Development and tests

```bash
pip install -e ".[dev]"
pytest -q
```
Tests focus on security helper regressions and do not prove every integration or external scanner works. Use a disposable environment for manual smoke tests. Broader integration coverage and release automation are evolving.

## Troubleshooting

- **Provider errors:** check `LLM_PROVIDER`, the matching API key, provider account status, and API base URL. Do not include keys in logs or issue text.
- **Browser/PDF errors:** run `python -m playwright install chromium`. On Linux, follow Playwright's official system dependency guidance if shared libraries are missing.
- **Scanner unavailable:** check `command -v <tool>` (PowerShell: `Get-Command <tool>`), PATH, credentials, and permissions.
- **Port conflict:** choose another `PORT` and update Compose mapping; leave host-side binding on `127.0.0.1` unless deliberately deploying remotely.
- **Authentication challenge:** set both `APP_USERNAME` and `APP_PASSWORD` for remote use and connect over HTTPS with a client/browser supporting HTTP Basic authentication.
- **Container cannot reach a service:** check DNS, proxy, and egress configuration; do not disable TLS verification as a workaround.

## Project status and license

This is an experimental self-hosted security-assessment assistant. Scanner coverage, provider APIs, model availability, and report quality vary by environment. It is not a certified penetration-testing product or a substitute for qualified security review. See [LICENSE](LICENSE) for terms.
