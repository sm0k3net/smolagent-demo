# OWASP Helper

OWASP Helper is an experimental, self-hosted AI-assisted security-assessment workspace in the `owasp-helper-demo1/` directory. It uses FastAPI and `smolagents` to provide a browser interface for security guidance, task tracking, optional reconnaissance/scanner integrations, evidence handling, and HTML/Markdown/PDF report generation. OWASP Helper is not an official OWASP project, a certified penetration-testing product, or an authorization system.

> **Authorized use only.** Test only assets covered by written permission and an explicit scope. Active scanners can disrupt services or access sensitive systems. Review targets and proposed actions before running tools. This application does not enforce target scope for every tool; deployment and operator controls remain essential.

## Guides

- [Installation and configuration](owasp-helper-demo1/docs/INSTALL.md)
- [How to use OWASP Helper](owasp-helper-demo1/docs/USAGE.md)
- [Security, deployment, and operational precautions](owasp-helper-demo1/docs/SECURITY.md)
- [Application README and quick-start options](owasp-helper-demo1/README.md)
- [Agent capabilities and limitations](agent_description.md)

## Quick start

The supported local setup requires Python 3.10+, a provider API key, and Chromium for browser/PDF features. Optional scanners and integrations have separate prerequisites.

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

Edit `.env` with a supported model provider credential. For the default DeepSeek provider:

```dotenv
LLM_PROVIDER=deepseek
DEEPSEEK_API_KEY=your-provider-key
```

Then start the app from `owasp-helper-demo1/`:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. For Windows, Docker Compose, remote-access controls, environment variables, and troubleshooting, follow the [installation guide](owasp-helper-demo1/docs/INSTALL.md) and [security guide](owasp-helper-demo1/docs/SECURITY.md).

## What is included

- OWASP Top 10 (2021) lookup, vulnerability classification, and scoped test-scenario planning.
- Browser automation and captured-response analysis, including an offline HTTP security-header analyzer that makes no network requests.
- Optional active and passive tool integrations, depending on installed binaries, credentials, and environment configuration.
- Task, notes, evidence, scan-output, and report workflows; report formats include HTML, Markdown, and PDF.
- An agent-driven assessment workflow with finding validation and quality-review steps.

The availability and reliability of individual tools vary by deployment. A tool listed in the application is not proof that its binary, credentials, or external service is configured. Agent plans, phase flags, and generated findings do not establish that a test actually ran; verify evidence independently.

## Safety and deployment

Run the app on a dedicated, isolated host or container and keep it bound to loopback unless you have deliberately designed and reviewed remote access. The application can invoke tools capable of making network requests, and it does not automatically confine every tool to an approved target list. For non-loopback use, configure authentication, HTTPS, network restrictions, least privilege, and egress controls. Do not expose the service directly to the public internet without a separate security review. Treat prompts, reports, screenshots, scan output, and integration credentials as sensitive data.

Read the full [security and deployment guide](owasp-helper-demo1/docs/SECURITY.md) before using the application with real systems or sensitive information.

## Development

From `owasp-helper-demo1/`:

```bash
pip install -e ".[dev]"
pytest -q
```

The test suite covers selected regression and workflow behaviors; it is not comprehensive validation of every scanner or integration. See the application's [README](owasp-helper-demo1/README.md) for Docker, Windows, configuration, and troubleshooting details. Contributions and issue reports should avoid publishing secrets, sensitive target data, or unredacted scan evidence.

## Project status and license

OWASP Helper is an experimental operator-assist project. It can produce false positives, omit relevant issues, and generate unsafe or inaccurate suggestions if used without human review. It does not replace qualified security professionals, formal rules of engagement, or independent validation. See [`owasp-helper-demo1/LICENSE`](owasp-helper-demo1/LICENSE) for license terms.
