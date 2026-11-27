# Installation guide

This guide expands the quick start in the repository README. Run commands from the `owasp-helper-demo1` directory unless noted.

## Local Python install

1. Install Python 3.10+ and Git. Python 3.11 or 3.12 is recommended.
2. Clone the repository and enter the app directory:

   ```bash
   git clone https://github.com/sm0k3net/smolagent-demo.git
   cd smolagent-demo/owasp-helper-demo1
   ```

3. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   . .venv/bin/activate
   ```

   On Windows PowerShell use `py -3 -m venv .venv` and `\.venv\Scripts\Activate.ps1`.

4. Install project and development requirements, then Chromium:

   ```bash
   python -m pip install --upgrade pip
   pip install -e ".[dev]"
   python -m playwright install chromium
   ```

   Linux may require native browser libraries; use Playwright's official `install-deps chromium` guidance for your distribution.

5. Copy `.env.example` to `.env`, set `LLM_PROVIDER` and the matching API key, and keep `.env` private. DeepSeek is the default; OpenRouter requires `LLM_PROVIDER=openrouter` and `OPENROUTER_API_KEY`.
6. Start with `uvicorn app.main:app --host 127.0.0.1 --port 8000`, then open <http://127.0.0.1:8000>.

## Docker install

Install Docker Engine/Desktop with the Compose plugin. From this directory, configure `.env`, run `docker compose build`, then `docker compose up -d`. Follow logs using `docker compose logs -f owasp-agent`. The host port is loopback-bound by default. To stop, run `docker compose down`; persistent volumes remain. Remove volumes only when intentionally deleting stored app data.

The full image includes more command-line tools and is much larger. The lite image is smaller but omits many scanners. External images, packages, and scanner templates are not all pinned immutably, so review the build configuration before production deployment.

## Scanner installation

Scanner command-line tools are optional. Install each from its official, trusted source and verify its executable is on PATH. The `scripts/setup_wsl.sh` helper is not an all-in-one installer; inspect it before use. Never install tools dynamically from untrusted agent output.

## Verify the installation

- Open the local UI and check `/health` in a browser; a healthy response should indicate the service is running.
- Configure a provider and submit a harmless informational prompt before using any scan tool.
- Run `pytest -q` from the app directory to run automated regression tests.
- Try browser automation or PDF export only after installing Playwright Chromium.

## Common issues

- **Missing API key:** configure the provider and key in `.env`; restart the process after edits.
- **Playwright cannot launch:** install Chromium and OS dependencies for the selected Linux distribution.
- **Scanner missing:** check PATH with `command -v scanner-name` or `Get-Command scanner-name`.
- **Port is busy:** choose another port and keep the host-side Compose bind on `127.0.0.1` unless remote exposure has been reviewed.
- **No access from another machine:** remote access is blocked unless `APP_USERNAME` and `APP_PASSWORD` are configured; use HTTPS.
