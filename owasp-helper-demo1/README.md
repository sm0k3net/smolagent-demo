# OWASP SmolAgent Helper

Early prototype of an OWASP helper agent powered by smolagents. Features:

- Chat UI (FastAPI + WebSocket) with a CodeAgent backend
- DeepSeek via OpenAI-compatible client (set `DEEPSEEK_API_KEY` and `DEEPSEEK_API_BASE`)
- SearXNG search tool integration (configure `SEARXNG_BASE_URL`)
- OWASP Top 10 2021 knowledge + lookup tools
- Structured instructions for classification & testing scenarios referencing OWASP WSTG / MSTG / API / ASVS
- Optional tools: Playwright page fetch and Nmap port scanning

## Quick start

```powershell
# (optional) python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -e .[dev]
# Optional: browser tooling
pip install -e .[browser]
# After installing playwright, install browsers once:
python -m playwright install --with-deps
$env:DEEPSEEK_API_KEY = "sk-..."
$env:DEEPSEEK_API_BASE = "https://api.deepseek.com/v1"
$env:SEARXNG_BASE_URL = "https://searxng.example.org"
uvicorn app.main:app --reload
```
Navigate to http://127.0.0.1:8000

## Roadmap
- Add vulnerability classification function (accept description, output best OWASP category + rationale + confidence)
- Add scenario generation tool referencing specific WSTG sections
- Add retrieval augmented generation (RAG) over local curated OWASP docs snippets
- Caching layer for search & model calls
- Multi-modal (code scanning) tool hooks
- Rich Playwright workflows (auth flows, screenshots) and safer nmap wrappers

## Troubleshooting
- DeepSeek: ensure `DEEPSEEK_API_KEY` and `DEEPSEEK_API_BASE` are set. We use an OpenAI-compatible client.
- SearXNG 429: set your own instance in `SEARXNG_BASE_URL`; the tool sets a UA and trims slashes.
- Playwright: run `python -m playwright install --with-deps` inside venv; WSL may need extra packages.
- nmap: install in WSL with `sudo apt-get update && sudo apt-get install -y nmap`.

## Disclaimer
Not an official OWASP project. Validate results manually.
