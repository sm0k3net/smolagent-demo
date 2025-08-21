# OWASP SmolAgent Helper

Early prototype of an OWASP helper agent powered by [smolagents]. Features:

- Chat UI (FastAPI + WebSocket) with a CodeAgent backend
- DeepSeek chat model wrapper (configure `DEEPSEEK_API_KEY` env var)
- SearXNG search tool integration (configure `SEARXNG_BASE_URL`)
- OWASP Top 10 2021 knowledge + lookup tools
- Structured system prompt to generate classifications & testing scenarios referencing OWASP WSTG / MSTG / API / ASVS concepts.

## Quick start

```powershell
# (optional) python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -e .[dev]
$env:DEEPSEEK_API_KEY = "sk-..."  # set your key
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

## Disclaimer
Not an official OWASP project. Validate results manually.
