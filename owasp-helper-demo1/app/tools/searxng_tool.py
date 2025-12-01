from __future__ import annotations
import httpx
from smolagents import tool
from app.config import get_settings

@tool
def searxng_search(query: str, engines: str | None = None, categories: str | None = None, language: str = "en") -> str:
    """Search the web using a configured SearXNG meta-search instance.

    Args:
        query: search query
        engines: optional comma separated engines list
        categories: optional categories
        language: search language (default en)
    Returns: Plain text aggregated snippet of results (title - url: snippet)
    """
    settings = get_settings()
    base = settings.searxng_base_url
    if not base:
        return "SearXNG base URL not configured. Set SEARXNG_BASE_URL env var."
    params = {"q": query, "format": "json"}
    if engines:
        params["engines"] = engines
    if categories:
        params["categories"] = categories
    if language:
        params["language"] = language
    try:
        headers = {"User-Agent": "pentest-systems-assistant/0.1", **(settings.searxng_headers or {})}
        with httpx.Client(timeout=20.0, headers=headers) as client:
            r = client.get(f"{base.rstrip('/')}/search", params=params)
            r.raise_for_status()
            data = r.json()
            parts: list[str] = []
            for res in data.get("results", [])[:10]:
                parts.append(f"{res.get('title','')} - {res.get('url','')}: {res.get('content','')}")
            if not parts:
                return "No results found"
            return "\n".join(parts)
    except Exception as e:  # pragma: no cover - network
        return f"SearXNG search error: {e}"
