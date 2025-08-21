from __future__ import annotations
from smolagents import tool

@tool
def fetch_page_title(url: str) -> str:
    """Fetch a page title using Playwright (headless).

    Args:
        url: The URL to open.
    Returns:
        Extracted <title> text or an error message.
    """
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception as e:  # pragma: no cover
        return f"Playwright not available: {e}"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            title = page.title()
            browser.close()
            return title
    except Exception as e:  # pragma: no cover
        return f"Playwright error: {e}"
