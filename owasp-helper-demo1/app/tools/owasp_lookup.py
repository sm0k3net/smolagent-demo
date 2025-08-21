from __future__ import annotations
from smolagents import tool
from app.knowledge.owasp_top10_2021 import OWASP_TOP10_2021

_INDEX = {item["id"].lower(): item for item in OWASP_TOP10_2021}
for item in OWASP_TOP10_2021:
    _INDEX[item["name"].lower()] = item

@tool
def list_owasp_top10() -> str:
    """Return the OWASP Top 10 (2021) identifiers and names."""
    return "\n".join(f"{i['id']} - {i['name']}" for i in OWASP_TOP10_2021)

@tool
def get_owasp_item(identifier_or_name: str) -> str:
    """Get detailed description for an OWASP Top 10 2021 item.

    Args:
        identifier_or_name: Either the OWASP identifier (e.g. "A01:2021") or the category name
            (case-insensitive, e.g. "Broken Access Control").
    Returns:
        A string containing: `<id> - <name>: <description>` or a not-found message with guidance.
    """
    key = identifier_or_name.lower().strip()
    item = _INDEX.get(key)
    if not item:
        return "Not found. Use list_owasp_top10 to list valid identifiers." 
    return f"{item['id']} - {item['name']}: {item['description']}"
