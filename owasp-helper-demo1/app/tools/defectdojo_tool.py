from __future__ import annotations
import os
from typing import Any, Optional
import httpx
from smolagents import tool
from app.config import get_settings


def _dd_get_base_and_headers() -> tuple[Optional[str], dict[str, str], bool]:
    """Resolve DefectDojo base URL, auth header, and SSL verify flag from settings/env."""
    settings = get_settings()
    base = getattr(settings, "defectdojo_base_url", None) or os.getenv("DEFECTDOJO_BASE_URL")
    api_key = getattr(settings, "defectdojo_api_key", None) or os.getenv("DEFECTDOJO_API_KEY")
    verify_ssl = True
    raw_verify = (getattr(settings, "defectdojo_verify_ssl", None) or os.getenv("DEFECTDOJO_VERIFY_SSL") or "true")
    if isinstance(raw_verify, str):
        verify_ssl = raw_verify.strip().lower() not in ("false", "0", "no")
    elif isinstance(raw_verify, bool):
        verify_ssl = raw_verify
    headers: dict[str, str] = {"Authorization": f"Token {api_key}"} if api_key else {}
    return base, headers, verify_ssl


def _dd_client() -> tuple[Optional[httpx.Client], Optional[str]]:
    base, headers, verify = _dd_get_base_and_headers()
    if not base:
        return None, "DefectDojo base URL not configured. Set DEFECTDOJO_BASE_URL."
    if not headers.get("Authorization"):
        return None, "DefectDojo API key not configured. Set DEFECTDOJO_API_KEY."
    client = httpx.Client(base_url=base.rstrip("/"), headers=headers, timeout=30.0, verify=verify)
    return client, None


@tool
def defectdojo_health() -> str:
    """Check connectivity to DefectDojo API v2 by querying system settings.

    Returns: A short status string with the version or an error message.
    """
    client, err = _dd_client()
    if err:
        return err
    try:
        assert client is not None
        r = client.get("/api/v2/system_settings/")
        r.raise_for_status()
        data = r.json()
        ver = data.get("version") or data.get("build_id") or "unknown"
        return f"DefectDojo reachable (version: {ver})"
    except Exception as e:  # pragma: no cover - network
        return f"DefectDojo health check failed: {e}"


@tool
def defectdojo_list_products(name_contains: str | None = None, max_items: int = 20) -> str:
    """List products from DefectDojo.

    Args:
        name_contains: Optional substring to filter product names.
        max_items: Maximum number of products to include in the output (default 20).
    Returns: Bullet list of product id, name, and description snippet.
    """
    client, err = _dd_client()
    if err:
        return err
    try:
        assert client is not None
        params: dict[str, Any] = {}
        if name_contains:
            params["name__icontains"] = name_contains
        r = client.get("/api/v2/products/", params=params)
        r.raise_for_status()
        data = r.json()
        results = data.get("results", data)
        lines: list[str] = []
        for p in results[:max_items]:
            desc = (p.get("description") or "").strip().replace("\n", " ")
            if len(desc) > 80:
                desc = desc[:77] + "..."
            lines.append(f"- #{p.get('id')} {p.get('name')} — {desc}")
        return "\n".join(lines) if lines else "No products found"
    except Exception as e:  # pragma: no cover - network
        return f"Error listing products: {e}"


@tool
def defectdojo_list_engagements(product_id: int, name_contains: str | None = None, max_items: int = 50) -> str:
    """List engagements for a given product.

    Args:
        product_id: ID of the product to filter by.
        name_contains: Optional substring to filter engagement names.
        max_items: Maximum number of engagements to include (default 50).
    Returns: Bullet list of engagement id, name, status, and dates.
    """
    client, err = _dd_client()
    if err:
        return err
    try:
        assert client is not None
        params: dict[str, Any] = {"product": product_id}
        if name_contains:
            params["name__icontains"] = name_contains
        r = client.get("/api/v2/engagements/", params=params)
        r.raise_for_status()
        data = r.json()
        results = data.get("results", data)
        lines: list[str] = []
        for e in results[:max_items]:
            lines.append(
                f"- #{e.get('id')} {e.get('name')} — status={e.get('status')} start={e.get('target_start')} end={e.get('target_end')}"
            )
        return "\n".join(lines) if lines else "No engagements found"
    except Exception as e:  # pragma: no cover - network
        return f"Error listing engagements: {e}"


@tool
def defectdojo_import_scan(
    engagement_id: int,
    scan_type: str,
    file_path: str,
    active: bool = True,
    verified: bool = True,
    minimum_severity: str = "Info",
    close_old_findings: bool = False,
    skip_duplicates: bool = True,
    tags: str | None = None,
) -> str:
    """Import a scan file into DefectDojo for the specified engagement.

    Args:
        engagement_id: The engagement ID where the scan will be imported.
        scan_type: The scan type label as recognized by DefectDojo (e.g., 'ZAP Scan', 'Generic Findings Importer').
        file_path: Path to the scan report file on the server filesystem.
        active: Mark findings as active (default True).
        verified: Mark findings as verified (default True).
        minimum_severity: Minimum severity to import (default 'Info').
        close_old_findings: Whether to close old findings (default False).
        skip_duplicates: Skip duplicate findings (default True).
        tags: Optional comma-separated tags to add to import.
    Returns: A short status string with created/updated counts or error.
    """
    client, err = _dd_client()
    if err:
        return err
    try:
        assert client is not None
        if not os.path.isfile(file_path):
            return f"Scan file not found: {file_path}"
        data = {
            "engagement": str(engagement_id),
            "scan_type": scan_type,
            "active": str(active).lower(),
            "verified": str(verified).lower(),
            "minimum_severity": minimum_severity,
            "close_old_findings": str(close_old_findings).lower(),
            "skip_duplicates": str(skip_duplicates).lower(),
        }
        if tags:
            data["tags"] = tags
        # Note: do not send json header for multipart
        with open(file_path, "rb") as fh:
            files = {"file": (os.path.basename(file_path), fh)}
            r = client.post("/api/v2/import-scan/", files=files, data=data)
        r.raise_for_status()
        try:
            payload = r.json()
            created = payload.get("success") or payload.get("imported_findings", "ok")
            return f"Import successful: {created}"
        except Exception:
            return f"Import successful: HTTP {r.status_code}"
    except Exception as e:  # pragma: no cover - network
        return f"Error importing scan: {e}"


@tool
def defectdojo_list_findings(
    product_id: int | None = None,
    engagement_id: int | None = None,
    active_only: bool = True,
    severity: str | None = None,
    max_items: int = 50,
) -> str:
    """List findings filtered by product or engagement.

    Args:
        product_id: Optional product id to filter on.
        engagement_id: Optional engagement id to filter on.
        active_only: Only include active findings (default True).
        severity: Optional severity filter (Info/Low/Medium/High/Critical).
        max_items: Maximum findings to include (default 50).
    Returns: Bullet list of finding id, title, severity, CWE.
    """
    client, err = _dd_client()
    if err:
        return err
    try:
        assert client is not None
        params: dict[str, Any] = {}
        if product_id is not None:
            params["product"] = product_id
        if engagement_id is not None:
            params["engagement"] = engagement_id
        if active_only:
            params["active"] = True
        if severity:
            params["severity"] = severity
        r = client.get("/api/v2/findings/", params=params)
        r.raise_for_status()
        data = r.json()
        results = data.get("results", data)
        lines: list[str] = []
        for f in results[:max_items]:
            lines.append(
                f"- #{f.get('id')} [{f.get('severity')}] {f.get('title')} — CWE-{f.get('cwe') or 'N/A'}"
            )
        return "\n".join(lines) if lines else "No findings found"
    except Exception as e:  # pragma: no cover - network
        return f"Error listing findings: {e}"
