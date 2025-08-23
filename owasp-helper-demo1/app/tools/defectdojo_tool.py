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

# Simple in-memory context (per-process). For multi-user, consider per-session scoping.
_CURRENT_PRODUCT_ID: Optional[int] = None
_CURRENT_ENGAGEMENT_ID: Optional[int] = None


@tool
def defectdojo_get_current_context() -> str:
    """Get current DefectDojo context (product_id and engagement_id) stored in memory.

    Returns: "product_id=<id>; engagement_id=<id>" or "not set".
    """
    global _CURRENT_PRODUCT_ID, _CURRENT_ENGAGEMENT_ID
    if _CURRENT_PRODUCT_ID and _CURRENT_ENGAGEMENT_ID:
        return f"product_id={_CURRENT_PRODUCT_ID}; engagement_id={_CURRENT_ENGAGEMENT_ID}"
    if _CURRENT_PRODUCT_ID:
        return f"product_id={_CURRENT_PRODUCT_ID}; engagement_id=not set"
    return "not set"


@tool
def defectdojo_set_current_context(product_id: int | None = None, engagement_id: int | None = None) -> str:
    """Set current DefectDojo context in memory (product_id and/or engagement_id).

    Args:
        product_id: Optional product id to set.
        engagement_id: Optional engagement id to set.
    Returns: Current context string.
    """
    global _CURRENT_PRODUCT_ID, _CURRENT_ENGAGEMENT_ID
    if product_id is not None:
        _CURRENT_PRODUCT_ID = product_id
    if engagement_id is not None:
        _CURRENT_ENGAGEMENT_ID = engagement_id
    return defectdojo_get_current_context()


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
def defectdojo_ensure_product(name: str, description: str | None = None, product_type_id: int | None = None) -> str:
    """Ensure a DefectDojo product exists, creating it if missing.

    Args:
        name: Product name.
        description: Optional product description.
        product_type_id: Product type id (defaults to DEFECTDOJO_DEFAULT_PRODUCT_TYPE_ID or 1).
    Returns: "product_id=<id> (existing|created)" or an error message.
    """
    client, err = _dd_client()
    if err:
        return err
    try:
        assert client is not None
        # Try exact match (case-insensitive)
        r = client.get("/api/v2/products/", params={"name__iexact": name})
        r.raise_for_status()
        data = r.json()
        results = data.get("results", data)
        if results:
            pid = results[0].get("id")
            return f"product_id={pid} existing"
        # Create new
        from app.config import get_settings as _gs
        s = _gs()
        prod_type = product_type_id or getattr(s, "defectdojo_default_product_type_id", None) or 1
        payload = {"name": name, "description": description or "", "prod_type": prod_type}
        r2 = client.post("/api/v2/products/", json=payload)
        r2.raise_for_status()
        new_obj = r2.json()
        return f"product_id={new_obj.get('id')} created"
    except Exception as e:  # pragma: no cover - network
        return f"Error ensuring product: {e}"


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
def defectdojo_create_engagement(
    product_id: int,
    name: str,
    start_date: str,
    end_date: str,
    description: str | None = None,
    status: str = "In Progress",
    engagement_type: str = "Pen Test",
) -> str:
    """Create a new engagement under a product.

    Args:
        product_id: Product id owner of the engagement.
        name: Engagement name.
        start_date: Target start date (YYYY-MM-DD).
        end_date: Target end date (YYYY-MM-DD).
        description: Optional description.
        status: Status (default 'In Progress').
        engagement_type: Type label (default 'Pen Test').
    Returns: "engagement_id=<id> created" or an error.
    """
    client, err = _dd_client()
    if err:
        return err
    try:
        assert client is not None
        payload = {
            "product": product_id,
            "name": name,
            "target_start": start_date,
            "target_end": end_date,
            "status": status,
            "engagement_type": engagement_type,
            "description": description or "",
        }
        r = client.post("/api/v2/engagements/", json=payload)
        r.raise_for_status()
        obj = r.json()
        return f"engagement_id={obj.get('id')} created"
    except Exception as e:  # pragma: no cover - network
        return f"Error creating engagement: {e}"


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
def defectdojo_create_finding(
    engagement_id: int,
    title: str,
    description: str,
    severity: str = "Medium",
    owasp_top10: str | None = None,
    tool: str | None = None,
    repro_steps: str | None = None,
    poc: str | None = None,
    remediation: str | None = None,
) -> str:
    """Create a manual finding under an engagement with rich details.

    Args:
        engagement_id: Target engagement id.
        title: Finding title.
        description: Detailed description of the issue.
        severity: Severity (Info/Low/Medium/High/Critical).
        owasp_top10: Optional OWASP Top 10 classification (e.g., 'A01:2021 Broken Access Control').
        tool: Optional tool name used to identify it (e.g., 'curl', 'nmap', 'Playwright').
        repro_steps: How to reproduce the issue step-by-step.
        poc: Proof-of-concept details (payloads, commands, screenshots links).
        remediation: Remediation recommendation.
    Returns: "finding_id=<id> created" or an error message.
    """
    client, err = _dd_client()
    if err:
        return err
    try:
        assert client is not None
        refs: list[str] = []
        tags: list[str] = []
        if owasp_top10:
            refs.append(f"OWASP Top 10: {owasp_top10}")
            # Create a tag like OWASP-A01-2021 if possible
            parts = owasp_top10.split()[0] if owasp_top10 else ""
            if parts:
                tags.append(f"OWASP-{parts.replace(':','-')}")
        if tool:
            refs.append(f"Tool: {tool}")
        full_desc = description.strip()
        if poc:
            full_desc += f"\n\nProof of Concept:\n{poc.strip()}"
        payload = {
            "title": title,
            "severity": severity,
            "description": full_desc,
            "mitigation": remediation or "",
            "steps_to_reproduce": (repro_steps or "").strip(),
            "references": "\n".join(refs) if refs else "",
            "engagement": engagement_id,
            "verified": True,
            "active": True,
            "tags": tags,
        }
        r = client.post("/api/v2/findings/", json=payload)
        if r.status_code >= 400:
            # Provide helpful message if the instance requires a Test instead of direct engagement posting
            try:
                detail = r.json()
            except Exception:
                detail = r.text
            return f"Error creating finding (consider enabling direct finding creation or creating a Test first): {detail}"
        obj = r.json()
        return f"finding_id={obj.get('id')} created"
    except Exception as e:  # pragma: no cover - network
        return f"Error creating finding: {e}"


@tool
def defectdojo_ensure_product_and_create_engagement(
    product_name: str,
    engagement_name: str,
    start_date: str,
    end_date: str,
    product_description: str | None = None,
    product_type_id: int | None = None,
    engagement_description: str | None = None,
) -> str:
    """Ensure product exists and create a new engagement for the current pentest.

    Returns: "product_id=<id>; engagement_id=<id>"
    """
    prod_res = defectdojo_ensure_product(product_name, product_description, product_type_id)
    if not prod_res.startswith("product_id="):
        return prod_res
    try:
        product_id = int(prod_res.split("=")[1].split()[0])
    except Exception:
        return f"Unexpected response: {prod_res}"
    eng_res = defectdojo_create_engagement(product_id, engagement_name, start_date, end_date, engagement_description)
    if not eng_res.startswith("engagement_id="):
        return eng_res
    engagement_id = int(eng_res.split("=")[1].split()[0])
    # Set current context for subsequent finding creation
    defectdojo_set_current_context(product_id=product_id, engagement_id=engagement_id)
    return f"product_id={product_id}; engagement_id={engagement_id}"


@tool
def defectdojo_record_finding(
    title: str,
    description: str,
    severity: str = "Medium",
    owasp_top10: str | None = None,
    tool: str | None = None,
    repro_steps: str | None = None,
    poc: str | None = None,
    remediation: str | None = None,
) -> str:
    """Create a finding using the current engagement context.

    Requires current engagement to be set via ensure+create or set_current_context.
    """
    global _CURRENT_ENGAGEMENT_ID
    if not _CURRENT_ENGAGEMENT_ID:
        return "Current engagement is not set. Use defectdojo_ensure_product_and_create_engagement or defectdojo_set_current_context first."
    return defectdojo_create_finding(
        engagement_id=_CURRENT_ENGAGEMENT_ID,
        title=title,
        description=description,
        severity=severity,
        owasp_top10=owasp_top10,
        tool=tool,
        repro_steps=repro_steps,
        poc=poc,
        remediation=remediation,
    )


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
