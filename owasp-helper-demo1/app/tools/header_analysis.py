from __future__ import annotations

import json
from html import escape
from urllib.parse import urlsplit

from smolagents import tool


@tool
def analyze_http_security_headers(url: str, response_headers_json: str) -> str:
    """Analyze captured HTTP response headers for common defensive configuration gaps.

    This tool is offline: it never connects to the supplied URL. Pass the URL and a
    JSON object containing headers from an already-authorized request (for example,
    {"Content-Security-Policy": "default-src 'self'"}). Findings are observations,
    not proof of exploitability or a compliance determination.
    Args:
        url: URL associated with the captured response.
        response_headers_json: JSON object mapping HTTP header names to values.
    Returns:
        A concise checklist of observations and recommendations.
    """
    if len(response_headers_json) > 32_768:
        return "Invalid input: response headers must be 32 KB or smaller."
    try:
        parsed_url = urlsplit(url)
        if parsed_url.scheme.lower() not in {"http", "https"} or not parsed_url.hostname:
            return "Invalid input: provide an absolute http:// or https:// URL."
        if parsed_url.username is not None or parsed_url.password is not None:
            return "Invalid input: do not include credentials in the URL."
        port = parsed_url.port
        raw_headers = json.loads(response_headers_json)
    except (ValueError, json.JSONDecodeError):
        return "Invalid input: URL or response_headers_json is malformed."
    if not isinstance(raw_headers, dict) or any(
        not isinstance(name, str) or not isinstance(value, (str, int, float))
        for name, value in raw_headers.items()
    ):
        return "Invalid input: response_headers_json must be an object of header names and values."

    headers = {name.strip().lower(): str(value).strip() for name, value in raw_headers.items()}
    observations: list[tuple[str, str, str]] = []

    def missing(header: str, severity: str, advice: str) -> None:
        observations.append((severity, f"{header} is absent", advice))

    if parsed_url.scheme.lower() == "https":
        if "strict-transport-security" not in headers:
            missing("Strict-Transport-Security", "Medium", "Set HSTS with an appropriate max-age after confirming all subdomains support HTTPS.")
    else:
        observations.append(("Info", "The supplied URL uses HTTP", "Repeat the observation over HTTPS before drawing conclusions about transport security."))

    csp = headers.get("content-security-policy", "")
    if not csp:
        missing("Content-Security-Policy", "Low", "Define a policy suited to the application; test in report-only mode before enforcement if needed.")
    else:
        lowered_csp = csp.lower()
        risky = [token for token in ("'unsafe-inline'", "'unsafe-eval'", "*") if token in lowered_csp]
        if risky:
            observations.append(("Info", "Content-Security-Policy contains broad/risky source expressions", f"Review these expressions in context: {', '.join(risky)}."))

    if "x-content-type-options" not in headers:
        missing("X-Content-Type-Options", "Low", "Set X-Content-Type-Options: nosniff where compatible.")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        missing("X-Frame-Options / CSP frame-ancestors", "Low", "Use CSP frame-ancestors (preferred) or X-Frame-Options to control embedding.")
    if "referrer-policy" not in headers:
        missing("Referrer-Policy", "Info", "Choose a policy that limits unnecessary referrer data, such as strict-origin-when-cross-origin.")
    if "permissions-policy" not in headers:
        missing("Permissions-Policy", "Info", "Explicitly limit browser features the application does not need.")

    cors_origin = headers.get("access-control-allow-origin", "")
    cors_credentials = headers.get("access-control-allow-credentials", "").lower()
    if cors_origin == "*" and cors_credentials == "true":
        observations.append(("Info", "CORS combines wildcard origin with the credentials flag", "Browsers reject this combination in standard credentialed CORS flows. Verify actual request/response behavior before assigning severity; investigate dynamic origin reflection separately."))
    elif cors_origin == "*":
        observations.append(("Info", "CORS allows any origin", "Confirm the resource is intentionally public and does not expose sensitive data."))

    if not observations:
        observations.append(("Info", "No checked gaps were observed", "This limited header review does not establish that the application is secure."))
    order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    observations.sort(key=lambda item: (order[item[0]], item[1]))
    host_label = escape(parsed_url.hostname, quote=True)
    if port is not None:
        host_label += f":{port}"
    lines = [f"Offline HTTP header review for {parsed_url.scheme}://{host_label}", "Observations:"]
    lines.extend(f"- [{severity}] {finding}. {advice}" for severity, finding, advice in observations)
    lines.append("Scope note: analysis used only the supplied header snapshot; no network request was made.")
    return "\n".join(lines)
