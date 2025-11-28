"""Professional pentest report generation tools."""
from __future__ import annotations
import os
import json
from datetime import datetime
from smolagents import tool


# Global state for report mode
_REPORT_MODE_ENABLED = False
_CURRENT_REPORT_DATA: dict = {}
# Track all tools used during the session (even outside report mode)
_SESSION_TOOLS_USED: set = set()
# Artifacts storage (screenshots, raw tool outputs)
_REPORT_ARTIFACTS: list = []


def track_tool_usage(tool_name: str):
    """Track tool usage for the session (called by other tools)."""
    global _SESSION_TOOLS_USED, _CURRENT_REPORT_DATA
    _SESSION_TOOLS_USED.add(tool_name)
    if _REPORT_MODE_ENABLED and _CURRENT_REPORT_DATA:
        _CURRENT_REPORT_DATA["tools"].add(tool_name)


def get_session_tools() -> set:
    """Get all tools used in the current session."""
    global _SESSION_TOOLS_USED
    return _SESSION_TOOLS_USED.copy()


def _get_report_template_html() -> str:
    """Return the HTML report template."""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{title}}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            color: #333;
            background: #f5f5f5;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .report-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 3rem 2rem;
            margin-bottom: 2rem;
            border-radius: 8px;
        }
        .report-header h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
        .report-header .subtitle { opacity: 0.9; font-size: 1.2rem; }
        .report-header .meta { margin-top: 1.5rem; font-size: 0.95rem; opacity: 0.85; }
        .section {
            background: white;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .section h2 {
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 0.5rem;
            margin-bottom: 1.5rem;
        }
        .section h3 { color: #444; margin: 1.5rem 0 1rem; }
        .executive-summary { background: #f8f9ff; border-left: 4px solid #667eea; }
        .findings-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 1.5rem 0;
        }
        .stat-card {
            text-align: center;
            padding: 1.5rem;
            border-radius: 8px;
            color: white;
        }
        .stat-card.critical { background: #dc3545; }
        .stat-card.high { background: #fd7e14; }
        .stat-card.medium { background: #ffc107; color: #333; }
        .stat-card.low { background: #28a745; }
        .stat-card.info { background: #17a2b8; }
        .stat-card .number { font-size: 2.5rem; font-weight: bold; }
        .stat-card .label { text-transform: uppercase; font-size: 0.85rem; }
        .finding {
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }
        .finding-header {
            padding: 1rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .finding-header.critical { background: #dc3545; color: white; }
        .finding-header.high { background: #fd7e14; color: white; }
        .finding-header.medium { background: #ffc107; color: #333; }
        .finding-header.low { background: #28a745; color: white; }
        .finding-header.info { background: #17a2b8; color: white; }
        .finding-title { font-weight: 600; font-size: 1.1rem; }
        .finding-body { padding: 1.5rem; }
        .finding-body h4 { color: #555; margin: 1rem 0 0.5rem; font-size: 0.95rem; }
        .finding-body p, .finding-body pre { margin-bottom: 1rem; }
        pre {
            background: #282c34;
            color: #abb2bf;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 0.9rem;
        }
        .tag {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.85rem;
            margin-right: 0.5rem;
            background: rgba(255,255,255,0.2);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        th { background: #f8f9fa; font-weight: 600; }
        .scope-list { list-style: none; }
        .scope-list li { padding: 0.5rem 0; border-bottom: 1px solid #eee; }
        .scope-list li:last-child { border-bottom: none; }
        .tool-badge {
            display: inline-block;
            background: #e9ecef;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            margin: 0.25rem;
        }
        .tools-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        .tool-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }
        .tool-card .tool-icon { font-size: 1.5rem; margin-bottom: 0.5rem; }
        .tool-card .tool-name { font-weight: 600; color: #495057; }
        .recon-section { background: #e8f4fd; border-left: 4px solid #0d6efd; }
        .recon-data-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }
        .recon-data-card {
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .recon-data-header {
            background: #0d6efd;
            color: white;
            padding: 0.75rem 1rem;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
        }
        .recon-data-count { background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.85rem; }
        .recon-data-list {
            max-height: 300px;
            overflow-y: auto;
            padding: 0.5rem;
        }
        .recon-data-list code {
            display: block;
            padding: 0.3rem 0.5rem;
            font-size: 0.8rem;
            border-bottom: 1px solid #eee;
            word-break: break-all;
        }
        .recon-data-list code:last-child { border-bottom: none; }
        .methodology { background: #fff3cd; border-left: 4px solid #ffc107; }
        .conclusion { background: #d4edda; border-left: 4px solid #28a745; }
        .artifacts-section { background: #f0f7ff; border-left: 4px solid #0d6efd; }
        .artifacts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }
        .artifact-card {
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .artifact-header {
            background: #0d6efd;
            color: white;
            padding: 0.75rem 1rem;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .artifact-header.screenshot { background: #6f42c1; }
        .artifact-header.tool-output { background: #198754; }
        .artifact-body { padding: 1rem; }
        .artifact-body img { 
            max-width: 100%; 
            height: auto; 
            border-radius: 4px;
            border: 1px solid #dee2e6;
            cursor: pointer;
        }
        .artifact-body pre {
            max-height: 300px;
            overflow: auto;
            font-size: 0.75rem;
            margin: 0;
        }
        .artifact-meta { font-size: 0.8rem; color: #6c757d; margin-top: 0.5rem; }
        .download-btn {
            display: inline-block;
            background: #0d6efd;
            color: white;
            padding: 0.4rem 0.8rem;
            border-radius: 4px;
            text-decoration: none;
            font-size: 0.85rem;
            margin-top: 0.5rem;
        }
        .download-btn:hover { background: #0b5ed7; }
        @media print {
            .container { max-width: 100%; }
            .section { break-inside: avoid; }
            .finding { break-inside: avoid; }
            .recon-data-list { max-height: none; }
            .artifact-body pre { max-height: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <h1>{{title}}</h1>
            <div class="subtitle">{{subtitle}}</div>
            <div class="meta">
                <strong>Target:</strong> {{target}} | 
                <strong>Date:</strong> {{date}} | 
                <strong>Prepared by:</strong> {{author}}
            </div>
        </div>
        
        <div class="section executive-summary">
            <h2>📋 Executive Summary</h2>
            <p>{{executive_summary}}</p>
            
            <div class="findings-summary">
                <div class="stat-card critical">
                    <div class="number">{{critical_count}}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="number">{{high_count}}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="number">{{medium_count}}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="number">{{low_count}}</div>
                    <div class="label">Low</div>
                </div>
                <div class="stat-card info">
                    <div class="number">{{info_count}}</div>
                    <div class="label">Info</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🎯 Scope & Methodology</h2>
            <h3>Targets in Scope</h3>
            <ul class="scope-list">
                {{scope_items}}
            </ul>
            
            <h3>Testing Methodology</h3>
            <p>{{methodology}}</p>
        </div>
        
        {{recon_section}}
        
        <div class="section">
            <h2>🔍 Detailed Findings</h2>
            {{findings_html}}
        </div>
        
        <div class="section conclusion">
            <h2>📝 Conclusion & Recommendations</h2>
            <p>{{conclusion}}</p>
        </div>
        
        <div class="section">
            <h2>🛠️ Tools Used</h2>
            <p>The following tools were used during this assessment:</p>
            <div class="tools-grid">
                {{tools_used}}
            </div>
        </div>
        
        {{artifacts_section}}
        
        <div class="section">
            <h2>📚 References</h2>
            <ul>
                {{references}}
            </ul>
        </div>
    </div>
</body>
</html>'''


@tool
def enable_report_mode(
    title: str,
    target: str,
    author: str = "OWASP SmolAgent",
    report_type: str = "Penetration Test"
) -> str:
    """Enable report generation mode. All subsequent findings will be collected for the report.

    Args:
        title: Report title (e.g., 'Security Assessment of Example Corp').
        target: Primary target (e.g., 'https://example.com').
        author: Report author name (default 'OWASP SmolAgent').
        report_type: Type of assessment (default 'Penetration Test').
    Returns: Confirmation that report mode is enabled.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    _REPORT_MODE_ENABLED = True
    _REPORT_ARTIFACTS.clear()  # Clear previous artifacts
    _CURRENT_REPORT_DATA = {
        "title": title,
        "subtitle": f"{report_type} Report",
        "target": target,
        "author": author,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "executive_summary": "",
        "scope": [target],
        "methodology": "Testing was conducted following OWASP Testing Guide (WSTG) methodology, covering reconnaissance, vulnerability scanning, manual testing, and exploitation attempts within the defined scope.",
        "tools": set(),
        "findings": [],
        "conclusion": "",
        "references": [],
        "artifacts": []  # Screenshots and tool outputs
    }
    
    return f"✅ Report mode ENABLED. Collecting findings for: {title}\nTarget: {target}\nUse add_finding_to_report() to add findings, then generate_report() when done."


@tool
def disable_report_mode() -> str:
    """Disable report generation mode and clear collected data.

    Returns: Confirmation that report mode is disabled.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    _REPORT_MODE_ENABLED = False
    _CURRENT_REPORT_DATA = {}
    
    return "Report mode DISABLED. Data cleared."


@tool
def get_report_status() -> str:
    """Check if report mode is enabled and get current report status.

    Returns: Current report mode status and collected findings count.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is DISABLED. Use enable_report_mode() to start collecting findings."
    
    findings_count = len(_CURRENT_REPORT_DATA.get("findings", []))
    severity_counts = {}
    for f in _CURRENT_REPORT_DATA.get("findings", []):
        sev = f.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    return f"""Report mode ENABLED
Title: {_CURRENT_REPORT_DATA.get('title')}
Target: {_CURRENT_REPORT_DATA.get('target')}
Findings collected: {findings_count}
By severity: {severity_counts}
Tools used: {', '.join(_CURRENT_REPORT_DATA.get('tools', set()))}"""


@tool
def add_finding_to_report(
    title: str,
    severity: str,
    description: str,
    impact: str,
    remediation: str,
    owasp_category: str | None = None,
    cvss_score: str | None = None,
    affected_component: str | None = None,
    evidence: str | None = None,
    steps_to_reproduce: str | None = None,
    tool_used: str | None = None
) -> str:
    """Add a security finding to the current report.

    Args:
        title: Finding title (e.g., 'SQL Injection in Login Form').
        severity: Severity level (Critical, High, Medium, Low, Info).
        description: Detailed description of the vulnerability.
        impact: Business/technical impact of the vulnerability.
        remediation: Recommended fix/mitigation.
        owasp_category: OWASP Top 10 category (e.g., 'A03:2021 Injection').
        cvss_score: CVSS score if calculated (e.g., '9.8').
        affected_component: Specific URL/endpoint/component affected.
        evidence: Proof of concept, screenshots description, or payload.
        steps_to_reproduce: Steps to reproduce the issue.
        tool_used: Tool used to discover (e.g., 'nmap', 'nikto', 'manual').
    Returns: Confirmation that finding was added.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled. Use enable_report_mode() first."
    
    finding = {
        "id": len(_CURRENT_REPORT_DATA["findings"]) + 1,
        "title": title,
        "severity": severity,
        "description": description,
        "impact": impact,
        "remediation": remediation,
        "owasp_category": owasp_category or "N/A",
        "cvss_score": cvss_score or "N/A",
        "affected_component": affected_component or _CURRENT_REPORT_DATA.get("target", "N/A"),
        "evidence": evidence or "",
        "steps_to_reproduce": steps_to_reproduce or "",
        "tool_used": tool_used or "Manual Testing"
    }
    
    _CURRENT_REPORT_DATA["findings"].append(finding)
    
    if tool_used:
        _CURRENT_REPORT_DATA["tools"].add(tool_used)
    
    return f"✅ Finding #{finding['id']} added: [{severity}] {title}"


@tool
def add_scope_item(item: str) -> str:
    """Add an item to the report scope.

    Args:
        item: Scope item to add (URL, IP, hostname, etc.).
    Returns: Confirmation that scope item was added.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled."
    
    if item not in _CURRENT_REPORT_DATA["scope"]:
        _CURRENT_REPORT_DATA["scope"].append(item)
    
    return f"Added to scope: {item}"


@tool
def set_executive_summary(summary: str) -> str:
    """Set the executive summary for the report.

    Args:
        summary: Executive summary text (high-level overview for management).
    Returns: Confirmation.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled."
    
    _CURRENT_REPORT_DATA["executive_summary"] = summary
    return "Executive summary set."


@tool
def set_conclusion(conclusion: str) -> str:
    """Set the conclusion and recommendations for the report.

    Args:
        conclusion: Conclusion and recommendations text.
    Returns: Confirmation.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled."
    
    _CURRENT_REPORT_DATA["conclusion"] = conclusion
    return "Conclusion set."


@tool
def add_recon_data(
    data_type: str,
    items: str,
    source_tool: str | None = None
) -> str:
    """Add reconnaissance data (subdomains, IPs, emails, etc.) to the report.
    Use this to store COMPLETE raw data that should not be truncated in the report.

    Args:
        data_type: Type of data (subdomains, ip_addresses, emails, dns_records, ports, technologies, directories, endpoints).
        items: Newline-separated list of items OR JSON array string.
        source_tool: Tool that discovered this data (e.g., 'subfinder', 'nmap', 'whois').
    Returns: Confirmation with count of items added.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled. Use enable_report_mode() first."
    
    # Parse items - support both newline-separated and JSON array
    if items.strip().startswith('['):
        try:
            item_list = json.loads(items)
        except:
            item_list = [i.strip() for i in items.split('\n') if i.strip()]
    else:
        item_list = [i.strip() for i in items.split('\n') if i.strip()]
    
    # Initialize recon_data dict if not exists
    if "recon_data" not in _CURRENT_REPORT_DATA:
        _CURRENT_REPORT_DATA["recon_data"] = {}
    
    # Add or extend the data type
    if data_type not in _CURRENT_REPORT_DATA["recon_data"]:
        _CURRENT_REPORT_DATA["recon_data"][data_type] = []
    
    # Add unique items
    existing = set(_CURRENT_REPORT_DATA["recon_data"][data_type])
    new_items = [i for i in item_list if i not in existing]
    _CURRENT_REPORT_DATA["recon_data"][data_type].extend(new_items)
    
    # Track tool usage
    if source_tool:
        _CURRENT_REPORT_DATA["tools"].add(source_tool)
    
    total = len(_CURRENT_REPORT_DATA["recon_data"][data_type])
    return f"✅ Added {len(new_items)} new {data_type} (total: {total}). Source: {source_tool or 'N/A'}"


@tool
def add_bulk_scope(items: str) -> str:
    """Add multiple scope items at once (subdomains, IPs, URLs discovered during recon).

    Args:
        items: Newline-separated list of scope items OR JSON array string.
    Returns: Confirmation with count of items added.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled."
    
    # Parse items
    if items.strip().startswith('['):
        try:
            item_list = json.loads(items)
        except:
            item_list = [i.strip() for i in items.split('\n') if i.strip()]
    else:
        item_list = [i.strip() for i in items.split('\n') if i.strip()]
    
    # Add unique items
    existing = set(_CURRENT_REPORT_DATA.get("scope", []))
    new_items = [i for i in item_list if i not in existing]
    _CURRENT_REPORT_DATA["scope"].extend(new_items)
    
    return f"✅ Added {len(new_items)} scope items (total: {len(_CURRENT_REPORT_DATA['scope'])})"


@tool
def get_recon_summary() -> str:
    """Get a summary of all collected reconnaissance data.

    Returns: Summary of all recon data types and counts.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled."
    
    recon_data = _CURRENT_REPORT_DATA.get("recon_data", {})
    if not recon_data:
        return "No reconnaissance data collected yet. Use add_recon_data() to add data."
    
    lines = ["📊 Reconnaissance Data Summary:", ""]
    for data_type, items in sorted(recon_data.items()):
        lines.append(f"- {data_type}: {len(items)} items")
    
    lines.append("")
    lines.append(f"Tools used: {', '.join(sorted(_CURRENT_REPORT_DATA.get('tools', set())))}")
    
    return "\n".join(lines)


@tool
def record_tool_used(tool_name: str, description: str | None = None) -> str:
    """Record a tool that was used during the assessment.

    Args:
        tool_name: Name of the tool (e.g., 'nmap', 'burpsuite', 'subfinder').
        description: Optional description of how the tool was used.
    Returns: Confirmation.
    """
    global _CURRENT_REPORT_DATA, _SESSION_TOOLS_USED
    
    _SESSION_TOOLS_USED.add(tool_name)
    
    if _REPORT_MODE_ENABLED and _CURRENT_REPORT_DATA:
        _CURRENT_REPORT_DATA["tools"].add(tool_name)
        
        # Store tool details if provided
        if description:
            if "tool_details" not in _CURRENT_REPORT_DATA:
                _CURRENT_REPORT_DATA["tool_details"] = {}
            _CURRENT_REPORT_DATA["tool_details"][tool_name] = description
    
    return f"✅ Recorded tool: {tool_name}"


@tool
def add_screenshot_to_report(
    url: str,
    base64_data: str,
    description: str = "Website Screenshot",
    timestamp: str | None = None
) -> str:
    """Add a screenshot to the report artifacts section.

    Args:
        url: The URL that was screenshotted.
        base64_data: Base64 encoded PNG image data.
        description: Description of the screenshot (e.g., 'Homepage', 'Login Page').
        timestamp: Optional timestamp when screenshot was taken.
    Returns: Confirmation that screenshot was added.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA, _REPORT_ARTIFACTS
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled. Use enable_report_mode() first."
    
    artifact = {
        "type": "screenshot",
        "url": url,
        "description": description,
        "data": base64_data,
        "timestamp": timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    _REPORT_ARTIFACTS.append(artifact)
    if "artifacts" not in _CURRENT_REPORT_DATA:
        _CURRENT_REPORT_DATA["artifacts"] = []
    _CURRENT_REPORT_DATA["artifacts"].append(artifact)
    
    return f"✅ Screenshot added to report: {description} ({url})"


@tool
def add_tool_output_to_report(
    tool_name: str,
    output_data: str,
    output_format: str = "text",
    filename: str | None = None,
    description: str | None = None
) -> str:
    """Add raw tool output data to the report artifacts section.

    Args:
        tool_name: Name of the tool (e.g., 'nmap', 'nikto', 'nuclei').
        output_data: Raw output data from the tool.
        output_format: Format of the output (text, xml, json, csv).
        filename: Optional filename for the artifact (e.g., 'nmap_scan.xml').
        description: Optional description of what this output contains.
    Returns: Confirmation that artifact was added.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA, _REPORT_ARTIFACTS
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled. Use enable_report_mode() first."
    
    # Generate filename if not provided
    if not filename:
        ext = {"xml": "xml", "json": "json", "csv": "csv", "text": "txt"}.get(output_format, "txt")
        filename = f"{tool_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
    
    artifact = {
        "type": "tool_output",
        "tool_name": tool_name,
        "filename": filename,
        "format": output_format,
        "data": output_data,
        "description": description or f"Raw output from {tool_name}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    _REPORT_ARTIFACTS.append(artifact)
    if "artifacts" not in _CURRENT_REPORT_DATA:
        _CURRENT_REPORT_DATA["artifacts"] = []
    _CURRENT_REPORT_DATA["artifacts"].append(artifact)
    
    # Also track the tool
    _CURRENT_REPORT_DATA["tools"].add(tool_name)
    
    return f"✅ Tool output added to report: {filename} ({len(output_data)} bytes)"


def get_report_artifacts() -> list:
    """Get all artifacts for external access."""
    global _REPORT_ARTIFACTS
    return _REPORT_ARTIFACTS.copy()


@tool
def generate_html_report() -> str:
    """Generate the final HTML report from collected findings.

    Returns: Complete HTML report as a string.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA, _SESSION_TOOLS_USED
    
    if not _REPORT_MODE_ENABLED or not _CURRENT_REPORT_DATA:
        return "Report mode is not enabled or no data collected. Use enable_report_mode() first."
    
    template = _get_report_template_html()
    data = _CURRENT_REPORT_DATA
    
    # Count severities
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in data.get("findings", []):
        sev = f.get("severity", "Info")
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    # Build scope HTML - include all items
    scope_items = data.get("scope", [])
    scope_html = "".join([f"<li>{s}</li>" for s in scope_items])
    
    # Build tools HTML with cards for better presentation
    all_tools = data.get("tools", set()) | _SESSION_TOOLS_USED
    tool_details = data.get("tool_details", {})
    
    tool_icons = {
        "nmap": "🔍", "nikto": "🔧", "sqlmap": "💉", "burpsuite": "🌐", 
        "subfinder": "🔎", "amass": "🗺️", "dirsearch": "📂", "gobuster": "📁",
        "nuclei": "⚛️", "wpscan": "📝", "curl": "🔗", "whois": "ℹ️",
        "dig": "🌍", "nslookup": "📡", "masscan": "🚀", "ffuf": "🎯",
        "hydra": "🔓", "john": "🔐", "hashcat": "🔢", "metasploit": "💀",
        "playwright": "🎭", "wapiti": "🐺", "zaproxy": "⚡", "feroxbuster": "🦊"
    }
    
    tools_html = ""
    for t in sorted(all_tools):
        icon = tool_icons.get(t.lower(), "🛠️")
        tools_html += f'''
        <div class="tool-card">
            <div class="tool-icon">{icon}</div>
            <div class="tool-name">{t}</div>
        </div>
        '''
    
    # Build recon data section
    recon_data = data.get("recon_data", {})
    recon_section = ""
    if recon_data:
        recon_cards = ""
        for data_type, items in sorted(recon_data.items()):
            items_html = "".join([f"<code>{item}</code>" for item in items])
            recon_cards += f'''
            <div class="recon-data-card">
                <div class="recon-data-header">
                    <span>{data_type.replace('_', ' ').title()}</span>
                    <span class="recon-data-count">{len(items)} items</span>
                </div>
                <div class="recon-data-list">{items_html}</div>
            </div>
            '''
        
        recon_section = f'''
        <div class="section recon-section">
            <h2>📡 Reconnaissance Data</h2>
            <p>The following data was collected during the reconnaissance phase:</p>
            <div class="recon-data-grid">
                {recon_cards}
            </div>
        </div>
        '''
    
    # Build findings HTML
    findings_html = ""
    for f in sorted(data.get("findings", []), key=lambda x: ["Critical", "High", "Medium", "Low", "Info"].index(x.get("severity", "Info"))):
        sev_class = f.get("severity", "Info").lower()
        findings_html += f'''
        <div class="finding">
            <div class="finding-header {sev_class}">
                <span class="finding-title">#{f['id']}: {f['title']}</span>
                <span class="tag">{f['severity']}</span>
                <span class="tag">{f['owasp_category']}</span>
            </div>
            <div class="finding-body">
                <h4>Description</h4>
                <p>{f['description']}</p>
                
                <h4>Affected Component</h4>
                <p>{f['affected_component']}</p>
                
                <h4>Impact</h4>
                <p>{f['impact']}</p>
                
                {"<h4>Evidence / PoC</h4><pre>" + f['evidence'] + "</pre>" if f.get('evidence') else ""}
                
                {"<h4>Steps to Reproduce</h4><p>" + f['steps_to_reproduce'] + "</p>" if f.get('steps_to_reproduce') else ""}
                
                <h4>Remediation</h4>
                <p>{f['remediation']}</p>
                
                <h4>Details</h4>
                <table>
                    <tr><th>CVSS Score</th><td>{f['cvss_score']}</td></tr>
                    <tr><th>Tool Used</th><td>{f['tool_used']}</td></tr>
                </table>
            </div>
        </div>
        '''
    
    # Build references
    references_html = """
        <li><a href="https://owasp.org/Top10/">OWASP Top 10</a></li>
        <li><a href="https://owasp.org/www-project-web-security-testing-guide/">OWASP Web Security Testing Guide (WSTG)</a></li>
        <li><a href="https://owasp.org/www-project-application-security-verification-standard/">OWASP ASVS</a></li>
        <li><a href="https://cwe.mitre.org/">CWE - Common Weakness Enumeration</a></li>
        <li><a href="https://nvd.nist.gov/">NIST National Vulnerability Database</a></li>
    """
    
    # Build artifacts section
    artifacts = data.get("artifacts", []) + _REPORT_ARTIFACTS
    artifacts_section = ""
    if artifacts:
        artifacts_html = ""
        for artifact in artifacts:
            if artifact.get("type") == "screenshot":
                artifacts_html += f'''
                <div class="artifact-card">
                    <div class="artifact-header screenshot">
                        <span>📸 {artifact.get("description", "Screenshot")}</span>
                        <span style="font-size: 0.8rem; opacity: 0.8;">{artifact.get("timestamp", "")}</span>
                    </div>
                    <div class="artifact-body">
                        <img src="data:image/png;base64,{artifact.get("data", "")}" alt="{artifact.get("description", "Screenshot")}" onclick="window.open(this.src)">
                        <div class="artifact-meta">URL: {artifact.get("url", "N/A")}</div>
                    </div>
                </div>
                '''
            elif artifact.get("type") == "tool_output":
                # Truncate very long outputs in HTML, but provide download
                output_data = artifact.get("data", "")
                display_data = output_data[:5000] + ("\\n... [truncated, see download]" if len(output_data) > 5000 else "")
                # Create data URL for download
                import base64
                encoded_data = base64.b64encode(output_data.encode()).decode()
                mime_types = {"xml": "application/xml", "json": "application/json", "csv": "text/csv", "text": "text/plain"}
                mime = mime_types.get(artifact.get("format", "text"), "text/plain")
                
                artifacts_html += f'''
                <div class="artifact-card">
                    <div class="artifact-header tool-output">
                        <span>📄 {artifact.get("filename", "output.txt")}</span>
                        <span style="font-size: 0.8rem; opacity: 0.8;">{artifact.get("tool_name", "")}</span>
                    </div>
                    <div class="artifact-body">
                        <pre>{display_data}</pre>
                        <div class="artifact-meta">{artifact.get("description", "")} | {artifact.get("timestamp", "")}</div>
                        <a class="download-btn" href="data:{mime};base64,{encoded_data}" download="{artifact.get("filename", "output.txt")}">📥 Download {artifact.get("filename", "file")}</a>
                    </div>
                </div>
                '''
        
        artifacts_section = f'''
        <div class="section artifacts-section">
            <h2>📦 Artifacts</h2>
            <p>Screenshots and raw tool outputs collected during the assessment:</p>
            <div class="artifacts-grid">
                {artifacts_html}
            </div>
        </div>
        '''
    
    # Replace placeholders
    html = template
    html = html.replace("{{title}}", data.get("title", "Security Assessment Report"))
    html = html.replace("{{subtitle}}", data.get("subtitle", "Penetration Test Report"))
    html = html.replace("{{target}}", data.get("target", "N/A"))
    html = html.replace("{{date}}", data.get("date", datetime.now().strftime("%Y-%m-%d")))
    html = html.replace("{{author}}", data.get("author", "OWASP SmolAgent"))
    html = html.replace("{{executive_summary}}", data.get("executive_summary", "This report presents the findings from a security assessment conducted against the target application."))
    html = html.replace("{{critical_count}}", str(severity_counts["Critical"]))
    html = html.replace("{{high_count}}", str(severity_counts["High"]))
    html = html.replace("{{medium_count}}", str(severity_counts["Medium"]))
    html = html.replace("{{low_count}}", str(severity_counts["Low"]))
    html = html.replace("{{info_count}}", str(severity_counts["Info"]))
    html = html.replace("{{scope_items}}", scope_html or "<li>Target scope not specified</li>")
    html = html.replace("{{methodology}}", data.get("methodology", ""))
    html = html.replace("{{recon_section}}", recon_section)
    html = html.replace("{{tools_used}}", tools_html or '<div class="tool-card"><div class="tool-icon">🛠️</div><div class="tool-name">Manual Testing</div></div>')
    html = html.replace("{{findings_html}}", findings_html or "<p>No findings recorded.</p>")
    html = html.replace("{{conclusion}}", data.get("conclusion", "Based on the assessment, the recommendations above should be implemented to improve the security posture of the application."))
    html = html.replace("{{artifacts_section}}", artifacts_section)
    html = html.replace("{{references}}", references_html)
    
    return html


@tool
def generate_markdown_report() -> str:
    """Generate the report in Markdown format for easy sharing and editing.

    Returns: Complete Markdown report as a string.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA, _SESSION_TOOLS_USED
    
    if not _REPORT_MODE_ENABLED or not _CURRENT_REPORT_DATA:
        return "Report mode is not enabled or no data collected."
    
    data = _CURRENT_REPORT_DATA
    
    # Count severities
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in data.get("findings", []):
        sev = f.get("severity", "Info")
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    # Combine all tools used
    all_tools = data.get("tools", set()) | _SESSION_TOOLS_USED
    
    lines = []
    
    # Header
    lines.append(f"# {data.get('title', 'Security Assessment Report')}")
    lines.append(f"**{data.get('subtitle', 'Penetration Test Report')}**")
    lines.append("")
    lines.append(f"- **Target:** {data.get('target', 'N/A')}")
    lines.append(f"- **Date:** {data.get('date', datetime.now().strftime('%Y-%m-%d'))}")
    lines.append(f"- **Author:** {data.get('author', 'OWASP SmolAgent')}")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(data.get("executive_summary", "This report presents findings from a security assessment."))
    lines.append("")
    lines.append("### Findings Overview")
    lines.append("")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    lines.append(f"| 🔴 Critical | {severity_counts['Critical']} |")
    lines.append(f"| 🟠 High | {severity_counts['High']} |")
    lines.append(f"| 🟡 Medium | {severity_counts['Medium']} |")
    lines.append(f"| 🟢 Low | {severity_counts['Low']} |")
    lines.append(f"| 🔵 Info | {severity_counts['Info']} |")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Scope
    lines.append("## Scope & Methodology")
    lines.append("")
    lines.append("### Targets in Scope")
    lines.append("")
    scope_items = data.get("scope", [])
    if scope_items:
        for s in scope_items:
            lines.append(f"- {s}")
    else:
        lines.append("- (No scope items specified)")
    lines.append("")
    lines.append("### Methodology")
    lines.append("")
    lines.append(data.get("methodology", "Testing followed OWASP Testing Guide methodology."))
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Recon Data Section
    recon_data = data.get("recon_data", {})
    if recon_data:
        lines.append("## 📡 Reconnaissance Data")
        lines.append("")
        lines.append("The following data was collected during the reconnaissance phase:")
        lines.append("")
        
        for data_type, items in sorted(recon_data.items()):
            lines.append(f"### {data_type.replace('_', ' ').title()} ({len(items)} items)")
            lines.append("")
            lines.append("<details>")
            lines.append("<summary>Click to expand</summary>")
            lines.append("")
            lines.append("```")
            for item in items:
                lines.append(item)
            lines.append("```")
            lines.append("")
            lines.append("</details>")
            lines.append("")
        
        lines.append("---")
        lines.append("")
    
    # Findings
    lines.append("## Detailed Findings")
    lines.append("")
    
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    sorted_findings = sorted(
        data.get("findings", []),
        key=lambda x: severity_order.index(x.get("severity", "Info")) if x.get("severity", "Info") in severity_order else 5
    )
    
    for f in sorted_findings:
        sev_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Info": "🔵"}.get(f.get("severity"), "⚪")
        lines.append(f"### {sev_emoji} {f['id']}. {f['title']}")
        lines.append("")
        lines.append(f"**Severity:** {f.get('severity', 'N/A')} | **OWASP:** {f.get('owasp_category', 'N/A')} | **CVSS:** {f.get('cvss_score', 'N/A')}")
        lines.append("")
        lines.append("#### Description")
        lines.append(f.get("description", ""))
        lines.append("")
        lines.append("#### Affected Component")
        lines.append(f.get("affected_component", "N/A"))
        lines.append("")
        lines.append("#### Impact")
        lines.append(f.get("impact", ""))
        lines.append("")
        if f.get("evidence"):
            lines.append("#### Evidence / PoC")
            lines.append("```")
            lines.append(f.get("evidence", ""))
            lines.append("```")
            lines.append("")
        if f.get("steps_to_reproduce"):
            lines.append("#### Steps to Reproduce")
            lines.append(f.get("steps_to_reproduce", ""))
            lines.append("")
        lines.append("#### Remediation")
        lines.append(f.get("remediation", ""))
        lines.append("")
        lines.append(f"*Tool Used: {f.get('tool_used', 'Manual Testing')}*")
        lines.append("")
        lines.append("---")
        lines.append("")
    
    # Conclusion
    lines.append("## Conclusion & Recommendations")
    lines.append("")
    lines.append(data.get("conclusion", "Implement the recommended remediations to improve security posture."))
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Tools Used Section
    lines.append("## 🛠️ Tools Used")
    lines.append("")
    lines.append("The following tools were used during this assessment:")
    lines.append("")
    lines.append("| Tool | Category |")
    lines.append("|------|----------|")
    
    # Tool categories for better organization
    tool_categories = {
        "nmap": "Network Scanning", "masscan": "Network Scanning", "rustscan": "Network Scanning",
        "nikto": "Web Scanning", "nuclei": "Web Scanning", "wapiti": "Web Scanning", "zaproxy": "Web Scanning",
        "sqlmap": "Exploitation", "hydra": "Exploitation", "metasploit": "Exploitation",
        "subfinder": "Reconnaissance", "amass": "Reconnaissance", "sublist3r": "Reconnaissance",
        "dirsearch": "Content Discovery", "gobuster": "Content Discovery", "ffuf": "Content Discovery", "feroxbuster": "Content Discovery",
        "curl": "HTTP Client", "httpx": "HTTP Client", "wget": "HTTP Client",
        "whois": "OSINT", "dig": "OSINT", "nslookup": "OSINT", "theharvester": "OSINT",
        "playwright": "Browser Automation", "selenium": "Browser Automation",
        "burpsuite": "Proxy/Scanner", "mitmproxy": "Proxy/Scanner",
        "john": "Password Cracking", "hashcat": "Password Cracking",
        "wpscan": "CMS Scanner"
    }
    
    for t in sorted(all_tools):
        category = tool_categories.get(t.lower(), "Other")
        lines.append(f"| {t} | {category} |")
    
    if not all_tools:
        lines.append("| Manual Testing | Manual |")
    
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Artifacts Section
    artifacts = data.get("artifacts", []) + _REPORT_ARTIFACTS
    if artifacts:
        lines.append("## 📦 Artifacts")
        lines.append("")
        lines.append("Screenshots and raw tool outputs collected during the assessment:")
        lines.append("")
        
        screenshots = [a for a in artifacts if a.get("type") == "screenshot"]
        tool_outputs = [a for a in artifacts if a.get("type") == "tool_output"]
        
        if screenshots:
            lines.append("### Screenshots")
            lines.append("")
            for i, s in enumerate(screenshots, 1):
                lines.append(f"**{i}. {s.get('description', 'Screenshot')}**")
                lines.append(f"- URL: {s.get('url', 'N/A')}")
                lines.append(f"- Timestamp: {s.get('timestamp', 'N/A')}")
                # Include base64 image for markdown that supports it
                lines.append(f"- ![Screenshot]({s.get('url', '')})")
                lines.append("")
        
        if tool_outputs:
            lines.append("### Tool Outputs")
            lines.append("")
            for i, t in enumerate(tool_outputs, 1):
                lines.append(f"**{i}. {t.get('filename', 'output.txt')}** ({t.get('tool_name', 'Unknown')})")
                lines.append(f"- Description: {t.get('description', 'N/A')}")
                lines.append(f"- Format: {t.get('format', 'text')}")
                lines.append(f"- Timestamp: {t.get('timestamp', 'N/A')}")
                lines.append("")
                lines.append("<details>")
                lines.append("<summary>Click to expand output</summary>")
                lines.append("")
                lines.append("```")
                output_data = t.get("data", "")
                if len(output_data) > 10000:
                    lines.append(output_data[:10000] + "\\n... [truncated]")
                else:
                    lines.append(output_data)
                lines.append("```")
                lines.append("")
                lines.append("</details>")
                lines.append("")
        
        lines.append("---")
        lines.append("")
    
    # References
    lines.append("## References")
    lines.append("")
    lines.append("- [OWASP Top 10](https://owasp.org/Top10/)")
    lines.append("- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)")
    lines.append("- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)")
    lines.append("- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)")
    lines.append("- [NIST NVD](https://nvd.nist.gov/)")
    lines.append("")
    lines.append("---")
    lines.append(f"*Report generated by OWASP SmolAgent on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
    
    return "\n".join(lines)


@tool
def generate_pdf_report(output_path: str | None = None) -> str:
    """Generate a PDF report from the HTML report using browser printing.

    Args:
        output_path: Optional file path to save the PDF. If not provided, returns instructions.
    Returns: Path to generated PDF or instructions for manual generation.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled."
    
    # Try using playwright for PDF generation
    try:
        from playwright.sync_api import sync_playwright
        
        html_content = generate_html_report()
        
        if not output_path:
            output_path = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.set_content(html_content)
            page.pdf(path=output_path, format="A4", print_background=True)
            browser.close()
        
        return f"✅ PDF report generated: {output_path}"
    
    except ImportError:
        html_content = generate_html_report()
        html_path = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        # Save HTML instead
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return f"""Playwright not available for PDF generation.
HTML report saved to: {html_path}

To generate PDF manually:
1. Open the HTML file in Chrome/Edge
2. Press Ctrl+P (Print)
3. Select "Save as PDF"
4. Click Save

Or install Playwright: pip install playwright && playwright install chromium"""
    
    except Exception as e:
        return f"Error generating PDF: {e}"


def is_report_mode_enabled() -> bool:
    """Check if report mode is enabled (non-tool function for internal use)."""
    global _REPORT_MODE_ENABLED
    return _REPORT_MODE_ENABLED


def get_report_data() -> dict:
    """Get current report data (non-tool function for internal use)."""
    global _CURRENT_REPORT_DATA
    return _CURRENT_REPORT_DATA.copy() if _CURRENT_REPORT_DATA else {}
