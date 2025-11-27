"""Professional pentest report generation tools."""
from __future__ import annotations
import os
import json
from datetime import datetime
from smolagents import tool


# Global state for report mode
_REPORT_MODE_ENABLED = False
_CURRENT_REPORT_DATA: dict = {}


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
        .methodology { background: #fff3cd; border-left: 4px solid #ffc107; }
        .conclusion { background: #d4edda; border-left: 4px solid #28a745; }
        @media print {
            .container { max-width: 100%; }
            .section { break-inside: avoid; }
            .finding { break-inside: avoid; }
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
            
            <h3>Tools Used</h3>
            <div>{{tools_used}}</div>
        </div>
        
        <div class="section">
            <h2>🔍 Detailed Findings</h2>
            {{findings_html}}
        </div>
        
        <div class="section conclusion">
            <h2>📝 Conclusion & Recommendations</h2>
            <p>{{conclusion}}</p>
        </div>
        
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
        "references": []
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
def generate_html_report() -> str:
    """Generate the final HTML report from collected findings.

    Returns: Complete HTML report as a string.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
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
    
    # Build scope HTML
    scope_html = "".join([f"<li>{s}</li>" for s in data.get("scope", [])])
    
    # Build tools HTML
    tools_html = "".join([f'<span class="tool-badge">{t}</span>' for t in sorted(data.get("tools", set()))])
    
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
    html = html.replace("{{scope_items}}", scope_html)
    html = html.replace("{{methodology}}", data.get("methodology", ""))
    html = html.replace("{{tools_used}}", tools_html or "Various security testing tools")
    html = html.replace("{{findings_html}}", findings_html or "<p>No findings recorded.</p>")
    html = html.replace("{{conclusion}}", data.get("conclusion", "Based on the assessment, the recommendations above should be implemented to improve the security posture of the application."))
    html = html.replace("{{references}}", references_html)
    
    return html


@tool
def generate_markdown_report() -> str:
    """Generate the report in Markdown format for easy sharing and editing.

    Returns: Complete Markdown report as a string.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED or not _CURRENT_REPORT_DATA:
        return "Report mode is not enabled or no data collected."
    
    data = _CURRENT_REPORT_DATA
    
    # Count severities
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in data.get("findings", []):
        sev = f.get("severity", "Info")
        if sev in severity_counts:
            severity_counts[sev] += 1
    
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
    for s in data.get("scope", []):
        lines.append(f"- {s}")
    lines.append("")
    lines.append("### Methodology")
    lines.append("")
    lines.append(data.get("methodology", "Testing followed OWASP Testing Guide methodology."))
    lines.append("")
    lines.append("### Tools Used")
    lines.append("")
    for t in sorted(data.get("tools", set())):
        lines.append(f"- {t}")
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
