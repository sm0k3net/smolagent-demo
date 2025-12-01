"""Professional pentest report generation tools."""
from __future__ import annotations
import os
import re
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


# Mapping of function names to real tool names for command display
_TOOL_NAME_MAPPING = {
    "sqlmap_scan": "sqlmap",
    "sqlmap_dump": "sqlmap",
    "nmap_scan": "nmap",
    "nikto_scan": "nikto",
    "gobuster_scan": "gobuster",
    "gobuster_dir": "gobuster",
    "ffuf_scan": "ffuf",
    "ffuf_vhost": "ffuf",
    "nuclei_scan": "nuclei",
    "nuclei_update_templates": "nuclei",
    "whatweb_scan": "whatweb",
    "httpx_probe": "httpx",
    "subfinder_scan": "subfinder",
    "wpscan_scan": "wpscan",
    "amass_enum": "amass",
    "theharvester_scan": "theharvester",
    "fierce_scan": "fierce",
    "dirb_scan": "dirb",
    "searchsploit_search": "searchsploit",
    "searchsploit_examine": "searchsploit",
    "hydra_brute": "hydra",
    "ncrack_brute": "ncrack",
    "curl_request": "curl",
    "curl_tool": "curl",
}


def normalize_tool_name(name: str) -> str:
    """Convert function name (like sqlmap_scan) to real tool name (sqlmap).
    
    Args:
        name: Tool or function name (e.g., 'sqlmap_scan', 'sqlmap_scan()', 'sqlmap')
    Returns:
        Normalized tool name (e.g., 'sqlmap')
    """
    if not name:
        return "Tool"
    
    # Remove parentheses and arguments if present
    clean_name = re.sub(r'\([^)]*\)', '', name).strip()
    
    # Check mapping first
    if clean_name in _TOOL_NAME_MAPPING:
        return _TOOL_NAME_MAPPING[clean_name]
    
    # Try to extract base tool name from pattern: tool_action or tool_scan
    parts = clean_name.split('_')
    if len(parts) >= 2 and parts[-1] in ('scan', 'dump', 'brute', 'enum', 'search', 
                                           'examine', 'probe', 'request', 'dir', 'vhost'):
        return '_'.join(parts[:-1])
    
    return clean_name


def normalize_command_text(command: str, tool_name: str = None) -> str:
    """Clean up command text for display in reports.
    
    Args:
        command: Raw command text (may contain function calls like sqlmap_scan(...))
        tool_name: Optional tool name for context
    Returns:
        Cleaned command suitable for display
    """
    if not command:
        return ""
    
    # If it looks like a Python function call, try to convert it
    # Pattern: function_name(arg1, arg2, ...) or function_name(key=value, ...)
    func_call_pattern = r'^(\w+)\s*\((.+)\)\s*$'
    match = re.match(func_call_pattern, command.strip(), re.DOTALL)
    
    if match:
        func_name = match.group(1)
        real_tool = normalize_tool_name(func_name)
        
        # If we recognized the function, indicate it's a tool command
        if real_tool != func_name:
            return f"# Executed via {real_tool}\n{command}"
    
    return command


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
        :root {
            --primary: #1e3a5f;
            --primary-light: #2d5a8a;
            --accent: #00b4d8;
            --accent-light: #48cae4;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --danger-dark: #b91c1c;
            --info: #6366f1;
            --neutral-50: #f8fafc;
            --neutral-100: #f1f5f9;
            --neutral-200: #e2e8f0;
            --neutral-300: #cbd5e1;
            --neutral-400: #94a3b8;
            --neutral-500: #64748b;
            --neutral-600: #475569;
            --neutral-700: #334155;
            --neutral-800: #1e293b;
            --neutral-900: #0f172a;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif; 
            line-height: 1.6; 
            color: var(--neutral-800);
            background: var(--neutral-100);
            font-size: 15px;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        
        /* Header */
        .report-header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 50%, var(--accent) 100%);
            color: white;
            padding: 3rem 2.5rem;
            margin-bottom: 2rem;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(30, 58, 95, 0.3);
            position: relative;
            overflow: hidden;
        }
        .report-header::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -20%;
            width: 60%;
            height: 200%;
            background: radial-gradient(ellipse, rgba(255,255,255,0.1) 0%, transparent 70%);
            pointer-events: none;
        }
        .report-header h1 { 
            font-size: 2.25rem; 
            margin-bottom: 0.5rem; 
            font-weight: 700;
            letter-spacing: -0.5px;
        }
        .report-header .subtitle { 
            opacity: 0.9; 
            font-size: 1.1rem;
            font-weight: 500;
        }
        .report-header .meta { 
            margin-top: 1.5rem; 
            font-size: 0.9rem; 
            opacity: 0.85;
            display: flex;
            gap: 2rem;
            flex-wrap: wrap;
        }
        .report-header .meta-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .report-header .meta-icon {
            width: 18px;
            height: 18px;
            opacity: 0.8;
        }
        
        /* Sections */
        .section {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
            border: 1px solid var(--neutral-200);
        }
        .section h2 {
            color: var(--primary);
            font-size: 1.35rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding-bottom: 0.75rem;
            border-bottom: 2px solid var(--neutral-200);
        }
        .section h2 .section-icon {
            width: 28px;
            height: 28px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--accent) 100%);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1rem;
        }
        .section h3 { 
            color: var(--neutral-700); 
            margin: 1.5rem 0 1rem; 
            font-size: 1.1rem;
            font-weight: 600;
        }
        
        /* Executive Summary */
        .executive-summary { 
            background: linear-gradient(135deg, var(--neutral-50) 0%, #f0f9ff 100%);
            border-left: 4px solid var(--accent);
        }
        .exec-summary-content { margin-bottom: 1.5rem; }
        .exec-summary-content p { 
            margin-bottom: 1rem; 
            line-height: 1.8; 
            color: var(--neutral-700);
        }
        
        /* Severity Chart */
        .severity-chart-container {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1.5rem 0;
            border: 1px solid var(--neutral-200);
        }
        .severity-chart-title {
            font-size: 1rem;
            font-weight: 600;
            color: var(--neutral-700);
            margin-bottom: 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .severity-chart {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }
        .severity-bar {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .severity-label {
            width: 80px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .severity-label.critical { color: var(--danger-dark); }
        .severity-label.high { color: #ea580c; }
        .severity-label.medium { color: var(--warning); }
        .severity-label.low { color: var(--success); }
        .severity-label.info { color: var(--info); }
        .bar-container {
            flex: 1;
            height: 28px;
            background: var(--neutral-100);
            border-radius: 6px;
            overflow: hidden;
            position: relative;
        }
        .bar-fill {
            height: 100%;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 0.75rem;
            color: white;
            font-weight: 700;
            font-size: 0.85rem;
            min-width: 35px;
            transition: width 0.5s ease;
        }
        .bar-fill.critical { background: linear-gradient(90deg, var(--danger-dark) 0%, var(--danger) 100%); }
        .bar-fill.high { background: linear-gradient(90deg, #ea580c 0%, #f97316 100%); }
        .bar-fill.medium { background: linear-gradient(90deg, #d97706 0%, var(--warning) 100%); }
        .bar-fill.low { background: linear-gradient(90deg, #059669 0%, var(--success) 100%); }
        .bar-fill.info { background: linear-gradient(90deg, #4f46e5 0%, var(--info) 100%); }
        .bar-count {
            width: 50px;
            text-align: right;
            font-weight: 700;
            font-size: 1.1rem;
            color: var(--neutral-800);
        }
        
        /* Stats Cards */
        .findings-summary {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
            margin: 1.5rem 0;
        }
        .stat-card {
            text-align: center;
            padding: 1.25rem 1rem;
            border-radius: 12px;
            color: white;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            position: relative;
            overflow: hidden;
        }
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 50%;
            height: 100%;
            background: rgba(255,255,255,0.1);
            clip-path: polygon(30% 0, 100% 0, 100% 100%, 0% 100%);
        }
        .stat-card.critical { background: linear-gradient(135deg, var(--danger-dark) 0%, var(--danger) 100%); }
        .stat-card.high { background: linear-gradient(135deg, #ea580c 0%, #f97316 100%); }
        .stat-card.medium { background: linear-gradient(135deg, #d97706 0%, var(--warning) 100%); color: var(--neutral-800); }
        .stat-card.low { background: linear-gradient(135deg, #059669 0%, var(--success) 100%); }
        .stat-card.info { background: linear-gradient(135deg, #4f46e5 0%, var(--info) 100%); }
        .stat-card .number { 
            font-size: 2.5rem; 
            font-weight: 800; 
            line-height: 1;
            position: relative;
        }
        .stat-card .label { 
            text-transform: uppercase; 
            font-size: 0.7rem; 
            font-weight: 700;
            letter-spacing: 1px;
            margin-top: 0.5rem;
            opacity: 0.9;
        }
        
        /* Findings */
        .finding {
            border: 1px solid var(--neutral-200);
            border-radius: 12px;
            margin-bottom: 1.5rem;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        }
        .finding-header {
            padding: 1rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .finding-header.critical { background: linear-gradient(90deg, var(--danger-dark) 0%, var(--danger) 100%); color: white; }
        .finding-header.high { background: linear-gradient(90deg, #ea580c 0%, #f97316 100%); color: white; }
        .finding-header.medium { background: linear-gradient(90deg, #d97706 0%, var(--warning) 100%); color: var(--neutral-800); }
        .finding-header.low { background: linear-gradient(90deg, #059669 0%, var(--success) 100%); color: white; }
        .finding-header.info { background: linear-gradient(90deg, #4f46e5 0%, var(--info) 100%); color: white; }
        .finding-title { 
            font-weight: 700; 
            font-size: 1.05rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .finding-body { padding: 1.5rem; }
        .finding-body h4 { 
            color: var(--neutral-600); 
            margin: 1.25rem 0 0.5rem; 
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 700;
        }
        .finding-body p { margin-bottom: 1rem; color: var(--neutral-700); }
        .finding-meta {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid var(--neutral-200);
        }
        .finding-meta-item {
            display: flex;
            align-items: center;
            gap: 0.4rem;
            font-size: 0.85rem;
            color: var(--neutral-600);
            background: var(--neutral-100);
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
        }
        .finding-screenshot {
            margin: 1rem 0;
            border-radius: 8px;
            overflow: hidden;
            border: 2px solid var(--neutral-200);
        }
        .finding-screenshot img {
            width: 100%;
            display: block;
        }
        .finding-screenshot-caption {
            background: var(--neutral-100);
            padding: 0.5rem 1rem;
            font-size: 0.85rem;
            color: var(--neutral-600);
            font-style: italic;
        }
        
        /* Code blocks */
        pre {
            background: var(--neutral-900);
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.85rem;
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            margin: 0.75rem 0;
        }
        code {
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            font-size: 0.9em;
        }
        .command-block { 
            background: var(--neutral-900); 
            color: #e2e8f0; 
            padding: 1rem 1.25rem; 
            border-radius: 8px; 
            margin: 0.5rem 0; 
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace; 
            font-size: 0.85rem; 
            overflow-x: auto; 
            border-left: 4px solid var(--accent);
            position: relative;
        }
        .command-label { 
            color: var(--accent); 
            margin-bottom: 0.25rem; 
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        /* Tags */
        .tag {
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
            padding: 0.25rem 0.75rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-right: 0.5rem;
            background: rgba(255,255,255,0.25);
        }
        
        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            table-layout: fixed;
        }
        th, td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--neutral-200);
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        th { 
            background: var(--neutral-100); 
            font-weight: 700; 
            color: var(--neutral-700);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        tr:hover { background: var(--neutral-50); }
        
        .scope-table { margin-bottom: 1.5rem; overflow-x: auto; }
        .scope-table table { min-width: 100%; }
        .scope-table th { 
            background: var(--primary); 
            color: white; 
        }
        .scope-table td { 
            font-family: 'JetBrains Mono', monospace; 
            font-size: 0.85rem;
        }
        .scope-type-header { 
            background: var(--neutral-200) !important; 
            font-weight: 700; 
            color: var(--neutral-700); 
        }
        
        /* Infrastructure Tables - Fixed Overflow */
        .infrastructure-table { 
            margin-bottom: 2rem;
            overflow-x: auto;
        }
        .infrastructure-table h3 { 
            color: var(--primary); 
            margin-bottom: 1rem; 
            font-size: 1.05rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .infrastructure-table table { 
            width: 100%;
            min-width: 600px;
            border-collapse: collapse; 
            margin-top: 0.5rem;
            table-layout: fixed;
        }
        .infrastructure-table th { 
            background: var(--primary); 
            color: white; 
            padding: 0.75rem 1rem; 
            text-align: left; 
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .infrastructure-table td { 
            padding: 0.65rem 1rem; 
            border-bottom: 1px solid var(--neutral-200); 
            font-size: 0.85rem;
            word-break: break-word;
            overflow-wrap: break-word;
        }
        .infrastructure-table tr:nth-child(even) { background: var(--neutral-50); }
        .infrastructure-table code { 
            background: var(--neutral-200); 
            padding: 0.15rem 0.4rem; 
            border-radius: 4px; 
            font-size: 0.8rem;
            word-break: break-all;
        }
        .port-open { color: var(--success); font-weight: 700; }
        .port-filtered { color: #ea580c; font-weight: 700; }
        .port-closed { color: var(--danger); font-weight: 700; }
        
        /* Recon Section */
        .recon-section { 
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            border-left: 4px solid var(--info);
        }
        .recon-data-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.25rem;
            margin-top: 1.5rem;
        }
        .recon-data-card {
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border: 1px solid var(--neutral-200);
        }
        .recon-data-header {
            background: var(--primary);
            color: white;
            padding: 0.75rem 1rem;
            font-weight: 600;
            font-size: 0.9rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .recon-data-count { 
            background: rgba(255,255,255,0.2); 
            padding: 0.2rem 0.6rem; 
            border-radius: 20px; 
            font-size: 0.8rem;
            font-weight: 700;
        }
        .recon-data-list {
            max-height: 250px;
            overflow-y: auto;
            padding: 0.5rem;
        }
        .recon-data-list code {
            display: block;
            padding: 0.4rem 0.75rem;
            font-size: 0.8rem;
            border-bottom: 1px solid var(--neutral-100);
            word-break: break-all;
            background: transparent;
            color: var(--neutral-700);
        }
        .recon-data-list code:last-child { border-bottom: none; }
        .recon-data-list code:hover { background: var(--neutral-50); }
        
        /* Tools Section */
        .tools-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        .tool-card {
            background: var(--neutral-50);
            border: 1px solid var(--neutral-200);
            border-radius: 10px;
            padding: 1.25rem 1rem;
            text-align: center;
            transition: all 0.2s;
        }
        .tool-card:hover {
            background: white;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }
        .tool-card .tool-icon { 
            font-size: 1.5rem; 
            margin-bottom: 0.5rem;
            filter: grayscale(0);
        }
        .tool-card .tool-name { 
            font-weight: 700; 
            color: var(--neutral-700);
            font-size: 0.95rem;
        }
        
        /* Artifacts Section */
        .artifacts-section { 
            background: linear-gradient(135deg, #f0f9ff 0%, #faf5ff 100%);
            border-left: 4px solid #8b5cf6;
        }
        .artifacts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }
        .artifact-card {
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border: 1px solid var(--neutral-200);
        }
        .artifact-header {
            background: var(--primary);
            color: white;
            padding: 0.75rem 1rem;
            font-weight: 600;
            font-size: 0.9rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .artifact-header.screenshot { background: linear-gradient(90deg, #7c3aed 0%, #8b5cf6 100%); }
        .artifact-header.tool-output { background: linear-gradient(90deg, #059669 0%, var(--success) 100%); }
        .artifact-body { padding: 1rem; }
        .artifact-body img { 
            max-width: 100%; 
            height: auto; 
            border-radius: 6px;
            border: 1px solid var(--neutral-200);
            cursor: pointer;
            transition: transform 0.2s;
        }
        .artifact-body img:hover { transform: scale(1.02); }
        .artifact-body pre {
            max-height: 280px;
            overflow: auto;
            font-size: 0.75rem;
            margin: 0;
            border-radius: 6px;
        }
        .artifact-meta { 
            font-size: 0.8rem; 
            color: var(--neutral-500); 
            margin-top: 0.75rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .download-btn {
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            background: var(--primary);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            text-decoration: none;
            font-size: 0.85rem;
            font-weight: 600;
            margin-top: 0.75rem;
            transition: all 0.2s;
        }
        .download-btn:hover { 
            background: var(--primary-light);
            transform: translateY(-1px);
        }
        
        /* Conclusion Section */
        .conclusion-section { 
            background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%);
            border-left: 4px solid var(--success);
        }
        .conclusion-grid { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 1.5rem; 
            margin-top: 1.5rem; 
        }
        .conclusion-card { 
            background: white; 
            border-radius: 10px; 
            padding: 1.5rem; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            border: 1px solid var(--neutral-200);
        }
        .conclusion-card h4 { 
            color: #065f46; 
            margin-bottom: 1rem; 
            display: flex; 
            align-items: center; 
            gap: 0.5rem;
            font-size: 1rem;
        }
        .conclusion-card ul { margin: 0; padding-left: 1.25rem; }
        .conclusion-card li { 
            margin-bottom: 0.5rem;
            color: var(--neutral-700);
        }
        .priority-badge { 
            display: inline-block; 
            padding: 0.2rem 0.6rem; 
            border-radius: 20px; 
            font-size: 0.7rem; 
            font-weight: 700; 
            margin-left: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .priority-immediate { background: var(--danger); color: white; }
        .priority-short { background: #f97316; color: white; }
        .priority-medium { background: var(--warning); color: var(--neutral-800); }
        .priority-long { background: var(--success); color: white; }
        
        /* References */
        .references-list { list-style: none; padding: 0; margin: 0.5rem 0; }
        .references-list li { 
            padding: 0.5rem 0; 
            border-bottom: 1px solid var(--neutral-100);
        }
        .references-list li:last-child { border-bottom: none; }
        .references-list a { 
            color: var(--info); 
            text-decoration: none;
            font-weight: 500;
        }
        .references-list a:hover { text-decoration: underline; }
        
        /* Steps List */
        .steps-list { 
            counter-reset: step-counter; 
            list-style: none; 
            padding-left: 0; 
        }
        .steps-list li { 
            counter-increment: step-counter; 
            margin-bottom: 0.75rem; 
            padding-left: 2.5rem; 
            position: relative;
            color: var(--neutral-700);
        }
        .steps-list li::before { 
            content: counter(step-counter); 
            position: absolute; 
            left: 0; 
            background: var(--primary); 
            color: white; 
            width: 1.75rem; 
            height: 1.75rem; 
            border-radius: 50%; 
            text-align: center; 
            font-size: 0.85rem; 
            line-height: 1.75rem;
            font-weight: 700;
        }
        
        /* Print Styles */
        @media print {
            body { background: white; font-size: 12px; }
            .container { max-width: 100%; padding: 0; }
            .section { 
                break-inside: avoid; 
                box-shadow: none;
                border: 1px solid #ddd;
                margin-bottom: 1rem;
            }
            .report-header { 
                background: var(--primary) !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
            .finding { break-inside: avoid; }
            .recon-data-list { max-height: none; }
            .artifact-body pre { max-height: none; }
            .infrastructure-table { break-inside: avoid; }
            .stat-card {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
        }
        
        /* Responsive */
        @media (max-width: 768px) { 
            .container { padding: 1rem; }
            .report-header { padding: 2rem 1.5rem; }
            .report-header h1 { font-size: 1.75rem; }
            .findings-summary { grid-template-columns: repeat(3, 1fr); }
            .conclusion-grid { grid-template-columns: 1fr; }
            .artifacts-grid { grid-template-columns: 1fr; }
            .infrastructure-table table { min-width: 500px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <h1>{{title}}</h1>
            <div class="subtitle">{{subtitle}}</div>
            <div class="meta">
                <div class="meta-item">
                    <svg class="meta-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                    </svg>
                    <span>{{target}}</span>
                </div>
                <div class="meta-item">
                    <svg class="meta-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>
                    </svg>
                    <span>{{date}}</span>
                </div>
                <div class="meta-item">
                    <svg class="meta-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
                    </svg>
                    <span>{{author}}</span>
                </div>
            </div>
        </div>
        
        <div class="section executive-summary">
            <h2>
                <span class="section-icon">📋</span>
                Executive Summary
            </h2>
            
            <div class="exec-summary-content">
                {{executive_summary_html}}
            </div>
            
            <!-- Severity Distribution Chart -->
            <div class="severity-chart-container">
                <div class="severity-chart-title">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>
                    </svg>
                    Vulnerability Distribution by Severity
                </div>
                <div class="severity-chart">
                    <div class="severity-bar">
                        <span class="severity-label critical">Critical</span>
                        <div class="bar-container">
                            <div class="bar-fill critical" style="width: {{critical_percent}}%;">{{critical_count}}</div>
                        </div>
                        <span class="bar-count">{{critical_count}}</span>
                    </div>
                    <div class="severity-bar">
                        <span class="severity-label high">High</span>
                        <div class="bar-container">
                            <div class="bar-fill high" style="width: {{high_percent}}%;">{{high_count}}</div>
                        </div>
                        <span class="bar-count">{{high_count}}</span>
                    </div>
                    <div class="severity-bar">
                        <span class="severity-label medium">Medium</span>
                        <div class="bar-container">
                            <div class="bar-fill medium" style="width: {{medium_percent}}%;">{{medium_count}}</div>
                        </div>
                        <span class="bar-count">{{medium_count}}</span>
                    </div>
                    <div class="severity-bar">
                        <span class="severity-label low">Low</span>
                        <div class="bar-container">
                            <div class="bar-fill low" style="width: {{low_percent}}%;">{{low_count}}</div>
                        </div>
                        <span class="bar-count">{{low_count}}</span>
                    </div>
                    <div class="severity-bar">
                        <span class="severity-label info">Info</span>
                        <div class="bar-container">
                            <div class="bar-fill info" style="width: {{info_percent}}%;">{{info_count}}</div>
                        </div>
                        <span class="bar-count">{{info_count}}</span>
                    </div>
                </div>
            </div>
            
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
            <h2>
                <span class="section-icon">🎯</span>
                Scope & Methodology
            </h2>
            <h3>Targets in Scope</h3>
            {{scope_table}}
            
            <h3>Testing Methodology</h3>
            <p>{{methodology}}</p>
        </div>
        
        {{recon_section}}
        
        <div class="section">
            <h2>
                <span class="section-icon">🔍</span>
                Detailed Findings
            </h2>
            {{findings_html}}
        </div>
        
        <div class="section conclusion-section">
            <h2>
                <span class="section-icon">📝</span>
                Conclusion & Recommendations
            </h2>
            {{conclusion_html}}
        </div>
        
        <div class="section">
            <h2>
                <span class="section-icon">🛠️</span>
                Tools Used
            </h2>
            <p>The following tools were used during this assessment:</p>
            <div class="tools-grid">
                {{tools_used}}
            </div>
        </div>
        
        {{artifacts_section}}
        
        <div class="section">
            <h2>
                <span class="section-icon">📚</span>
                References
            </h2>
            <ul class="references-list">
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
    author: str = "Pentest.Systems Assistant",
    report_type: str = "Penetration Test"
) -> str:
    """Enable report generation mode. All subsequent findings will be collected for the report.

    Args:
        title: Report title (e.g., 'Security Assessment of Example Corp').
        target: Primary target (e.g., 'https://example.com').
        author: Report author name (default 'Pentest.Systems Assistant').
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
    tool_used: str | None = None,
    command_used: str | None = None,
    references: str | None = None,
    cwe_id: str | None = None
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
        affected_component: Full vulnerability path/URL (e.g., 'https://example.com/admin/upload.php').
        evidence: Proof of concept, screenshots description, or payload.
        steps_to_reproduce: Steps to reproduce (use numbered list format: '1. Step one\n2. Step two').
        tool_used: Tool used to discover (e.g., 'nmap', 'nikto', 'manual').
        command_used: Exact command that was executed (e.g., 'nmap -sV -sC -p- target.com').
        references: Relevant references (newline-separated URLs or CVE IDs).
        cwe_id: CWE ID if applicable (e.g., 'CWE-89').
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
        "cwe_id": cwe_id or "N/A",
        "affected_component": affected_component or _CURRENT_REPORT_DATA.get("target", "N/A"),
        "evidence": evidence or "",
        "steps_to_reproduce": steps_to_reproduce or "",
        "tool_used": tool_used or "Manual Testing",
        "command_used": command_used or "",
        "references": references or ""
    }
    
    _CURRENT_REPORT_DATA["findings"].append(finding)
    
    # Record all tools used (supports comma-separated list like "nikto, sqlmap, curl")
    if tool_used:
        # Split by comma and add each tool
        tools = [t.strip() for t in tool_used.split(",")]
        for t in tools:
            if t:
                _CURRENT_REPORT_DATA["tools"].add(t)
    
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
def add_dns_record(
    record_type: str,
    name: str,
    value: str,
    ttl: str | None = None,
    source_tool: str | None = None
) -> str:
    """Add a DNS record to the report's infrastructure section.

    Args:
        record_type: DNS record type (A, AAAA, CNAME, MX, NS, TXT, SOA, PTR).
        name: DNS name/hostname.
        value: Record value (IP address, domain, etc.).
        ttl: Time-to-live value (optional).
        source_tool: Tool that discovered this record (e.g., 'dig', 'nslookup', 'dnsrecon').
    Returns: Confirmation that DNS record was added.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled. Use enable_report_mode() first."
    
    # Initialize infrastructure data if not exists
    if "infrastructure" not in _CURRENT_REPORT_DATA:
        _CURRENT_REPORT_DATA["infrastructure"] = {
            "dns_records": [],
            "services": [],
            "technologies": [],
            "network_topology": []
        }
    
    record = {
        "type": record_type.upper(),
        "name": name,
        "value": value,
        "ttl": ttl or "N/A"
    }
    
    # Avoid duplicates
    if record not in _CURRENT_REPORT_DATA["infrastructure"]["dns_records"]:
        _CURRENT_REPORT_DATA["infrastructure"]["dns_records"].append(record)
    
    if source_tool:
        _CURRENT_REPORT_DATA["tools"].add(source_tool)
    
    return f"✅ DNS record added: {record_type} {name} → {value}"


@tool
def add_service_discovery(
    host: str,
    port: int,
    protocol: str,
    service: str,
    version: str | None = None,
    state: str = "open",
    source_tool: str | None = None
) -> str:
    """Add a discovered service/port to the report's infrastructure section.

    Args:
        host: IP address or hostname.
        port: Port number.
        protocol: Protocol (tcp, udp).
        service: Service name (http, ssh, ftp, mysql, etc.).
        version: Service version if detected (e.g., 'Apache httpd 2.4.41').
        state: Port state (open, filtered, closed).
        source_tool: Tool that discovered this service (e.g., 'nmap', 'masscan').
    Returns: Confirmation that service was added.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled. Use enable_report_mode() first."
    
    if "infrastructure" not in _CURRENT_REPORT_DATA:
        _CURRENT_REPORT_DATA["infrastructure"] = {
            "dns_records": [],
            "services": [],
            "technologies": [],
            "network_topology": []
        }
    
    service_entry = {
        "host": host,
        "port": port,
        "protocol": protocol.lower(),
        "service": service,
        "version": version or "Unknown",
        "state": state
    }
    
    # Avoid duplicates (same host:port:protocol)
    existing = [s for s in _CURRENT_REPORT_DATA["infrastructure"]["services"] 
                if s["host"] == host and s["port"] == port and s["protocol"] == protocol.lower()]
    if not existing:
        _CURRENT_REPORT_DATA["infrastructure"]["services"].append(service_entry)
    
    if source_tool:
        _CURRENT_REPORT_DATA["tools"].add(source_tool)
    
    return f"✅ Service added: {host}:{port}/{protocol} ({service} {version or ''})"


@tool
def add_technology_stack(
    technology: str,
    category: str,
    version: str | None = None,
    url: str | None = None,
    source_tool: str | None = None
) -> str:
    """Add an identified technology to the report's infrastructure section.

    Args:
        technology: Technology name (e.g., 'WordPress', 'Apache', 'PHP', 'jQuery').
        category: Category (web_server, framework, cms, language, library, os, database).
        version: Version if detected (e.g., '5.8.1').
        url: URL where technology was detected (optional).
        source_tool: Tool that detected this (e.g., 'whatweb', 'wappalyzer', 'nuclei').
    Returns: Confirmation that technology was added.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled. Use enable_report_mode() first."
    
    if "infrastructure" not in _CURRENT_REPORT_DATA:
        _CURRENT_REPORT_DATA["infrastructure"] = {
            "dns_records": [],
            "services": [],
            "technologies": [],
            "network_topology": []
        }
    
    tech_entry = {
        "technology": technology,
        "category": category,
        "version": version or "Unknown",
        "url": url or _CURRENT_REPORT_DATA.get("target", "N/A")
    }
    
    # Avoid duplicates
    existing = [t for t in _CURRENT_REPORT_DATA["infrastructure"]["technologies"]
                if t["technology"].lower() == technology.lower()]
    if not existing:
        _CURRENT_REPORT_DATA["infrastructure"]["technologies"].append(tech_entry)
    
    if source_tool:
        _CURRENT_REPORT_DATA["tools"].add(source_tool)
    
    return f"✅ Technology added: {technology} ({category}) {version or ''}"


@tool
def add_network_topology(
    source: str,
    destination: str,
    relationship: str,
    details: str | None = None
) -> str:
    """Add a network topology relationship to the report.

    Args:
        source: Source entity (IP, hostname, or service).
        destination: Destination entity (IP, hostname, or service).
        relationship: Relationship type (resolves_to, proxies_to, redirects_to, connects_to, hosts).
        details: Additional details about the relationship.
    Returns: Confirmation that topology entry was added.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled. Use enable_report_mode() first."
    
    if "infrastructure" not in _CURRENT_REPORT_DATA:
        _CURRENT_REPORT_DATA["infrastructure"] = {
            "dns_records": [],
            "services": [],
            "technologies": [],
            "network_topology": []
        }
    
    entry = {
        "source": source,
        "destination": destination,
        "relationship": relationship,
        "details": details or ""
    }
    
    _CURRENT_REPORT_DATA["infrastructure"]["network_topology"].append(entry)
    
    return f"✅ Topology added: {source} → ({relationship}) → {destination}"


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
    timestamp: str | None = None,
    screenshot_type: str = "website"
) -> str:
    """Add a screenshot to the report artifacts section.

    Args:
        url: The URL that was screenshotted.
        base64_data: Base64 encoded PNG image data.
        description: Description of the screenshot (e.g., 'Homepage', 'Login Page').
        timestamp: Optional timestamp when screenshot was taken.
        screenshot_type: Type of screenshot - "website" goes to Artifacts, "exploitation" can be linked to findings.
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
        "timestamp": timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "screenshot_type": screenshot_type  # "website" or "exploitation"
    }
    
    # Only add to _REPORT_ARTIFACTS to avoid duplication
    _REPORT_ARTIFACTS.append(artifact)
    
    return f"✅ Screenshot added to report ({screenshot_type}): {description} ({url})"


@tool
def add_screenshot_to_finding(
    finding_id: int,
    url: str,
    base64_data: str,
    caption: str = "Exploitation Evidence"
) -> str:
    """Add an exploitation screenshot directly to a finding's evidence section.
    
    Use this to add proof-of-concept screenshots that should appear inline with the 
    vulnerability finding, rather than in the general Artifacts section.

    Args:
        finding_id: The ID of the finding to attach the screenshot to.
        url: The URL where the exploitation was performed.
        base64_data: Base64 encoded PNG image data.
        caption: Caption describing what the screenshot shows.
    Returns: Confirmation that screenshot was attached to finding.
    """
    global _REPORT_MODE_ENABLED, _CURRENT_REPORT_DATA
    
    if not _REPORT_MODE_ENABLED:
        return "Report mode is not enabled. Use enable_report_mode() first."
    
    findings = _CURRENT_REPORT_DATA.get("findings", [])
    
    # Find the finding by ID
    for finding in findings:
        if finding.get("id") == finding_id:
            # Initialize screenshots list if not exists
            if "screenshots" not in finding:
                finding["screenshots"] = []
            
            finding["screenshots"].append({
                "url": url,
                "data": base64_data,
                "caption": caption,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
            return f"✅ Screenshot attached to finding #{finding_id}: {caption}"
    
    return f"⚠️ Finding #{finding_id} not found. Available IDs: {[f.get('id') for f in findings]}"


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
    
    # Only add to _REPORT_ARTIFACTS to avoid duplication
    _REPORT_ARTIFACTS.append(artifact)
    
    # Also track the tool
    _CURRENT_REPORT_DATA["tools"].add(tool_name)
    
    return f"✅ Tool output added to report: {filename} ({len(output_data)} bytes)"


def get_report_artifacts() -> list:
    """Get all artifacts for external access."""
    global _REPORT_ARTIFACTS
    return _REPORT_ARTIFACTS.copy()


def _classify_scope_item(item: str) -> str:
    """Classify a scope item as FQDN/URL or Subnet/IP."""
    import re
    item = item.strip()
    # Check for IP address (IPv4)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    # Check for CIDR notation
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    # Check for IP range
    range_pattern = r'^(\d{1,3}\.){3}\d{1,3}\s*-\s*(\d{1,3}\.){3}\d{1,3}$'
    
    if re.match(ip_pattern, item) or re.match(cidr_pattern, item) or re.match(range_pattern, item):
        return "subnet_ip"
    return "fqdn_url"


def _build_scope_table(scope_items: list) -> str:
    """Build HTML table for scope items grouped by type."""
    fqdns_urls = []
    subnets_ips = []
    
    for item in scope_items:
        if _classify_scope_item(item) == "subnet_ip":
            subnets_ips.append(item)
        else:
            fqdns_urls.append(item)
    
    table_html = '<table class="scope-table">'
    table_html += '<thead><tr><th>Type</th><th>Target</th><th>Description</th></tr></thead>'
    table_html += '<tbody>'
    
    # Add FQDNs/URLs section
    if fqdns_urls:
        table_html += f'<tr class="scope-type-header"><td colspan="3">🌐 FQDNs / URLs ({len(fqdns_urls)})</td></tr>'
        for item in fqdns_urls:
            item_type = "URL" if item.startswith(("http://", "https://")) else "FQDN"
            table_html += f'<tr><td>{item_type}</td><td>{item}</td><td>In scope</td></tr>'
    
    # Add Subnets/IPs section
    if subnets_ips:
        table_html += f'<tr class="scope-type-header"><td colspan="3">🔢 Subnets / IP Addresses ({len(subnets_ips)})</td></tr>'
        for item in subnets_ips:
            if "/" in item:
                item_type = "Subnet (CIDR)"
            elif "-" in item:
                item_type = "IP Range"
            else:
                item_type = "IP Address"
            table_html += f'<tr><td>{item_type}</td><td>{item}</td><td>In scope</td></tr>'
    
    if not fqdns_urls and not subnets_ips:
        table_html += '<tr><td colspan="3">No targets specified</td></tr>'
    
    table_html += '</tbody></table>'
    return table_html


def _convert_markdown_to_html(text: str) -> str:
    """Convert common markdown elements to HTML.
    
    Handles: bold (**text**), italic (*text*), inline code (`code`),
    headers (# ## ###), bullet lists (- item), numbered lists (1. item),
    and links ([text](url)).
    """
    if not text:
        return ""
    
    import re
    
    # Escape HTML special characters first (except for intentional HTML)
    # Don't escape < and > as they might be intentional HTML
    text = text.replace('&', '&amp;')
    
    # Convert headers (## Header -> <h3>Header</h3>)
    text = re.sub(r'^#{4}\s+(.+)$', r'<h5>\1</h5>', text, flags=re.MULTILINE)
    text = re.sub(r'^#{3}\s+(.+)$', r'<h4>\1</h4>', text, flags=re.MULTILINE)
    text = re.sub(r'^#{2}\s+(.+)$', r'<h4>\1</h4>', text, flags=re.MULTILINE)
    text = re.sub(r'^#\s+(.+)$', r'<h4>\1</h4>', text, flags=re.MULTILINE)
    
    # Convert bold (**text** or __text__)
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'__(.+?)__', r'<strong>\1</strong>', text)
    
    # Convert italic (*text* or _text_) - but not inside words
    text = re.sub(r'(?<!\w)\*([^*]+)\*(?!\w)', r'<em>\1</em>', text)
    text = re.sub(r'(?<!\w)_([^_]+)_(?!\w)', r'<em>\1</em>', text)
    
    # Convert inline code (`code`)
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
    
    # Convert links ([text](url))
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" target="_blank">\1</a>', text)
    
    # Convert bullet lists (- item or * item at start of line)
    lines = text.split('\n')
    result_lines = []
    in_list = False
    list_type = None
    
    for line in lines:
        stripped = line.strip()
        
        # Check for bullet list item
        bullet_match = re.match(r'^[-*]\s+(.+)$', stripped)
        # Check for numbered list item  
        number_match = re.match(r'^(\d+)[.)]\s+(.+)$', stripped)
        
        if bullet_match:
            if not in_list or list_type != 'ul':
                if in_list:
                    result_lines.append(f'</{list_type}>')
                result_lines.append('<ul>')
                in_list = True
                list_type = 'ul'
            result_lines.append(f'<li>{bullet_match.group(1)}</li>')
        elif number_match:
            if not in_list or list_type != 'ol':
                if in_list:
                    result_lines.append(f'</{list_type}>')
                result_lines.append('<ol>')
                in_list = True
                list_type = 'ol'
            result_lines.append(f'<li>{number_match.group(2)}</li>')
        else:
            if in_list:
                result_lines.append(f'</{list_type}>')
                in_list = False
                list_type = None
            result_lines.append(line)
    
    if in_list:
        result_lines.append(f'</{list_type}>')
    
    return '\n'.join(result_lines)


def _build_executive_summary_html(summary: str, findings: list, severity_counts: dict) -> str:
    """Build structured executive summary HTML with proper formatting."""
    # Convert any markdown in the summary to HTML
    summary = _convert_markdown_to_html(summary)
    
    # Split summary into paragraphs
    paragraphs = [p.strip() for p in summary.split('\n\n') if p.strip()]
    if not paragraphs:
        paragraphs = [summary] if summary else ["This report presents the findings from a security assessment."]
    
    # Build description section
    desc_html = ""
    for p in paragraphs:
        # Check if it's already wrapped in HTML tags
        if p.startswith('<h') or p.startswith('<ul') or p.startswith('<ol') or p.startswith('<p'):
            desc_html += p
        else:
            # Convert single newlines to <br> within paragraphs
            p = p.replace('\n', '<br>')
            desc_html += f"<p>{p}</p>"
    
    # Build key findings bullet list
    key_findings = []
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    sorted_findings = sorted(findings, key=lambda x: severity_order.index(x.get("severity", "Info")) if x.get("severity", "Info") in severity_order else 5)
    
    for f in sorted_findings[:10]:  # Top 10 findings
        sev = f.get("severity", "Info")
        emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Info": "🔵"}.get(sev, "⚪")
        key_findings.append(f"{emoji} <strong>[{sev}]</strong> {f['title']}")
    
    findings_html = ""
    if key_findings:
        findings_html = '''
        <div class="exec-summary-findings">
            <h4>Key Findings</h4>
            <ul>
        '''
        for finding in key_findings:
            findings_html += f"<li>{finding}</li>"
        findings_html += "</ul></div>"
    
    return desc_html + findings_html


def _build_finding_steps_html(steps: str) -> str:
    """Build structured steps to reproduce HTML."""
    if not steps:
        return ""
    
    # Check if already numbered (1. Step or 1) Step format)
    import re
    numbered_pattern = r'^[\d]+[\.\)]\s*'
    
    lines = [l.strip() for l in steps.split('\n') if l.strip()]
    if not lines:
        return f"<p>{steps}</p>"
    
    # Check if lines are numbered
    is_numbered = any(re.match(numbered_pattern, line) for line in lines)
    
    if is_numbered or len(lines) > 1:
        # Build numbered list
        html = '<ol class="steps-list">'
        for line in lines:
            # Remove existing numbers if present
            cleaned = re.sub(numbered_pattern, '', line)
            html += f"<li>{cleaned}</li>"
        html += '</ol>'
        return html
    else:
        return f"<p>{steps}</p>"


def _build_finding_screenshots_html(screenshots: list) -> str:
    """Build HTML for screenshots attached to a finding."""
    if not screenshots:
        return ""
    
    html = '<h4>Exploitation Screenshots</h4>'
    for screenshot in screenshots:
        html += f'''
        <div class="finding-screenshot">
            <img src="data:image/png;base64,{screenshot.get("data", "")}" alt="{screenshot.get("caption", "Screenshot")}">
            <div class="finding-screenshot-caption">
                {screenshot.get("caption", "Exploitation evidence")} - {screenshot.get("url", "")}
            </div>
        </div>
        '''
    
    return html


def _build_finding_references_html(references: str, owasp_cat: str, cwe_id: str) -> str:
    """Build references section HTML for a finding."""
    refs = []
    
    # Add OWASP reference
    if owasp_cat and owasp_cat != "N/A":
        # Extract category ID (e.g., A01 from A01:2021)
        cat_match = owasp_cat.split(":")[0] if ":" in owasp_cat else owasp_cat
        refs.append(f'<a href="https://owasp.org/Top10/{cat_match}/" target="_blank">OWASP Top 10 - {owasp_cat}</a>')
    
    # Add CWE reference
    if cwe_id and cwe_id != "N/A":
        cwe_num = cwe_id.replace("CWE-", "").replace("cwe-", "")
        refs.append(f'<a href="https://cwe.mitre.org/data/definitions/{cwe_num}.html" target="_blank">{cwe_id}</a>')
    
    # Parse custom references
    if references:
        for ref in references.split('\n'):
            ref = ref.strip()
            if ref:
                if ref.startswith(("http://", "https://")):
                    refs.append(f'<a href="{ref}" target="_blank">{ref}</a>')
                elif ref.startswith("CVE-"):
                    refs.append(f'<a href="https://nvd.nist.gov/vuln/detail/{ref}" target="_blank">{ref}</a>')
                else:
                    refs.append(ref)
    
    if not refs:
        return ""
    
    html = '<h4>References</h4><ul class="references-list">'
    for ref in refs:
        html += f"<li>{ref}</li>"
    html += "</ul>"
    return html


def _build_conclusion_html(conclusion: str, findings: list, severity_counts: dict) -> str:
    """Build professional conclusion section HTML."""
    total_findings = sum(severity_counts.values())
    critical_high = severity_counts.get("Critical", 0) + severity_counts.get("High", 0)
    
    # Risk level determination
    if severity_counts.get("Critical", 0) > 0:
        risk_level = "Critical"
        risk_color = "#dc3545"
        risk_text = "The assessment identified critical vulnerabilities that pose an immediate threat to the security of the system."
    elif severity_counts.get("High", 0) > 0:
        risk_level = "High"
        risk_color = "#fd7e14"
        risk_text = "The assessment identified high-severity vulnerabilities that should be addressed as a priority."
    elif severity_counts.get("Medium", 0) > 0:
        risk_level = "Medium"
        risk_color = "#ffc107"
        risk_text = "The assessment identified vulnerabilities of moderate severity that should be remediated in a timely manner."
    else:
        risk_level = "Low"
        risk_color = "#28a745"
        risk_text = "The assessment found primarily low-severity or informational findings. The overall security posture is reasonable."
    
    # Build priority remediation lists
    immediate_actions = []
    short_term_actions = []
    medium_term_actions = []
    long_term_actions = []
    
    for f in findings:
        sev = f.get("severity", "Info")
        item = f"Fix: {f['title']}"
        if sev == "Critical":
            immediate_actions.append(item)
        elif sev == "High":
            short_term_actions.append(item)
        elif sev == "Medium":
            medium_term_actions.append(item)
        else:
            long_term_actions.append(item)
    
    # Parse conclusion text into paragraphs - convert markdown to HTML first
    conclusion_paragraphs = ""
    if conclusion:
        conclusion = _convert_markdown_to_html(conclusion)
        for p in conclusion.split('\n\n'):
            p = p.strip()
            if p:
                # Check if already wrapped in HTML tags
                if p.startswith('<h') or p.startswith('<ul') or p.startswith('<ol') or p.startswith('<p'):
                    conclusion_paragraphs += p
                else:
                    conclusion_paragraphs += f"<p>{p.replace(chr(10), '<br>')}</p>"
    
    html = f'''
    <div class="risk-summary" style="border-color: {risk_color};">
        <strong style="color: {risk_color};">Overall Risk Level: {risk_level}</strong>
        <p style="margin: 0.5rem 0 0 0;">{risk_text}</p>
        <p style="margin: 0.5rem 0 0 0;"><strong>Summary:</strong> {total_findings} total findings identified ({severity_counts.get("Critical", 0)} Critical, {severity_counts.get("High", 0)} High, {severity_counts.get("Medium", 0)} Medium, {severity_counts.get("Low", 0)} Low, {severity_counts.get("Info", 0)} Informational)</p>
    </div>
    
    <h3>Assessment Summary</h3>
    {conclusion_paragraphs if conclusion_paragraphs else "<p>Based on the assessment, the recommendations in this report should be implemented to improve the security posture of the application.</p>"}
    
    <h3>Prioritized Remediation Roadmap</h3>
    <div class="conclusion-grid">
    '''
    
    if immediate_actions:
        html += '''
        <div class="conclusion-card">
            <h4>🚨 Immediate Actions <span class="priority-badge priority-immediate">0-48 hours</span></h4>
            <p style="font-size: 0.9rem; color: #666; margin-bottom: 0.75rem;">Critical issues requiring emergency response</p>
            <ul>
        '''
        for action in immediate_actions[:5]:
            html += f"<li>{action}</li>"
        html += "</ul></div>"
    
    if short_term_actions:
        html += '''
        <div class="conclusion-card">
            <h4>⚠️ Short-Term Actions <span class="priority-badge priority-short">1-2 weeks</span></h4>
            <p style="font-size: 0.9rem; color: #666; margin-bottom: 0.75rem;">High priority issues for immediate sprint</p>
            <ul>
        '''
        for action in short_term_actions[:5]:
            html += f"<li>{action}</li>"
        html += "</ul></div>"
    
    if medium_term_actions:
        html += '''
        <div class="conclusion-card">
            <h4>📋 Medium-Term Actions <span class="priority-badge priority-medium">1-3 months</span></h4>
            <p style="font-size: 0.9rem; color: #666; margin-bottom: 0.75rem;">Moderate issues for planned remediation</p>
            <ul>
        '''
        for action in medium_term_actions[:5]:
            html += f"<li>{action}</li>"
        html += "</ul></div>"
    
    if long_term_actions:
        html += '''
        <div class="conclusion-card">
            <h4>📝 Long-Term Improvements <span class="priority-badge priority-long">3-6 months</span></h4>
            <p style="font-size: 0.9rem; color: #666; margin-bottom: 0.75rem;">Low priority enhancements and best practices</p>
            <ul>
        '''
        for action in long_term_actions[:5]:
            html += f"<li>{action}</li>"
        html += "</ul></div>"
    
    # Add general recommendations
    html += '''
    </div>
    
    <h3>General Recommendations</h3>
    <ul>
        <li><strong>Establish a Vulnerability Management Program:</strong> Implement regular security assessments and vulnerability scanning</li>
        <li><strong>Security Awareness Training:</strong> Conduct regular security training for development and operations teams</li>
        <li><strong>Secure Development Lifecycle:</strong> Integrate security testing into CI/CD pipelines</li>
        <li><strong>Incident Response Plan:</strong> Ensure a documented and tested incident response procedure is in place</li>
        <li><strong>Regular Patching:</strong> Maintain an aggressive patching schedule for all systems and dependencies</li>
    </ul>
    '''
    
    return html


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
    
    # Build scope table (grouped by type)
    scope_items = data.get("scope", [])
    scope_table = _build_scope_table(scope_items)
    
    # Build executive summary HTML (structured with findings list)
    exec_summary_html = _build_executive_summary_html(
        data.get("executive_summary", ""),
        data.get("findings", []),
        severity_counts
    )
    
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
    infrastructure = data.get("infrastructure", {})
    recon_section = ""
    
    has_recon_data = bool(recon_data or infrastructure.get("dns_records") or 
                         infrastructure.get("services") or infrastructure.get("technologies"))
    
    if has_recon_data:
        recon_content = ""
        
        # Infrastructure: DNS Records Table
        dns_records = infrastructure.get("dns_records", [])
        if dns_records:
            dns_rows = ""
            for rec in sorted(dns_records, key=lambda x: (x["type"], x["name"])):
                dns_rows += f'<tr><td>{rec["type"]}</td><td>{rec["name"]}</td><td><code>{rec["value"]}</code></td><td>{rec["ttl"]}</td></tr>'
            
            recon_content += f'''
            <div class="infrastructure-table">
                <h3>🌐 DNS Records</h3>
                <table>
                    <thead><tr><th>Type</th><th>Name</th><th>Value</th><th>TTL</th></tr></thead>
                    <tbody>{dns_rows}</tbody>
                </table>
            </div>
            '''
        
        # Infrastructure: Services/Ports Table
        services = infrastructure.get("services", [])
        if services:
            svc_rows = ""
            for svc in sorted(services, key=lambda x: (x["host"], x["port"])):
                state_class = "open" if svc["state"] == "open" else "filtered"
                svc_rows += f'<tr><td>{svc["host"]}</td><td>{svc["port"]}</td><td>{svc["protocol"].upper()}</td><td>{svc["service"]}</td><td>{svc["version"]}</td><td class="port-{state_class}">{svc["state"]}</td></tr>'
            
            recon_content += f'''
            <div class="infrastructure-table">
                <h3>🔌 Discovered Services</h3>
                <table>
                    <thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>State</th></tr></thead>
                    <tbody>{svc_rows}</tbody>
                </table>
            </div>
            '''
        
        # Infrastructure: Technology Stack
        technologies = infrastructure.get("technologies", [])
        if technologies:
            tech_rows = ""
            for tech in sorted(technologies, key=lambda x: x["category"]):
                tech_rows += f'<tr><td>{tech["technology"]}</td><td>{tech["category"].replace("_", " ").title()}</td><td>{tech["version"]}</td><td><code>{tech["url"]}</code></td></tr>'
            
            recon_content += f'''
            <div class="infrastructure-table">
                <h3>💻 Technology Stack</h3>
                <table>
                    <thead><tr><th>Technology</th><th>Category</th><th>Version</th><th>Detected On</th></tr></thead>
                    <tbody>{tech_rows}</tbody>
                </table>
            </div>
            '''
        
        # Infrastructure: Network Topology
        topology = infrastructure.get("network_topology", [])
        if topology:
            topo_rows = ""
            for entry in topology:
                topo_rows += f'<tr><td>{entry["source"]}</td><td>{entry["relationship"]}</td><td>{entry["destination"]}</td><td>{entry.get("details", "")}</td></tr>'
            
            recon_content += f'''
            <div class="infrastructure-table">
                <h3>🗺️ Network Topology</h3>
                <table>
                    <thead><tr><th>Source</th><th>Relationship</th><th>Destination</th><th>Details</th></tr></thead>
                    <tbody>{topo_rows}</tbody>
                </table>
            </div>
            '''
        
        # Recon Data Cards (subdomains, emails, IPs, etc.)
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
            
            recon_content += f'''
            <h3>📊 Collected Data</h3>
            <div class="recon-data-grid">
                {recon_cards}
            </div>
            '''
        
        recon_section = f'''
        <div class="section recon-section">
            <h2>
                <span class="section-icon">📡</span>
                Reconnaissance & Infrastructure
            </h2>
            <p>The following information was discovered during the reconnaissance and enumeration phases:</p>
            {recon_content}
        </div>
        '''
    
    # Build findings HTML with improved structure
    findings_html = ""
    for f in sorted(data.get("findings", []), key=lambda x: ["Critical", "High", "Medium", "Low", "Info"].index(x.get("severity", "Info"))):
        sev_class = f.get("severity", "Info").lower()
        
        # Build steps to reproduce HTML
        steps_html = _build_finding_steps_html(f.get("steps_to_reproduce", ""))
        if steps_html:
            steps_html = f"<h4>Steps to Reproduce</h4>{steps_html}"
        
        # Build command used HTML - normalize tool name for display
        command_html = ""
        if f.get("command_used"):
            tool_display_name = normalize_tool_name(f.get("tool_used", "Tool"))
            command_html = f'''
            <h4>Command Executed</h4>
            <div class="command-block">
                <div class="command-label"># {tool_display_name} command</div>
                {f["command_used"]}
            </div>
            '''
        
        # Build references HTML
        references_html = _build_finding_references_html(
            f.get("references", ""),
            f.get("owasp_category", ""),
            f.get("cwe_id", "")
        )
        
        findings_html += f'''
        <div class="finding">
            <div class="finding-header {sev_class}">
                <span class="finding-title">#{f['id']}: {f['title']}</span>
                <span class="tag">{f['severity']}</span>
                <span class="tag">{f['owasp_category']}</span>
                {f'<span class="tag">{f["cwe_id"]}</span>' if f.get("cwe_id") and f["cwe_id"] != "N/A" else ""}
            </div>
            <div class="finding-body">
                <h4>Description</h4>
                <p>{f['description']}</p>
                
                <h4>Affected Component</h4>
                <p><code>{f['affected_component']}</code></p>
                
                <h4>Impact</h4>
                <p>{f['impact']}</p>
                
                {"<h4>Evidence / Proof of Concept</h4><pre>" + f['evidence'] + "</pre>" if f.get('evidence') else ""}
                
                {_build_finding_screenshots_html(f.get('screenshots', []))}
                
                {steps_html}
                
                {command_html}
                
                <h4>Remediation</h4>
                <p>{f['remediation']}</p>
                
                {references_html}
                
                <h4>Technical Details</h4>
                <table>
                    <tr><th>CVSS Score</th><td>{f['cvss_score']}</td></tr>
                    <tr><th>CWE ID</th><td>{f.get('cwe_id', 'N/A')}</td></tr>
                    <tr><th>Tool Used</th><td>{normalize_tool_name(f['tool_used'])}</td></tr>
                </table>
            </div>
        </div>
        '''
    
    # Build general references
    references_list_html = """
        <li><a href="https://owasp.org/Top10/">OWASP Top 10 (2021)</a></li>
        <li><a href="https://owasp.org/www-project-web-security-testing-guide/">OWASP Web Security Testing Guide (WSTG)</a></li>
        <li><a href="https://owasp.org/www-project-application-security-verification-standard/">OWASP Application Security Verification Standard (ASVS)</a></li>
        <li><a href="https://owasp.org/API-Security/">OWASP API Security Top 10</a></li>
        <li><a href="https://cwe.mitre.org/">CWE - Common Weakness Enumeration</a></li>
        <li><a href="https://nvd.nist.gov/">NIST National Vulnerability Database</a></li>
        <li><a href="https://www.first.org/cvss/calculator/3.1">CVSS v3.1 Calculator</a></li>
    """
    
    # Build artifacts section - only include "website" screenshots and tool outputs
    # Exploitation screenshots are embedded in findings
    artifacts = _REPORT_ARTIFACTS
    artifacts_section = ""
    
    # Filter artifacts: website screenshots and tool outputs go to Artifacts section
    filtered_artifacts = [
        a for a in artifacts 
        if a.get("type") == "tool_output" or 
           (a.get("type") == "screenshot" and a.get("screenshot_type", "website") == "website")
    ]
    
    if filtered_artifacts:
        artifacts_html = ""
        for artifact in filtered_artifacts:
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
            <h2>
                <span class="section-icon">📦</span>
                Artifacts
            </h2>
            <p>Screenshots and raw tool outputs collected during the assessment:</p>
            <div class="artifacts-grid">
                {artifacts_html}
            </div>
        </div>
        '''
    
    # Build conclusion HTML (professional structure)
    conclusion_html = _build_conclusion_html(
        data.get("conclusion", ""),
        data.get("findings", []),
        severity_counts
    )
    
    # Replace placeholders
    html = template
    html = html.replace("{{title}}", data.get("title", "Security Assessment Report"))
    html = html.replace("{{subtitle}}", data.get("subtitle", "Penetration Test Report"))
    html = html.replace("{{target}}", data.get("target", "N/A"))
    html = html.replace("{{date}}", data.get("date", datetime.now().strftime("%Y-%m-%d")))
    html = html.replace("{{author}}", data.get("author", "Pentest.Systems Assistant"))
    html = html.replace("{{executive_summary_html}}", exec_summary_html)
    html = html.replace("{{critical_count}}", str(severity_counts["Critical"]))
    html = html.replace("{{high_count}}", str(severity_counts["High"]))
    html = html.replace("{{medium_count}}", str(severity_counts["Medium"]))
    html = html.replace("{{low_count}}", str(severity_counts["Low"]))
    html = html.replace("{{info_count}}", str(severity_counts["Info"]))
    
    # Calculate percentages for bar chart
    total_findings = sum(severity_counts.values())
    if total_findings > 0:
        critical_pct = max(5, int((severity_counts["Critical"] / total_findings) * 100)) if severity_counts["Critical"] > 0 else 0
        high_pct = max(5, int((severity_counts["High"] / total_findings) * 100)) if severity_counts["High"] > 0 else 0
        medium_pct = max(5, int((severity_counts["Medium"] / total_findings) * 100)) if severity_counts["Medium"] > 0 else 0
        low_pct = max(5, int((severity_counts["Low"] / total_findings) * 100)) if severity_counts["Low"] > 0 else 0
        info_pct = max(5, int((severity_counts["Info"] / total_findings) * 100)) if severity_counts["Info"] > 0 else 0
    else:
        critical_pct = high_pct = medium_pct = low_pct = info_pct = 0
    
    html = html.replace("{{critical_percent}}", str(critical_pct))
    html = html.replace("{{high_percent}}", str(high_pct))
    html = html.replace("{{medium_percent}}", str(medium_pct))
    html = html.replace("{{low_percent}}", str(low_pct))
    html = html.replace("{{info_percent}}", str(info_pct))
    
    html = html.replace("{{scope_table}}", scope_table)
    html = html.replace("{{methodology}}", data.get("methodology", ""))
    html = html.replace("{{recon_section}}", recon_section)
    html = html.replace("{{tools_used}}", tools_html or '<div class="tool-card"><div class="tool-icon">🛠️</div><div class="tool-name">Manual Testing</div></div>')
    html = html.replace("{{findings_html}}", findings_html or "<p>No findings recorded.</p>")
    html = html.replace("{{conclusion_html}}", conclusion_html)
    html = html.replace("{{artifacts_section}}", artifacts_section)
    html = html.replace("{{references}}", references_list_html)
    
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
    lines.append(f"- **Author:** {data.get('author', 'Pentest.Systems Assistant')}")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Executive Summary with structured format
    lines.append("## Executive Summary")
    lines.append("")
    
    # Description paragraphs
    exec_summary = data.get("executive_summary", "This report presents findings from a security assessment.")
    for paragraph in exec_summary.split('\n\n'):
        if paragraph.strip():
            lines.append(paragraph.strip())
            lines.append("")
    
    # Key Findings bullet list
    lines.append("### Key Findings")
    lines.append("")
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    sorted_findings = sorted(
        data.get("findings", []),
        key=lambda x: severity_order.index(x.get("severity", "Info")) if x.get("severity", "Info") in severity_order else 5
    )
    for f in sorted_findings[:10]:
        sev = f.get("severity", "Info")
        emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Info": "🔵"}.get(sev, "⚪")
        lines.append(f"- {emoji} **[{sev}]** {f['title']}")
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
    
    # Scope with table format
    lines.append("## Scope & Methodology")
    lines.append("")
    lines.append("### Targets in Scope")
    lines.append("")
    
    scope_items = data.get("scope", [])
    if scope_items:
        # Classify scope items
        fqdns_urls = []
        subnets_ips = []
        import re
        for item in scope_items:
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
            if re.match(ip_pattern, item.strip()) or '-' in item and re.match(r'^(\d{1,3}\.){3}\d{1,3}', item):
                subnets_ips.append(item)
            else:
                fqdns_urls.append(item)
        
        lines.append("| Type | Target | Description |")
        lines.append("|------|--------|-------------|")
        
        if fqdns_urls:
            lines.append(f"| **🌐 FQDNs / URLs** | | *{len(fqdns_urls)} items* |")
            for item in fqdns_urls:
                item_type = "URL" if item.startswith(("http://", "https://")) else "FQDN"
                lines.append(f"| {item_type} | `{item}` | In scope |")
        
        if subnets_ips:
            lines.append(f"| **🔢 Subnets / IPs** | | *{len(subnets_ips)} items* |")
            for item in subnets_ips:
                if "/" in item:
                    item_type = "Subnet"
                elif "-" in item:
                    item_type = "Range"
                else:
                    item_type = "IP"
                lines.append(f"| {item_type} | `{item}` | In scope |")
    else:
        lines.append("*(No scope items specified)*")
    
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
    
    # Findings with improved structure
    lines.append("## Detailed Findings")
    lines.append("")
    
    for f in sorted_findings:
        sev_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Info": "🔵"}.get(f.get("severity"), "⚪")
        lines.append(f"### {sev_emoji} {f['id']}. {f['title']}")
        lines.append("")
        
        # Header with all identifiers
        cwe_display = f" | **CWE:** {f.get('cwe_id')}" if f.get('cwe_id') and f.get('cwe_id') != 'N/A' else ""
        lines.append(f"**Severity:** {f.get('severity', 'N/A')} | **OWASP:** {f.get('owasp_category', 'N/A')} | **CVSS:** {f.get('cvss_score', 'N/A')}{cwe_display}")
        lines.append("")
        
        lines.append("#### Description")
        lines.append(f.get("description", ""))
        lines.append("")
        
        lines.append("#### Affected Component")
        lines.append(f"`{f.get('affected_component', 'N/A')}`")
        lines.append("")
        
        lines.append("#### Impact")
        lines.append(f.get("impact", ""))
        lines.append("")
        
        if f.get("evidence"):
            lines.append("#### Evidence / Proof of Concept")
            lines.append("```")
            lines.append(f.get("evidence", ""))
            lines.append("```")
            lines.append("")
        
        # Structured steps to reproduce
        if f.get("steps_to_reproduce"):
            lines.append("#### Steps to Reproduce")
            steps = f.get("steps_to_reproduce", "")
            step_lines = [s.strip() for s in steps.split('\n') if s.strip()]
            for i, step in enumerate(step_lines, 1):
                # Remove existing numbering if present
                import re
                cleaned = re.sub(r'^[\d]+[\.\)]\s*', '', step)
                lines.append(f"{i}. {cleaned}")
            lines.append("")
        
        # Command used - normalize tool name for display
        if f.get("command_used"):
            tool_display_name = normalize_tool_name(f.get("tool_used", "Tool"))
            lines.append("#### Command Executed")
            lines.append("```bash")
            lines.append(f"# {tool_display_name} command")
            lines.append(f.get("command_used", ""))
            lines.append("```")
            lines.append("")
        
        lines.append("#### Remediation")
        lines.append(f.get("remediation", ""))
        lines.append("")
        
        # References section
        refs = []
        owasp_cat = f.get("owasp_category", "")
        if owasp_cat and owasp_cat != "N/A":
            cat_id = owasp_cat.split(":")[0] if ":" in owasp_cat else owasp_cat
            refs.append(f"- [OWASP Top 10 - {owasp_cat}](https://owasp.org/Top10/{cat_id}/)")
        
        cwe_id = f.get("cwe_id", "")
        if cwe_id and cwe_id != "N/A":
            cwe_num = cwe_id.replace("CWE-", "").replace("cwe-", "")
            refs.append(f"- [{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)")
        
        if f.get("references"):
            for ref in f.get("references", "").split('\n'):
                ref = ref.strip()
                if ref:
                    if ref.startswith(("http://", "https://")):
                        refs.append(f"- [{ref}]({ref})")
                    elif ref.startswith("CVE-"):
                        refs.append(f"- [{ref}](https://nvd.nist.gov/vuln/detail/{ref})")
                    else:
                        refs.append(f"- {ref}")
        
        if refs:
            lines.append("#### References")
            lines.extend(refs)
            lines.append("")
        
        lines.append(f"*Tool Used: {normalize_tool_name(f.get('tool_used', 'Manual Testing'))}*")
        lines.append("")
        lines.append("---")
        lines.append("")
    
    # Professional Conclusion section
    lines.append("## Conclusion & Recommendations")
    lines.append("")
    
    # Risk level determination
    total_findings = sum(severity_counts.values())
    if severity_counts.get("Critical", 0) > 0:
        risk_level = "🔴 **Critical**"
        risk_text = "The assessment identified critical vulnerabilities that pose an immediate threat to the security of the system."
    elif severity_counts.get("High", 0) > 0:
        risk_level = "🟠 **High**"
        risk_text = "The assessment identified high-severity vulnerabilities that should be addressed as a priority."
    elif severity_counts.get("Medium", 0) > 0:
        risk_level = "🟡 **Medium**"
        risk_text = "The assessment identified vulnerabilities of moderate severity that should be remediated in a timely manner."
    else:
        risk_level = "🟢 **Low**"
        risk_text = "The assessment found primarily low-severity or informational findings."
    
    lines.append(f"### Overall Risk Level: {risk_level}")
    lines.append("")
    lines.append(risk_text)
    lines.append("")
    lines.append(f"**Summary:** {total_findings} total findings ({severity_counts.get('Critical', 0)} Critical, {severity_counts.get('High', 0)} High, {severity_counts.get('Medium', 0)} Medium, {severity_counts.get('Low', 0)} Low, {severity_counts.get('Info', 0)} Informational)")
    lines.append("")
    
    # Assessment summary (custom conclusion text)
    lines.append("### Assessment Summary")
    lines.append("")
    conclusion = data.get("conclusion", "Based on the assessment, the recommendations in this report should be implemented to improve the security posture of the application.")
    for paragraph in conclusion.split('\n\n'):
        if paragraph.strip():
            lines.append(paragraph.strip())
            lines.append("")
    
    # Prioritized remediation roadmap
    lines.append("### Prioritized Remediation Roadmap")
    lines.append("")
    
    immediate = [f for f in sorted_findings if f.get("severity") == "Critical"]
    short_term = [f for f in sorted_findings if f.get("severity") == "High"]
    medium_term = [f for f in sorted_findings if f.get("severity") == "Medium"]
    long_term = [f for f in sorted_findings if f.get("severity") in ["Low", "Info"]]
    
    if immediate:
        lines.append("#### 🚨 Immediate Actions (0-48 hours)")
        lines.append("*Critical issues requiring emergency response*")
        lines.append("")
        for f in immediate[:5]:
            lines.append(f"- Fix: {f['title']}")
        lines.append("")
    
    if short_term:
        lines.append("#### ⚠️ Short-Term Actions (1-2 weeks)")
        lines.append("*High priority issues for immediate sprint*")
        lines.append("")
        for f in short_term[:5]:
            lines.append(f"- Fix: {f['title']}")
        lines.append("")
    
    if medium_term:
        lines.append("#### 📋 Medium-Term Actions (1-3 months)")
        lines.append("*Moderate issues for planned remediation*")
        lines.append("")
        for f in medium_term[:5]:
            lines.append(f"- Fix: {f['title']}")
        lines.append("")
    
    if long_term:
        lines.append("#### 📝 Long-Term Improvements (3-6 months)")
        lines.append("*Low priority enhancements and best practices*")
        lines.append("")
        for f in long_term[:5]:
            lines.append(f"- Fix: {f['title']}")
        lines.append("")
    
    # General recommendations
    lines.append("### General Recommendations")
    lines.append("")
    lines.append("- **Establish a Vulnerability Management Program:** Implement regular security assessments and vulnerability scanning")
    lines.append("- **Security Awareness Training:** Conduct regular security training for development and operations teams")
    lines.append("- **Secure Development Lifecycle:** Integrate security testing into CI/CD pipelines")
    lines.append("- **Incident Response Plan:** Ensure a documented and tested incident response procedure is in place")
    lines.append("- **Regular Patching:** Maintain an aggressive patching schedule for all systems and dependencies")
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
    
    # Artifacts Section - use only _REPORT_ARTIFACTS to avoid duplication
    artifacts = _REPORT_ARTIFACTS
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
    lines.append(f"*Report generated by Pentest.Systems Assistant on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
    
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
