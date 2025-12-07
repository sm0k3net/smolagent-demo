"""
Multi-Agent System for OWASP Penetration Testing

This module provides specialized sub-agents that the main OWASP agent can delegate
tasks to. Each sub-agent is optimized for specific phases of a penetration test.

Architecture:
- Main Agent (Orchestrator): Coordinates the pentest, delegates complex tasks
- Recon Agent: Handles reconnaissance and information gathering
- Vulnerability Agent: Runs vulnerability scans and analysis
- Exploitation Agent: Handles exploitation and validation
- Reporting Agent: Generates reports and documentation

The main agent can spawn sub-agents on demand for parallel processing or
to handle specialized tasks that require focused attention.
"""
from __future__ import annotations
import threading
import queue
import json
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from smolagents import CodeAgent, OpenAIServerModel, tool

# Global state for sub-agent management
_SUB_AGENT_RESULTS: Dict[str, Any] = {}
_SUB_AGENT_STATUS: Dict[str, str] = {}
_SUB_AGENT_LOCK = threading.Lock()


class SubAgentType(Enum):
    """Types of specialized sub-agents available."""
    RECON = "recon"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    CUSTOM = "custom"


@dataclass
class SubAgentTask:
    """Represents a task delegated to a sub-agent."""
    task_id: str
    agent_type: SubAgentType
    task_description: str
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    result: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None


# Specialized prompts for each sub-agent type
RECON_AGENT_PROMPT = """You are a specialized Reconnaissance Sub-Agent. Your ONLY job is information gathering.

## Your Capabilities:
- Subdomain enumeration (subfinder, crt.sh, amass)
- DNS reconnaissance (dns_lookup, dnsrecon)
- Technology fingerprinting (whatweb, httpx)
- WHOIS lookups
- Certificate transparency searches
- Port scanning (nmap)

## Your Output Format:
Return a structured summary of ALL discovered information:
```
=== RECONNAISSANCE RESULTS ===
Target: [target]

SUBDOMAINS FOUND:
- subdomain1.target.com
- subdomain2.target.com

TECHNOLOGIES DETECTED:
- Web Server: nginx 1.19.0
- Backend: PHP 7.4
- CMS: WordPress 5.8

DNS RECORDS:
- A: 1.2.3.4
- MX: mail.target.com
- TXT: [SPF records, etc.]

OPEN PORTS:
- 80/tcp - HTTP
- 443/tcp - HTTPS
- 22/tcp - SSH

CERTIFICATES:
- Issuer: Let's Encrypt
- Valid until: 2024-01-01

WHOIS:
- Registrar: GoDaddy
- Created: 2020-01-01
===========================
```

## Rules:
1. Run ALL reconnaissance tools, not just one or two
2. Collect EVERYTHING - don't filter or summarize during collection
3. Return raw data that can be used for further analysis
4. Do NOT attempt exploitation - that's not your job
5. Do NOT generate reports - just collect data
"""

VULNERABILITY_AGENT_PROMPT = """You are a specialized Vulnerability Scanning Sub-Agent. Your ONLY job is finding vulnerabilities.

## Your Capabilities:
- Web vulnerability scanning (nikto, nuclei, ZAP)
- SQL injection testing (sqlmap)
- XSS testing (xsser)
- Directory enumeration (gobuster, ffuf)
- SSL/TLS analysis (sslyze, testssl)
- CMS-specific scanning (wpscan)

## Your Output Format:
Return a structured list of ALL findings:
```
=== VULNERABILITY SCAN RESULTS ===
Target: [target]

CRITICAL FINDINGS:
1. [Finding Title]
   - Type: SQL Injection
   - Location: /search.php?query=
   - Evidence: [raw scanner output]
   - Tool: sqlmap

HIGH FINDINGS:
1. [Finding Title]
   - Type: Remote Code Execution
   - Location: /upload.php
   - Evidence: [raw scanner output]
   - Tool: nuclei

MEDIUM FINDINGS:
[...]

LOW FINDINGS:
[...]

INFO FINDINGS:
[...]

RAW TOOL OUTPUTS:
--- nikto ---
[full nikto output]

--- nuclei ---
[full nuclei output]

--- gobuster ---
[full gobuster output]
================================
```

## Rules:
1. Run ALL vulnerability scanners, not just one
2. Use multiple nuclei template categories
3. Test all parameters for injection
4. Include RAW tool outputs for evidence
5. Do NOT attempt exploitation - just detection
6. Do NOT generate final reports
"""

EXPLOITATION_AGENT_PROMPT = """You are a specialized Exploitation Sub-Agent. Your ONLY job is validating and exploiting confirmed vulnerabilities.

## Your Capabilities:
- SQL injection exploitation (sqlmap --dump)
- File inclusion exploitation
- Command injection testing
- Default credential testing
- CVE exploitation (searchsploit, exploit-db)
- Manual exploitation with curl

## Your Input:
You will receive a list of vulnerabilities to validate and exploit.

## Your Output Format:
Return exploitation results:
```
=== EXPLOITATION RESULTS ===
Target: [target]

EXPLOITED VULNERABILITIES:

1. SQL Injection - /search.php
   - Status: CONFIRMED EXPLOITABLE
   - Impact: Full database access
   - Extracted Data:
     - Database: wordpress_db
     - Tables: wp_users, wp_posts
     - Users: admin (hash: $P$B...)
   - Proof: [screenshot path or command output]

2. Local File Inclusion - /page.php?file=
   - Status: CONFIRMED EXPLOITABLE
   - Impact: Read arbitrary files
   - Extracted: /etc/passwd content
   - Proof: [file content]

FAILED EXPLOITATION ATTEMPTS:

1. XSS - /comment.php
   - Status: BLOCKED by WAF
   - Notes: CSP prevents script execution

=============================
```

## Rules:
1. ONLY exploit vulnerabilities you've been given
2. Document EVERY exploitation attempt
3. Take screenshots of successful exploits
4. Extract proof-of-concept data (usernames, file contents)
5. Note any defensive measures encountered
6. Do NOT perform reconnaissance - use provided data
"""

REPORTING_AGENT_PROMPT = """You are a specialized Reporting Sub-Agent. Your ONLY job is generating professional reports.

## Your Capabilities:
- Report generation (HTML, Markdown, PDF)
- Finding documentation
- Executive summary writing
- Remediation recommendations
- Screenshot attachment

## Your Input:
You will receive:
- Reconnaissance data
- Vulnerability findings
- Exploitation results

## Your Tasks:
1. Call enable_report_mode() with proper title
2. Add ALL findings with add_finding_to_report()
3. Write a comprehensive executive summary
4. Write detailed conclusions and recommendations
5. Attach all screenshots and tool outputs
6. Generate the final HTML report

## Rules:
1. Include EVERY finding, don't skip any
2. Write professional, client-ready text
3. Include specific remediation guidance
4. Attach ALL evidence
5. Ensure report is complete before finishing
"""


def get_sub_agent_prompt(agent_type: SubAgentType) -> str:
    """Get the specialized prompt for a sub-agent type."""
    prompts = {
        SubAgentType.RECON: RECON_AGENT_PROMPT,
        SubAgentType.VULNERABILITY: VULNERABILITY_AGENT_PROMPT,
        SubAgentType.EXPLOITATION: EXPLOITATION_AGENT_PROMPT,
        SubAgentType.REPORTING: REPORTING_AGENT_PROMPT,
    }
    return prompts.get(agent_type, "You are a helpful security assistant.")


def get_sub_agent_tools(agent_type: SubAgentType) -> list:
    """Get the tool set for a specific sub-agent type."""
    
    # Import tools based on agent type to avoid circular imports
    tools = []
    
    if agent_type == SubAgentType.RECON:
        from app.tools.osint_tools import (
            dns_lookup, whois_lookup, crt_sh_search, duckduckgo_search,
        )
        from app.tools.pentest_tools import (
            subfinder_scan, httpx_probe, whatweb_scan, dnsrecon_scan,
            amass_enum, amass_intel,
        )
        from app.tools.nmap_tool import nmap_scan
        from app.tools.virustotal_tools import (
            virustotal_subdomains, virustotal_domain_analysis,
        )
        from app.tools.curl_tool import curl_request
        
        tools = [
            dns_lookup, whois_lookup, crt_sh_search, duckduckgo_search,
            subfinder_scan, httpx_probe, whatweb_scan, dnsrecon_scan,
            amass_enum, amass_intel, nmap_scan,
            virustotal_subdomains, virustotal_domain_analysis,
            curl_request,
        ]
        
    elif agent_type == SubAgentType.VULNERABILITY:
        from app.tools.pentest_tools import (
            nikto_scan, nuclei_scan, gobuster_scan, ffuf_scan,
            sslyze_scan, testssl_scan, sqlmap_scan, xsser_scan,
            wpscan_full,
        )
        from app.tools.zap_tools import (
            zap_spider_scan, zap_active_scan, zap_get_alerts,
        )
        from app.tools.curl_tool import curl_request
        from app.tools.playwright_tool import get_page_forms, get_page_links
        
        tools = [
            nikto_scan, nuclei_scan, gobuster_scan, ffuf_scan,
            sslyze_scan, testssl_scan, sqlmap_scan, xsser_scan,
            wpscan_full, zap_spider_scan, zap_active_scan, zap_get_alerts,
            curl_request, get_page_forms, get_page_links,
        ]
        
    elif agent_type == SubAgentType.EXPLOITATION:
        from app.tools.pentest_tools import (
            sqlmap_scan, sqlmap_dump, searchsploit_search, searchsploit_examine,
            run_exploit, msfconsole_command, exploit_db_search, download_exploit,
            hydra_brute_force, hydra_http_form_brute,
        )
        from app.tools.curl_tool import curl_request
        from app.tools.playwright_tool import (
            browse_page, take_screenshot, fill_form,
        )
        
        tools = [
            sqlmap_scan, sqlmap_dump, searchsploit_search, searchsploit_examine,
            run_exploit, msfconsole_command, exploit_db_search, download_exploit,
            hydra_brute_force, hydra_http_form_brute,
            curl_request, browse_page, take_screenshot, fill_form,
        ]
        
    elif agent_type == SubAgentType.REPORTING:
        from app.tools.report_tools import (
            enable_report_mode, add_finding_to_report, set_executive_summary,
            set_conclusion, add_screenshot_to_report, add_tool_output_to_report,
            generate_html_report, add_recon_data,
        )
        from app.tools.playwright_tool import take_screenshot
        
        tools = [
            enable_report_mode, add_finding_to_report, set_executive_summary,
            set_conclusion, add_screenshot_to_report, add_tool_output_to_report,
            generate_html_report, add_recon_data, take_screenshot,
        ]
    
    return tools


def build_sub_agent(
    agent_type: SubAgentType,
    custom_prompt: Optional[str] = None,
    max_steps: int = 50
) -> CodeAgent:
    """Build a specialized sub-agent for a specific task type.
    
    Args:
        agent_type: Type of sub-agent to create.
        custom_prompt: Optional custom instructions (for CUSTOM type).
        max_steps: Maximum steps the sub-agent can take.
        
    Returns:
        Configured CodeAgent instance.
    """
    from app.config import get_settings
    from app.agents.owasp_agent import build_model
    
    # Build model using same configuration as main agent
    model = build_model()
    
    # Get appropriate prompt and tools
    if agent_type == SubAgentType.CUSTOM and custom_prompt:
        prompt = custom_prompt
        # For custom agents, include all tools
        tools = get_sub_agent_tools(SubAgentType.VULNERABILITY)  # Default to vuln tools
    else:
        prompt = get_sub_agent_prompt(agent_type)
        tools = get_sub_agent_tools(agent_type)
    
    # Create the sub-agent with limited steps to prevent runaway execution
    agent = CodeAgent(
        tools=tools,
        model=model,
        instructions=prompt,
        max_print_outputs_length=15000,  # Slightly smaller than main agent
        max_steps=max_steps,
    )
    
    return agent


def run_sub_agent_sync(
    agent_type: SubAgentType,
    task: str,
    context: Optional[str] = None,
    max_steps: int = 50
) -> str:
    """Run a sub-agent synchronously and return its result.
    
    Args:
        agent_type: Type of sub-agent to use.
        task: Task description for the sub-agent.
        context: Optional additional context (e.g., previous findings).
        max_steps: Maximum steps allowed.
        
    Returns:
        Sub-agent's final response.
    """
    agent = build_sub_agent(agent_type, max_steps=max_steps)
    
    # Build full prompt with context
    full_prompt = task
    if context:
        full_prompt = f"""## Context from Previous Phases:
{context}

## Your Task:
{task}"""
    
    try:
        result = agent.run(full_prompt)
        return str(result)
    except Exception as e:
        return f"Sub-agent error: {type(e).__name__}: {str(e)}"


def run_sub_agent_async(
    task_id: str,
    agent_type: SubAgentType,
    task: str,
    context: Optional[str] = None,
    max_steps: int = 50
) -> None:
    """Run a sub-agent in a background thread.
    
    Results are stored in _SUB_AGENT_RESULTS with the task_id as key.
    
    Args:
        task_id: Unique identifier for this task.
        agent_type: Type of sub-agent to use.
        task: Task description.
        context: Optional context from previous phases.
        max_steps: Maximum steps allowed.
    """
    def worker():
        with _SUB_AGENT_LOCK:
            _SUB_AGENT_STATUS[task_id] = "running"
        
        try:
            result = run_sub_agent_sync(agent_type, task, context, max_steps)
            with _SUB_AGENT_LOCK:
                _SUB_AGENT_RESULTS[task_id] = result
                _SUB_AGENT_STATUS[task_id] = "completed"
        except Exception as e:
            with _SUB_AGENT_LOCK:
                _SUB_AGENT_RESULTS[task_id] = f"Error: {str(e)}"
                _SUB_AGENT_STATUS[task_id] = "failed"
    
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()


# ============================================================================
# TOOLS FOR MAIN AGENT TO DELEGATE TO SUB-AGENTS
# ============================================================================

@tool
def delegate_reconnaissance(target: str, scope: str = "full") -> str:
    """Delegate reconnaissance phase to a specialized Recon Sub-Agent.
    
    The Recon Sub-Agent will perform comprehensive information gathering including:
    - Subdomain enumeration (subfinder, crt.sh, amass)
    - DNS reconnaissance
    - Technology fingerprinting
    - Port scanning
    - WHOIS lookups
    - Certificate transparency searches
    
    Args:
        target: Target domain or URL to reconnoiter.
        scope: Scope of recon - 'full' (all techniques), 'passive' (no active scanning), 
               'subdomains' (only subdomain enum), 'ports' (focus on port scanning).
               
    Returns:
        Comprehensive reconnaissance results from the sub-agent.
    """
    task = f"""Perform {scope} reconnaissance on target: {target}

Execute the following based on scope '{scope}':
"""
    
    if scope == "full":
        task += """
1. Subdomain enumeration with subfinder_scan and crt_sh_search
2. DNS reconnaissance with dns_lookup 
3. Technology fingerprinting with whatweb_scan
4. Port scanning with nmap_scan
5. WHOIS lookup with whois_lookup
6. Check VirusTotal for additional subdomains with virustotal_subdomains

Return ALL discovered information in a structured format."""
    
    elif scope == "passive":
        task += """
1. Subdomain enumeration with crt_sh_search (passive only)
2. WHOIS lookup with whois_lookup
3. DNS lookup with dns_lookup
4. VirusTotal domain analysis with virustotal_domain_analysis

Do NOT perform any active scanning (no port scans, no web requests to target)."""
    
    elif scope == "subdomains":
        task += """
1. Subdomain enumeration with subfinder_scan
2. Certificate transparency with crt_sh_search
3. VirusTotal subdomains with virustotal_subdomains
4. Probe discovered subdomains with httpx_probe

Focus ONLY on finding as many subdomains as possible."""
    
    elif scope == "ports":
        task += """
1. Full port scan with nmap_scan using "-p-" for all ports
2. Service version detection with "-sV"
3. Script scanning with "-sC" for common vulnerabilities
4. Document all open ports and services

Focus on comprehensive port and service discovery."""
    
    # Run the sub-agent synchronously
    result = run_sub_agent_sync(SubAgentType.RECON, task, max_steps=40)
    
    return f"""=== RECONNAISSANCE SUB-AGENT RESULTS ===
Target: {target}
Scope: {scope}

{result}
========================================

Use these results for vulnerability scanning phase."""


@tool
def delegate_vulnerability_scan(target: str, recon_data: str = "", focus: str = "comprehensive") -> str:
    """Delegate vulnerability scanning to a specialized Vulnerability Sub-Agent.
    
    The Vulnerability Sub-Agent will perform comprehensive vulnerability assessment:
    - Web server scanning (nikto)
    - Vulnerability templates (nuclei)
    - Directory enumeration (gobuster)
    - SQL injection detection (sqlmap)
    - XSS detection (xsser)
    - SSL/TLS analysis (sslyze)
    
    Args:
        target: Target URL to scan for vulnerabilities.
        recon_data: Optional reconnaissance data from previous phase to inform scanning.
        focus: Scanning focus - 'comprehensive' (all scanners), 'web' (web-focused),
               'injection' (SQLi/XSS focus), 'infrastructure' (SSL/ports focus).
               
    Returns:
        Structured vulnerability findings from the sub-agent.
    """
    context = recon_data if recon_data else None
    
    task = f"""Perform {focus} vulnerability scanning on target: {target}

Execute the following based on focus '{focus}':
"""
    
    if focus == "comprehensive":
        task += """
1. Run nikto_scan for web server vulnerabilities
2. Run nuclei_scan with automatic=True for technology-based detection
3. Run nuclei_scan with templates="cves/" for known CVEs
4. Run gobuster_scan for directory enumeration
5. Find forms with get_page_forms and test with sqlmap_scan
6. Run sslyze_scan for TLS/SSL issues
7. Run xsser_scan for XSS vulnerabilities

Report ALL findings with severity, evidence, and affected component."""
    
    elif focus == "web":
        task += """
1. Run nikto_scan for web misconfigurations
2. Run nuclei_scan with automatic=True
3. Run gobuster_scan for hidden content
4. Spider the site with zap_spider_scan
5. Run zap_active_scan for web vulnerabilities
6. Get all alerts with zap_get_alerts

Focus on web application vulnerabilities."""
    
    elif focus == "injection":
        task += """
1. Find all forms with get_page_forms
2. Find all parameterized URLs with get_page_links
3. Run sqlmap_scan on EVERY parameter found
4. Run xsser_scan on input fields
5. Test for command injection manually with curl_request
6. Run nuclei_scan with tags="sqli,xss,ssti,lfi,rce"

Focus specifically on injection vulnerabilities."""
    
    elif focus == "infrastructure":
        task += """
1. Run sslyze_scan for SSL/TLS configuration
2. Run testssl_scan for comprehensive TLS testing
3. Run nuclei_scan with templates="network/"
4. Check for default credentials with nuclei_scan templates="default-logins/"
5. Look for exposed admin panels

Focus on infrastructure and configuration issues."""
    
    result = run_sub_agent_sync(SubAgentType.VULNERABILITY, task, context, max_steps=60)
    
    return f"""=== VULNERABILITY SUB-AGENT RESULTS ===
Target: {target}
Focus: {focus}

{result}
========================================

Use these findings for exploitation and validation phase."""


@tool
def delegate_exploitation(target: str, vulnerabilities: str, safe_mode: bool = True) -> str:
    """Delegate exploitation and validation to a specialized Exploitation Sub-Agent.
    
    The Exploitation Sub-Agent will validate and exploit confirmed vulnerabilities:
    - SQL injection exploitation (sqlmap --dump)
    - Default credential testing
    - CVE exploitation attempts
    - Proof-of-concept generation
    
    Args:
        target: Target URL/system to exploit.
        vulnerabilities: List of vulnerabilities to validate and exploit (from vuln scan).
        safe_mode: If True, only perform non-destructive exploitation (default True).
        
    Returns:
        Exploitation results with proof-of-concept evidence.
    """
    safety_note = """
SAFETY RULES:
- Do NOT delete or modify any data
- Do NOT create persistent backdoors
- Only extract proof-of-concept data (first 5 rows, etc.)
- Take screenshots of successful exploitation
- Document all attempts for the report
""" if safe_mode else ""
    
    task = f"""Validate and exploit the following vulnerabilities on {target}:

## Vulnerabilities to Validate:
{vulnerabilities}

{safety_note}

## Your Tasks:
1. For each vulnerability listed above:
   a. Attempt to validate it exists
   b. If confirmed, attempt exploitation
   c. Extract proof-of-concept evidence
   d. Take screenshots where applicable
   e. Document the exploitation steps

2. For SQL Injection:
   - Use sqlmap_scan to confirm
   - Use sqlmap_dump to extract sample data (limit 5 rows)
   - Document database name, tables, columns

3. For File Inclusion/RCE:
   - Attempt to read a safe file like /etc/passwd
   - Document the vulnerability with curl_request

4. For Authentication Bypass:
   - Test with common credentials
   - Take screenshot of successful login

Return structured results showing:
- Which vulnerabilities were CONFIRMED
- What proof-of-concept data was extracted
- Which vulnerabilities were FALSE POSITIVES
"""
    
    result = run_sub_agent_sync(SubAgentType.EXPLOITATION, task, max_steps=40)
    
    return f"""=== EXPLOITATION SUB-AGENT RESULTS ===
Target: {target}
Safe Mode: {safe_mode}

{result}
========================================

Use these results for final report generation."""


@tool
def delegate_report_generation(
    title: str,
    target: str,
    recon_results: str = "",
    vulnerability_results: str = "",
    exploitation_results: str = ""
) -> str:
    """Delegate final report generation to a specialized Reporting Sub-Agent.
    
    The Reporting Sub-Agent will compile all findings into a professional report:
    - Executive summary
    - Detailed findings with remediation
    - Evidence and screenshots
    - Prioritized recommendations
    
    Args:
        title: Report title.
        target: Primary target of the assessment.
        recon_results: Results from reconnaissance phase.
        vulnerability_results: Results from vulnerability scanning.
        exploitation_results: Results from exploitation phase.
        
    Returns:
        Confirmation of report generation with report path.
    """
    context = f"""## RECONNAISSANCE DATA:
{recon_results if recon_results else "No reconnaissance data provided."}

## VULNERABILITY SCAN RESULTS:
{vulnerability_results if vulnerability_results else "No vulnerability data provided."}

## EXPLOITATION RESULTS:
{exploitation_results if exploitation_results else "No exploitation data provided."}
"""
    
    task = f"""Generate a professional penetration test report.

## Report Details:
- Title: {title}
- Target: {target}

## Your Tasks:
1. Call enable_report_mode("{title}", "{target}")

2. Parse the reconnaissance data and add key findings:
   - Technologies discovered
   - Subdomains found
   - Open ports and services

3. For EACH vulnerability found, call add_finding_to_report() with:
   - Appropriate severity (Critical/High/Medium/Low/Info)
   - Detailed description
   - Business impact
   - Specific remediation steps
   - OWASP category if applicable
   - References

4. Write a professional executive summary with set_executive_summary():
   - Overall risk assessment
   - Key findings summary
   - High-level recommendations

5. Write detailed conclusions with set_conclusion():
   - Assessment summary
   - Prioritized remediation roadmap
   - Strategic recommendations

6. Generate the final HTML report with generate_html_report()

IMPORTANT: Include EVERY finding. Do not skip or summarize.
"""
    
    result = run_sub_agent_sync(SubAgentType.REPORTING, task, context, max_steps=50)
    
    return f"""=== REPORTING SUB-AGENT RESULTS ===
Title: {title}
Target: {target}

{result}
========================================"""


@tool 
def run_parallel_scans(target: str, scan_types: str = "recon,vuln") -> str:
    """Run multiple scan types in parallel using sub-agents.
    
    This launches multiple sub-agents simultaneously for faster results.
    Each sub-agent runs in a background thread.
    
    Args:
        target: Target URL/domain to scan.
        scan_types: Comma-separated list of scan types: 'recon', 'vuln', 'ports'.
        
    Returns:
        Task IDs for tracking parallel scans. Use get_sub_agent_results() to retrieve.
    """
    import uuid
    
    scan_list = [s.strip().lower() for s in scan_types.split(",")]
    task_ids = []
    
    for scan_type in scan_list:
        task_id = f"{scan_type}_{uuid.uuid4().hex[:8]}"
        
        if scan_type == "recon":
            task = f"Perform full reconnaissance on {target}"
            run_sub_agent_async(task_id, SubAgentType.RECON, task, max_steps=40)
        elif scan_type == "vuln":
            task = f"Perform comprehensive vulnerability scanning on {target}"
            run_sub_agent_async(task_id, SubAgentType.VULNERABILITY, task, max_steps=60)
        elif scan_type == "ports":
            task = f"Perform full port scan on {target}"
            run_sub_agent_async(task_id, SubAgentType.RECON, 
                              f"Run nmap_scan on {target} with '-p- -sV -sC' for full port scan", 
                              max_steps=30)
        
        task_ids.append(task_id)
        with _SUB_AGENT_LOCK:
            _SUB_AGENT_STATUS[task_id] = "started"
    
    return f"""Parallel scans started for {target}:

Task IDs:
{chr(10).join(f'- {tid}' for tid in task_ids)}

Use get_sub_agent_status() to check progress.
Use get_sub_agent_results() to retrieve completed results."""


@tool
def get_sub_agent_status() -> str:
    """Get the status of all running and completed sub-agent tasks.
    
    Returns:
        Status of all tracked sub-agent tasks.
    """
    with _SUB_AGENT_LOCK:
        if not _SUB_AGENT_STATUS:
            return "No sub-agent tasks have been started."
        
        status_lines = ["=== SUB-AGENT STATUS ==="]
        for task_id, status in _SUB_AGENT_STATUS.items():
            icon = "✅" if status == "completed" else "⏳" if status == "running" else "❌" if status == "failed" else "⏸️"
            status_lines.append(f"{icon} {task_id}: {status}")
        status_lines.append("========================")
        
        return "\n".join(status_lines)


@tool
def get_sub_agent_results(task_id: str = "") -> str:
    """Get results from completed sub-agent tasks.
    
    Args:
        task_id: Specific task ID to retrieve. Leave empty to get all completed results.
        
    Returns:
        Results from the specified or all completed sub-agent tasks.
    """
    with _SUB_AGENT_LOCK:
        if not _SUB_AGENT_RESULTS:
            return "No sub-agent results available yet."
        
        if task_id:
            if task_id in _SUB_AGENT_RESULTS:
                return f"=== RESULTS FOR {task_id} ===\n{_SUB_AGENT_RESULTS[task_id]}"
            elif task_id in _SUB_AGENT_STATUS:
                return f"Task {task_id} is still {_SUB_AGENT_STATUS[task_id]}. Please wait."
            else:
                return f"Task {task_id} not found."
        
        # Return all completed results
        results = ["=== ALL SUB-AGENT RESULTS ==="]
        for tid, result in _SUB_AGENT_RESULTS.items():
            results.append(f"\n--- {tid} ---\n{result[:2000]}...")
        results.append("==============================")
        
        return "\n".join(results)


@tool
def create_custom_sub_agent(task: str, tools_needed: str = "all", max_steps: int = 30) -> str:
    """Create and run a custom sub-agent for a specific task.
    
    Use this for specialized tasks that don't fit the predefined sub-agent types.
    
    Args:
        task: Detailed description of the task for the sub-agent.
        tools_needed: Which tool category to provide - 'recon', 'vuln', 'exploit', 'all'.
        max_steps: Maximum steps allowed (default 30).
        
    Returns:
        Result from the custom sub-agent.
    """
    # Map tool category to agent type
    type_map = {
        "recon": SubAgentType.RECON,
        "vuln": SubAgentType.VULNERABILITY,
        "exploit": SubAgentType.EXPLOITATION,
        "report": SubAgentType.REPORTING,
        "all": SubAgentType.VULNERABILITY,  # Default to vuln for "all"
    }
    
    agent_type = type_map.get(tools_needed.lower(), SubAgentType.VULNERABILITY)
    
    custom_prompt = f"""You are a custom security sub-agent. Complete the following task:

{task}

Follow security testing best practices and return detailed results."""
    
    # Build agent with custom prompt
    agent = build_sub_agent(SubAgentType.CUSTOM, custom_prompt, max_steps)
    
    try:
        result = agent.run(task)
        return f"=== CUSTOM SUB-AGENT RESULTS ===\n{result}"
    except Exception as e:
        return f"Custom sub-agent error: {str(e)}"
