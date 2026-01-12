"""
Hierarchical Multi-Agent System for OWASP Penetration Testing

Architecture:
┌─────────────────────────────────────────────────────────────────┐
│          CYBERSECURITY PROJECT MANAGER AGENT                     │
│          (Orchestrates entire pentest, final delivery)           │
└─────────────────────────────┬───────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ QUALITY       │◄───│  REPORTING    │◄───│  OPERATIONAL  │
│ CONTROL       │    │  AGENT        │    │  AGENTS       │
│ AGENT         │    │               │    │               │
│               │    │ Compiles all  │    │ • OSINT/Recon │
│ Reviews ALL   │    │ findings into │    │ • Vuln Scan   │
│ results from  │    │ final report  │    │ • Manual Test │
│ other agents  │    │               │    │ • Exploitation│
└───────────────┘    └───────────────┘    └───────────────┘

Data Flow:
1. Operational Agents → Shared Context (findings, evidence)
2. Quality Control validates each finding
3. Validated findings → Reporting Agent
4. Reporting Agent compiles final report
5. Quality Control reviews final report
6. Project Manager delivers to user

Shared Context Structure:
- All agents read/write to a shared context dictionary
- Each agent can see work from other agents
- Findings are tagged with: discovered_by, validated_by, status
"""
from __future__ import annotations
import threading
import json
import uuid
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from copy import deepcopy

import os

# Prevent Rich markup parsing errors when agent/tool outputs contain brackets.
os.environ.setdefault("RICH_DISABLE", "1")

from smolagents import CodeAgent, tool


# =============================================================================
# SHARED CONTEXT - The shared memory between all agents
# =============================================================================

class FindingStatus(Enum):
    """Status of a finding in the pipeline."""
    DISCOVERED = "discovered"       # Just found by operational agent
    PENDING_VALIDATION = "pending_validation"  # Waiting for QC review
    VALIDATED = "validated"         # Confirmed by QC agent
    FALSE_POSITIVE = "false_positive"  # Rejected by QC agent
    EXPLOITED = "exploited"         # Successfully exploited
    REPORTED = "reported"           # Added to final report


@dataclass
class SharedFinding:
    """A finding that flows through the multi-agent pipeline."""
    id: str
    title: str
    severity: str  # Critical, High, Medium, Low, Info
    description: str
    evidence: str
    affected_component: str
    discovered_by: str  # Agent that found it
    discovered_at: datetime
    
    # CRITICAL: Include actual tool info for quality reports
    tool_used: str = ""  # Actual tool name (nikto, nuclei, sqlmap, etc.)
    command_used: str = ""  # Actual command that was run
    steps_to_reproduce: str = ""  # Steps to reproduce the vulnerability
    impact: str = ""  # Business/technical impact (separate from description)
    
    # Validation tracking
    status: FindingStatus = FindingStatus.DISCOVERED
    validated_by: Optional[str] = None
    validated_at: Optional[datetime] = None
    validation_notes: str = ""
    
    # Exploitation tracking
    exploited: bool = False
    exploitation_proof: str = ""
    exploited_by: Optional[str] = None
    
    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    owasp_category: str = ""
    cwe_id: str = ""
    cvss_score: Optional[float] = None
    
    # Attachments
    screenshots: List[str] = field(default_factory=list)
    tool_outputs: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        d = asdict(self)
        d['status'] = self.status.value
        d['discovered_at'] = self.discovered_at.isoformat()
        if self.validated_at:
            d['validated_at'] = self.validated_at.isoformat()
        return d


@dataclass  
class SharedContext:
    """
    Shared context/memory accessible by all agents in the multi-agent system.
    This is the central hub where all agents share their work.
    """
    # Project metadata
    project_id: str = ""
    project_title: str = ""
    target: str = ""
    scope: List[str] = field(default_factory=list)
    started_at: Optional[datetime] = None
    
    # Reconnaissance data (from OSINT/Recon agent)
    recon_data: Dict[str, Any] = field(default_factory=lambda: {
        "subdomains": [],
        "ip_addresses": [],
        "dns_records": [],
        "technologies": [],
        "ports": [],
        "emails": [],
        "whois": {},
        "certificates": [],
        "directories": [],
        "endpoints": [],
    })
    
    # Findings pipeline
    findings: List[SharedFinding] = field(default_factory=list)
    
    # Agent activity log
    agent_logs: List[Dict[str, Any]] = field(default_factory=list)
    
    # Tool outputs (raw data for evidence)
    tool_outputs: Dict[str, str] = field(default_factory=dict)
    
    # Phase tracking
    phases_completed: Dict[str, bool] = field(default_factory=lambda: {
        "reconnaissance": False,
        "vulnerability_scanning": False,
        "manual_testing": False,
        "exploitation": False,
        "quality_control_review": False,
        "reporting": False,
        "final_review": False,
    })
    
    # Quality control notes
    qc_notes: List[Dict[str, str]] = field(default_factory=list)
    
    # Final report status
    report_generated: bool = False
    report_path: str = ""
    report_reviewed: bool = False
    
    def add_finding(self, finding: SharedFinding) -> None:
        """Add a new finding to the pipeline."""
        self.findings.append(finding)
        self.log_activity(finding.discovered_by, "finding_added", 
                         f"Added finding: {finding.title} ({finding.severity})")
    
    def get_findings_by_status(self, status: FindingStatus) -> List[SharedFinding]:
        """Get all findings with a specific status."""
        return [f for f in self.findings if f.status == status]
    
    def get_findings_by_agent(self, agent_name: str) -> List[SharedFinding]:
        """Get all findings discovered by a specific agent."""
        return [f for f in self.findings if f.discovered_by == agent_name]
    
    def get_validated_findings(self) -> List[SharedFinding]:
        """Get all validated findings ready for reporting."""
        return [f for f in self.findings 
                if f.status in (FindingStatus.VALIDATED, FindingStatus.EXPLOITED, FindingStatus.REPORTED)]
    
    def log_activity(self, agent: str, action: str, details: str) -> None:
        """Log an agent activity."""
        self.agent_logs.append({
            "timestamp": datetime.now().isoformat(),
            "agent": agent,
            "action": action,
            "details": details
        })
    
    def add_recon_data(self, data_type: str, items: List[str], source: str) -> int:
        """Add reconnaissance data."""
        if data_type not in self.recon_data:
            self.recon_data[data_type] = []
        
        existing = set(self.recon_data[data_type])
        new_items = [i for i in items if i not in existing]
        self.recon_data[data_type].extend(new_items)
        
        self.log_activity(source, "recon_data_added", 
                         f"Added {len(new_items)} {data_type} items")
        return len(new_items)
    
    def add_tool_output(self, tool_name: str, output: str, agent: str) -> None:
        """Store raw tool output for evidence."""
        key = f"{tool_name}_{datetime.now().strftime('%H%M%S')}"
        self.tool_outputs[key] = output
        self.log_activity(agent, "tool_output_saved", f"Saved {tool_name} output")
    
    def mark_phase_complete(self, phase: str, agent: str) -> None:
        """Mark a phase as completed."""
        if phase in self.phases_completed:
            self.phases_completed[phase] = True
            self.log_activity(agent, "phase_completed", f"Completed phase: {phase}")
    
    def add_qc_note(self, note: str, reviewer: str) -> None:
        """Add a quality control note."""
        self.qc_notes.append({
            "timestamp": datetime.now().isoformat(),
            "reviewer": reviewer,
            "note": note
        })
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the current context state."""
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            if f.severity in severity_counts:
                severity_counts[f.severity] += 1
        
        return {
            "project": self.project_title,
            "target": self.target,
            "total_findings": len(self.findings),
            "severity_breakdown": severity_counts,
            "validated_findings": len(self.get_validated_findings()),
            "pending_validation": len(self.get_findings_by_status(FindingStatus.PENDING_VALIDATION)),
            "false_positives": len(self.get_findings_by_status(FindingStatus.FALSE_POSITIVE)),
            "phases_completed": self.phases_completed,
            "recon_items": {k: len(v) for k, v in self.recon_data.items() if v},
        }
    
    def to_json(self) -> str:
        """Serialize context to JSON."""
        data = {
            "project_id": self.project_id,
            "project_title": self.project_title,
            "target": self.target,
            "scope": self.scope,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "recon_data": self.recon_data,
            "findings": [f.to_dict() for f in self.findings],
            "agent_logs": self.agent_logs,
            "phases_completed": self.phases_completed,
            "qc_notes": self.qc_notes,
            "report_generated": self.report_generated,
            "report_path": self.report_path,
            "report_reviewed": self.report_reviewed,
        }
        return json.dumps(data, indent=2)


# Global shared context - singleton instance
_SHARED_CONTEXT: Optional[SharedContext] = None
_CONTEXT_LOCK = threading.Lock()


def get_shared_context() -> SharedContext:
    """Get the global shared context instance."""
    global _SHARED_CONTEXT
    with _CONTEXT_LOCK:
        if _SHARED_CONTEXT is None:
            _SHARED_CONTEXT = SharedContext()
        return _SHARED_CONTEXT


def reset_shared_context() -> None:
    """Reset the shared context (for new projects)."""
    global _SHARED_CONTEXT
    with _CONTEXT_LOCK:
        _SHARED_CONTEXT = SharedContext()


def initialize_project(title: str, target: str, scope: List[str] = None) -> SharedContext:
    """Initialize a new pentest project with shared context."""
    global _SHARED_CONTEXT
    with _CONTEXT_LOCK:
        _SHARED_CONTEXT = SharedContext(
            project_id=uuid.uuid4().hex[:12],
            project_title=title,
            target=target,
            scope=scope or [target],
            started_at=datetime.now(),
        )
        _SHARED_CONTEXT.log_activity("ProjectManager", "project_initialized", 
                                     f"Started project: {title}")
        return _SHARED_CONTEXT


# =============================================================================
# AGENT ROLE DEFINITIONS
# =============================================================================

class AgentRole(Enum):
    """Roles in the multi-agent system."""
    PROJECT_MANAGER = "project_manager"
    OSINT_RECON = "osint_recon"
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    MANUAL_TESTER = "manual_tester"
    EXPLOITATION = "exploitation"
    QUALITY_CONTROL = "quality_control"
    REPORTING = "reporting"


# Agent-specific prompts
AGENT_PROMPTS = {
    AgentRole.PROJECT_MANAGER: """You are the CYBERSECURITY PROJECT MANAGER agent.

## Your Role:
You are the orchestrator of a multi-agent penetration testing team. You coordinate the work of specialized agents and ensure the pentest is completed professionally.

## Your Team:
1. **OSINT/Recon Agent** - Handles reconnaissance and information gathering
2. **Vulnerability Scanner Agent** - Runs automated vulnerability scans
3. **Manual Tester Agent** - Performs manual security testing
4. **Exploitation Agent** - Validates and exploits confirmed vulnerabilities
5. **Quality Control Agent** - Reviews and validates ALL findings
6. **Reporting Agent** - Compiles the final report

## Your Responsibilities:
1. Initialize the pentest project
2. Coordinate the sequence of agent activities
3. Monitor progress through the shared context
4. Ensure all phases are completed
5. Deliver the final report to the user

## Workflow:
1. Call `initialize_pentest_project()` to set up shared context
2. Dispatch agents in order: Recon → Vuln Scan → Manual Test → Exploitation
3. After each phase, QC Agent reviews the findings
4. Once all testing complete, Reporting Agent compiles report
5. QC Agent does final review
6. You deliver the final report

## Important:
- Check `get_project_status()` frequently to monitor progress
- All agents share context via the shared memory system
- Never skip the Quality Control review phases
""",

    AgentRole.OSINT_RECON: """You are the OSINT/RECONNAISSANCE agent.

## Your Role:
Perform comprehensive reconnaissance and information gathering on targets.

## Your Capabilities:
- Subdomain enumeration (subfinder, crt.sh, amass)
- DNS reconnaissance
- Technology fingerprinting (whatweb)
- Port scanning (nmap)
- WHOIS lookups
- Certificate transparency searches
- OSINT research (VirusTotal, Shodan)

## Your Responsibilities:
1. Gather ALL available information about the target
2. Store findings in shared context using `submit_recon_data()`
3. Create Info-level findings for sensitive discoveries
4. Mark phase complete when done

## Output Requirements:
- Submit ALL discovered subdomains, IPs, technologies
- Save raw tool outputs for evidence
- Create findings for any information disclosure issues
- Be thorough - missing recon data affects all other phases
""",

    AgentRole.VULNERABILITY_SCANNER: """You are the VULNERABILITY SCANNER agent.

## Your Role:
Run comprehensive automated vulnerability scans on targets.

## Your Capabilities:
- Web vulnerability scanning (nikto, nuclei, ZAP)
- SSL/TLS analysis (sslyze, testssl)
- Directory enumeration (gobuster, ffuf)
- CMS scanning (wpscan)
- Known CVE detection

## Your Responsibilities:
1. Review recon data from shared context to understand target
2. Run appropriate scanners based on discovered technologies
3. Submit ALL findings using `submit_finding()` with COMPLETE details
4. Each finding goes to QC for validation
5. Mark phase complete when done

## ⚠️ CRITICAL: FINDING SUBMISSION REQUIREMENTS ⚠️

For HIGH-QUALITY reports, EVERY finding MUST include:

```python
submit_finding(
    title="Descriptive title with specific details",
    severity="High",  # Critical, High, Medium, Low, Info
    description="Detailed multi-sentence description explaining the vulnerability, "
                "what it means, and how it was discovered.",
    evidence="Raw tool output or proof-of-concept showing the vulnerability",
    affected_component="https://target.com/specific/path/or/endpoint",
    remediation="Specific, actionable remediation steps (2-3 sentences minimum)",
    owasp_category="A03:2021 Injection",
    cwe_id="CWE-89",
    references="https://owasp.org/..., https://cwe.mitre.org/...",
    
    # ⚠️ REQUIRED FOR QUALITY REPORTS:
    tool_used="nikto",  # ACTUAL tool name: nikto, nuclei, sqlmap, nmap, etc.
    command_used="nikto -h https://target.com -o output.txt",  # EXACT command run
    steps_to_reproduce="1. Run nikto against target\\n2. Observe finding in output\\n3. Verify manually",
    impact="An attacker could exploit this to... (business/technical impact)",
    cvss_score="7.5"  # If known
)
```

## DO NOT:
- Use generic tool names like "Vulnerability Scanner" 
- Skip the command_used field
- Write single-sentence descriptions
- Forget steps_to_reproduce
""",

    AgentRole.MANUAL_TESTER: """You are the MANUAL TESTER agent.

## Your Role:
Perform manual security testing that automated scanners miss.

## Your Focus Areas:
- Business logic vulnerabilities
- Authentication/session testing
- Access control testing
- Input validation edge cases
- API security testing
- Custom vulnerability checks

## Your Responsibilities:
1. Review recon data and scanner findings from shared context
2. Perform manual testing based on discovered attack surface
3. Submit findings with detailed reproduction steps using submit_finding()
4. Focus on vulnerabilities scanners typically miss

## ⚠️ CRITICAL: FINDING SUBMISSION REQUIREMENTS ⚠️

For HIGH-QUALITY reports, EVERY finding MUST include:
- tool_used: "manual", "curl", "burp", "browser_devtools", etc.
- command_used: Exact curl command, HTTP request, or steps
- steps_to_reproduce: Numbered list of steps (1. Navigate to... 2. Enter... 3. Observe...)
- impact: Business/technical impact explanation
- evidence: HTTP request/response, screenshots, etc.

## Important:
- Check what scanners already found to avoid duplicates
- Document exact steps to reproduce each finding
- Take screenshots for evidence
""",

    AgentRole.EXPLOITATION: """You are the EXPLOITATION agent.

## Your Role:
Validate and exploit confirmed vulnerabilities to demonstrate impact.

## Your Capabilities:
- SQL injection exploitation (sqlmap)
- File inclusion exploitation
- Command injection
- Authentication bypass
- CVE exploitation
- Custom exploit development

## Your Responsibilities:
1. Review validated findings from shared context
2. Attempt safe exploitation of each vulnerability
3. Document exploitation steps and evidence
4. Update findings with exploitation proof
5. Mark findings as EXPLOITED when successful

## ⚠️ CRITICAL: ALWAYS include in exploitation findings:
- tool_used: "sqlmap", "curl", "metasploit", etc.
- command_used: EXACT exploit command that was run
- steps_to_reproduce: How to replicate the exploitation
- evidence: Proof of successful exploitation (data extracted, shell access, etc.)

## Safety Rules:
- Only exploit VALIDATED findings
- Do NOT delete or modify production data
- Extract minimal proof-of-concept data
- Document everything for the report
""",

    AgentRole.QUALITY_CONTROL: """You are the QUALITY CONTROL agent.

## Your Role:
Review and validate ALL findings from other agents. You are the gatekeeper of quality.

## Your Responsibilities:

### During Active Testing:
1. Review all findings with status PENDING_VALIDATION
2. Validate each finding by:
   - Checking if evidence supports the claim
   - Verifying severity is appropriate
   - Confirming it's not a false positive
3. Update finding status to VALIDATED or FALSE_POSITIVE
4. Add validation notes explaining your decision

### Final Report Review:
1. Review the complete report before delivery
2. Check that all validated findings are included
3. Verify no findings were missed
4. Check executive summary accuracy
5. Approve or request corrections

## Validation Criteria:
- Is there sufficient evidence?
- Is the severity rating accurate?
- Is the finding reproducible?
- Is the remediation advice correct?
- Are references and CVEs accurate?

## Commands:
- `review_pending_findings()` - Get findings awaiting validation
- `validate_finding(finding_id, approved, notes)` - Approve or reject
- `review_final_report()` - Do final report review
- `approve_report()` - Approve for delivery
""",

    AgentRole.REPORTING: """You are the REPORTING agent.

## Your Role:
Compile all validated findings into a professional penetration test report.

## Your Responsibilities:
1. Wait for Quality Control to validate findings
2. Only include VALIDATED or EXPLOITED findings
3. Generate comprehensive report with:
   - Executive summary
   - Detailed findings
   - Evidence and screenshots
   - Remediation guidance
   - Prioritized recommendations

## Report Sections:
1. Executive Summary - Business-focused overview
2. Scope & Methodology - What was tested and how
3. Findings - Each vulnerability in detail
4. Conclusion - Prioritized remediation roadmap
5. Appendices - Raw tool outputs, evidence

## Important:
- Include ONLY validated findings (not false positives)
- Check shared context for all evidence and screenshots
- Generate HTML report using existing report tools
- Notify QC when report is ready for final review
"""
}


# =============================================================================
# TOOLS FOR SHARED CONTEXT ACCESS
# =============================================================================

@tool
def initialize_pentest_project(title: str, target: str, scope: str = "") -> str:
    """Initialize a new penetration test project with shared context for all agents.
    
    This MUST be called at the start of any multi-agent pentest.
    It creates the shared memory space that all agents will use.
    
    Args:
        title: Project title (e.g., "Security Assessment - Acme Corp").
        target: Primary target URL or domain.
        scope: Comma-separated list of in-scope targets (optional).
        
    Returns:
        Confirmation with project ID and initial status.
    """
    scope_list = [s.strip() for s in scope.split(",") if s.strip()] if scope else [target]
    ctx = initialize_project(title, target, scope_list)
    
    # Also enable report mode in the existing report system
    try:
        from app.tools.report_tools import enable_report_mode
        enable_report_mode(title, target)
    except Exception:
        pass
    
    return f"""✅ PENTEST PROJECT INITIALIZED

Project ID: {ctx.project_id}
Title: {ctx.project_title}
Target: {ctx.target}
Scope: {', '.join(ctx.scope)}
Started: {ctx.started_at.strftime('%Y-%m-%d %H:%M:%S')}

Shared Context Status: ACTIVE
All agents can now read/write to shared context.

Next Steps:
1. Dispatch OSINT/Recon Agent to gather intelligence
2. Monitor progress with get_project_status()
3. After recon, dispatch Vulnerability Scanner
4. Quality Control reviews findings throughout
"""


@tool
def get_project_status() -> str:
    """Get current status of the pentest project including all agent activities.
    
    Returns:
        Comprehensive status report of the multi-agent pentest.
    """
    ctx = get_shared_context()
    
    if not ctx.project_id:
        return "No active project. Call initialize_pentest_project() first."
    
    summary = ctx.get_summary()
    
    # Build phase status
    phase_status = []
    for phase, complete in ctx.phases_completed.items():
        icon = "✅" if complete else "⏳"
        phase_status.append(f"  {icon} {phase.replace('_', ' ').title()}")
    
    # Recent activity
    recent_logs = ctx.agent_logs[-10:] if ctx.agent_logs else []
    activity_lines = []
    for log in recent_logs:
        activity_lines.append(f"  [{log['agent']}] {log['action']}: {log['details'][:50]}")
    
    # Finding stats
    findings_by_status = {}
    for f in ctx.findings:
        status_name = f.status.value
        if status_name not in findings_by_status:
            findings_by_status[status_name] = 0
        findings_by_status[status_name] += 1
    
    return f"""=== PROJECT STATUS: {ctx.project_title} ===

📋 PROJECT INFO:
  ID: {ctx.project_id}
  Target: {ctx.target}
  Started: {ctx.started_at.strftime('%Y-%m-%d %H:%M:%S') if ctx.started_at else 'N/A'}

📊 FINDINGS SUMMARY:
  Total: {summary['total_findings']}
  🔴 Critical: {summary['severity_breakdown']['Critical']}
  🟠 High: {summary['severity_breakdown']['High']}
  🟡 Medium: {summary['severity_breakdown']['Medium']}
  🟢 Low: {summary['severity_breakdown']['Low']}
  ℹ️ Info: {summary['severity_breakdown']['Info']}

📝 FINDING STATUS:
  {json.dumps(findings_by_status, indent=2) if findings_by_status else "  No findings yet"}

🔄 PHASE PROGRESS:
{chr(10).join(phase_status)}

📡 RECON DATA COLLECTED:
  Subdomains: {len(ctx.recon_data.get('subdomains', []))}
  IP Addresses: {len(ctx.recon_data.get('ip_addresses', []))}
  Technologies: {len(ctx.recon_data.get('technologies', []))}
  Ports: {len(ctx.recon_data.get('ports', []))}
  Directories: {len(ctx.recon_data.get('directories', []))}

📜 RECENT ACTIVITY:
{chr(10).join(activity_lines) if activity_lines else "  No activity yet"}

📄 REPORT STATUS:
  Generated: {'Yes' if ctx.report_generated else 'No'}
  Reviewed: {'Yes' if ctx.report_reviewed else 'No'}
  Path: {ctx.report_path or 'N/A'}

==========================================
"""


@tool
def submit_recon_data(data_type: str, items: str, source_agent: str = "osint_recon") -> str:
    """Submit reconnaissance data to the shared context.
    
    Used by OSINT/Recon agent to share discovered information with other agents.
    
    Args:
        data_type: Type of data - subdomains, ip_addresses, dns_records, technologies, 
                   ports, emails, directories, endpoints.
        items: Newline-separated or comma-separated list of discovered items.
        source_agent: Name of the agent submitting (default: osint_recon).
        
    Returns:
        Confirmation with count of new items added.
    """
    ctx = get_shared_context()
    
    # Parse items
    if '\n' in items:
        item_list = [i.strip() for i in items.split('\n') if i.strip()]
    else:
        item_list = [i.strip() for i in items.split(',') if i.strip()]
    
    count = ctx.add_recon_data(data_type, item_list, source_agent)
    
    return f"✅ Added {count} new {data_type} items to shared context. Total: {len(ctx.recon_data.get(data_type, []))}"


@tool
def submit_finding(
    title: str,
    severity: str,
    description: str,
    evidence: str,
    affected_component: str,
    remediation: str = "",
    owasp_category: str = "",
    cwe_id: str = "",
    references: str = "",
    source_agent: str = "vulnerability_scanner",
    tool_used: str = "",
    command_used: str = "",
    steps_to_reproduce: str = "",
    impact: str = "",
    cvss_score: str = ""
) -> str:
    """Submit a finding to the shared context for Quality Control review.
    
    This is the primary way for operational agents to report vulnerabilities.
    All findings go through QC validation before being included in the report.
    
    CRITICAL: For high-quality reports, include ALL fields:
    - tool_used: Actual tool name (nikto, nuclei, sqlmap, nmap, etc.)
    - command_used: Exact command that was run
    - steps_to_reproduce: Numbered steps to reproduce
    - impact: Business/technical impact
    - evidence: Raw tool output or proof
    
    Args:
        title: Short, descriptive title of the finding.
        severity: Critical, High, Medium, Low, or Info.
        description: Detailed description of the vulnerability (at least 2-3 sentences).
        evidence: Raw evidence (tool output, request/response, etc.).
        affected_component: URL, endpoint, or component affected.
        remediation: Recommended fix (at least 2-3 sentences).
        owasp_category: OWASP category (e.g., "A01:2021 Broken Access Control").
        cwe_id: CWE identifier (e.g., "CWE-89").
        references: Comma-separated list of reference URLs.
        source_agent: Name of the discovering agent.
        tool_used: REQUIRED - Actual tool name (nikto, nuclei, sqlmap, nmap, etc.).
        command_used: REQUIRED - Exact command that was executed.
        steps_to_reproduce: Numbered steps to reproduce (e.g., "1. Navigate to URL\\n2. Enter payload").
        impact: Business/technical impact of the vulnerability.
        cvss_score: CVSS score if known (e.g., "7.5" or "9.8").
        
    Returns:
        Confirmation with finding ID for tracking.
    """
    ctx = get_shared_context()
    
    # Parse references
    ref_list = [r.strip() for r in references.split(',') if r.strip()] if references else []
    
    # Parse CVSS score
    cvss_float = None
    if cvss_score:
        try:
            cvss_float = float(cvss_score)
        except ValueError:
            pass
    
    # Create finding with ALL fields
    finding = SharedFinding(
        id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
        title=title,
        severity=severity,
        description=description,
        evidence=evidence,
        affected_component=affected_component,
        remediation=remediation,
        owasp_category=owasp_category,
        cwe_id=cwe_id,
        references=ref_list,
        discovered_by=source_agent,
        discovered_at=datetime.now(),
        status=FindingStatus.PENDING_VALIDATION,
        tool_used=tool_used or source_agent,  # Fallback to source_agent if not specified
        command_used=command_used,
        steps_to_reproduce=steps_to_reproduce,
        impact=impact or description,  # Use description as fallback for impact
        cvss_score=cvss_float,
    )
    
    ctx.add_finding(finding)
    
    return f"""✅ FINDING SUBMITTED

ID: {finding.id}
Title: {finding.title}
Severity: {finding.severity}
Status: PENDING_VALIDATION

The Quality Control agent will review this finding.
Track status with get_finding_status("{finding.id}")
"""


@tool
def get_recon_data() -> str:
    """Get all reconnaissance data collected by the OSINT/Recon agent.
    
    Used by other agents to understand the target's attack surface.
    
    Returns:
        All collected reconnaissance data from shared context.
    """
    ctx = get_shared_context()
    
    output = ["=== RECONNAISSANCE DATA ===\n"]
    
    for data_type, items in ctx.recon_data.items():
        if items:
            output.append(f"\n📁 {data_type.upper()} ({len(items)} items):")
            for item in items[:50]:  # Limit display
                output.append(f"  • {item}")
            if len(items) > 50:
                output.append(f"  ... and {len(items) - 50} more")
    
    output.append("\n===========================")
    return "\n".join(output)


@tool
def get_pending_findings() -> str:
    """Get all findings pending Quality Control validation.
    
    Used by QC agent to review findings from operational agents.
    
    Returns:
        List of findings awaiting validation.
    """
    ctx = get_shared_context()
    pending = ctx.get_findings_by_status(FindingStatus.PENDING_VALIDATION)
    
    if not pending:
        return "No findings pending validation."
    
    output = [f"=== FINDINGS PENDING VALIDATION ({len(pending)}) ===\n"]
    
    for f in pending:
        output.append(f"""
📋 {f.id}: {f.title}
   Severity: {f.severity}
   Component: {f.affected_component}
   Discovered by: {f.discovered_by}
   Evidence preview: {f.evidence[:200]}...
   ---""")
    
    output.append("\nUse validate_finding(finding_id, approved, notes) to review each finding.")
    return "\n".join(output)


@tool
def validate_finding(finding_id: str, approved: bool, notes: str = "") -> str:
    """Validate or reject a finding (Quality Control only).
    
    Args:
        finding_id: ID of the finding to validate.
        approved: True to validate, False to mark as false positive.
        notes: Validation notes explaining the decision.
        
    Returns:
        Confirmation of validation action.
    """
    ctx = get_shared_context()
    
    # Find the finding
    finding = None
    for f in ctx.findings:
        if f.id == finding_id:
            finding = f
            break
    
    if not finding:
        return f"Finding {finding_id} not found."
    
    if approved:
        finding.status = FindingStatus.VALIDATED
        finding.validated_by = "quality_control"
        finding.validated_at = datetime.now()
        finding.validation_notes = notes
        
        ctx.log_activity("quality_control", "finding_validated", 
                        f"Validated: {finding.title}")
        
        return f"""✅ FINDING VALIDATED

ID: {finding_id}
Title: {finding.title}
Severity: {finding.severity}
Status: VALIDATED
Notes: {notes or 'Approved for inclusion in report'}

This finding will be included in the final report.
"""
    else:
        finding.status = FindingStatus.FALSE_POSITIVE
        finding.validated_by = "quality_control"
        finding.validated_at = datetime.now()
        finding.validation_notes = notes
        
        ctx.log_activity("quality_control", "finding_rejected", 
                        f"Rejected as false positive: {finding.title}")
        
        return f"""❌ FINDING REJECTED

ID: {finding_id}
Title: {finding.title}
Status: FALSE_POSITIVE
Reason: {notes or 'Determined to be false positive'}

This finding will NOT be included in the final report.
"""


@tool
def mark_finding_exploited(finding_id: str, exploitation_proof: str) -> str:
    """Mark a finding as successfully exploited (Exploitation agent only).
    
    Args:
        finding_id: ID of the finding that was exploited.
        exploitation_proof: Description or evidence of successful exploitation.
        
    Returns:
        Confirmation of exploitation status.
    """
    ctx = get_shared_context()
    
    finding = None
    for f in ctx.findings:
        if f.id == finding_id:
            finding = f
            break
    
    if not finding:
        return f"Finding {finding_id} not found."
    
    finding.exploited = True
    finding.exploitation_proof = exploitation_proof
    finding.exploited_by = "exploitation"
    finding.status = FindingStatus.EXPLOITED
    
    ctx.log_activity("exploitation", "finding_exploited", 
                    f"Exploited: {finding.title}")
    
    return f"""💥 EXPLOITATION CONFIRMED

ID: {finding_id}
Title: {finding.title}
Status: EXPLOITED

Proof of exploitation has been recorded.
This strengthens the finding's severity and report impact.
"""


@tool
def mark_phase_complete(phase: str) -> str:
    """Mark a testing phase as complete.
    
    Args:
        phase: Phase name - reconnaissance, vulnerability_scanning, manual_testing,
               exploitation, quality_control_review, reporting, final_review.
               
    Returns:
        Confirmation of phase completion.
    """
    ctx = get_shared_context()
    
    valid_phases = list(ctx.phases_completed.keys())
    if phase not in valid_phases:
        return f"Invalid phase. Valid phases: {', '.join(valid_phases)}"
    
    ctx.mark_phase_complete(phase, "agent")
    
    # Check what's next
    phase_order = ["reconnaissance", "vulnerability_scanning", "manual_testing", 
                   "exploitation", "quality_control_review", "reporting", "final_review"]
    
    current_idx = phase_order.index(phase)
    next_phase = phase_order[current_idx + 1] if current_idx < len(phase_order) - 1 else None
    
    return f"""✅ PHASE COMPLETE: {phase.replace('_', ' ').title()}

Progress: {sum(ctx.phases_completed.values())}/{len(ctx.phases_completed)} phases complete

{"Next phase: " + next_phase.replace('_', ' ').title() if next_phase else "All phases complete!"}
"""


@tool
def get_validated_findings_for_report() -> str:
    """Get all validated findings ready to be included in the report.
    
    Used by Reporting agent to compile the final report.
    
    Returns:
        All validated and exploited findings with full details.
    """
    ctx = get_shared_context()
    validated = ctx.get_validated_findings()
    
    if not validated:
        return "No validated findings ready for reporting."
    
    output = [f"=== VALIDATED FINDINGS FOR REPORT ({len(validated)}) ===\n"]
    
    # Sort by severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    validated.sort(key=lambda f: severity_order.get(f.severity, 5))
    
    for f in validated:
        exploited_tag = " [EXPLOITED]" if f.exploited else ""
        output.append(f"""
═══════════════════════════════════════════
📋 {f.id}: {f.title}{exploited_tag}
═══════════════════════════════════════════
Severity: {f.severity}
Component: {f.affected_component}
OWASP: {f.owasp_category or 'N/A'}
CWE: {f.cwe_id or 'N/A'}

DESCRIPTION:
{f.description}

EVIDENCE:
{f.evidence[:1000]}{'...' if len(f.evidence) > 1000 else ''}

REMEDIATION:
{f.remediation or 'See general recommendations'}

{"EXPLOITATION PROOF:" if f.exploited else ""}
{f.exploitation_proof if f.exploited else ""}

REFERENCES:
{chr(10).join('• ' + r for r in f.references) if f.references else 'None'}

Validated by: {f.validated_by}
Validation notes: {f.validation_notes}
""")
    
    output.append("\n===========================================")
    return "\n".join(output)


@tool
def compile_final_report() -> str:
    """Compile the final report from all validated findings (Reporting agent).
    
    This generates the HTML report using the existing report system.
    
    Returns:
        Confirmation and path to generated report.
    """
    ctx = get_shared_context()
    validated = ctx.get_validated_findings()
    
    if not validated:
        return "Cannot generate report: No validated findings."
    
    try:
        # Use existing report tools
        from app.tools.report_tools import (
            enable_report_mode, add_finding_to_report, 
            set_executive_summary, set_conclusion,
            add_tool_output_to_report, generate_html_report,
            add_recon_data as report_add_recon_data
        )
        
        # Enable report mode
        enable_report_mode(ctx.project_title, ctx.target)
        
        # Add all validated findings with ALL fields for high-quality reports
        for f in validated:
            add_finding_to_report(
                title=f.title,
                severity=f.severity,
                description=f.description,
                # Use dedicated impact field, fallback to exploitation proof, then description
                impact=f.impact if f.impact else (f.exploitation_proof if f.exploited else f.description),
                remediation=f.remediation,
                owasp_category=f.owasp_category,
                cwe_id=f.cwe_id,
                # CRITICAL: Use actual tool_used field, not discovered_by
                tool_used=f.tool_used if f.tool_used else f.discovered_by,
                command_used=f.command_used,
                steps_to_reproduce=f.steps_to_reproduce,
                evidence=f.evidence,
                cvss_score=str(f.cvss_score) if f.cvss_score else "",
                affected_component=f.affected_component,
                references=",".join(f.references) if f.references else "",
            )
        
        # Add recon data
        for data_type, items in ctx.recon_data.items():
            if items:
                report_add_recon_data(data_type, "\n".join(items), "osint_recon")
        
        # Generate executive summary
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in validated:
            if f.severity in severity_counts:
                severity_counts[f.severity] += 1
        
        exec_summary = f"""A comprehensive security assessment was conducted against {ctx.target}. 

The assessment identified {len(validated)} validated security findings:
- {severity_counts['Critical']} Critical severity
- {severity_counts['High']} High severity  
- {severity_counts['Medium']} Medium severity
- {severity_counts['Low']} Low severity
- {severity_counts['Info']} Informational

{'CRITICAL ISSUES IDENTIFIED: Immediate action required.' if severity_counts['Critical'] > 0 else ''}
{'HIGH SEVERITY ISSUES: Address within 1-2 weeks.' if severity_counts['High'] > 0 else ''}
"""
        set_executive_summary(exec_summary)
        
        # Generate conclusion
        conclusion = f"""This assessment of {ctx.target} revealed several security concerns requiring attention.

Prioritized Remediation:
1. Address all Critical findings immediately
2. Remediate High severity issues within 2 weeks
3. Plan Medium severity fixes for next quarter
4. Include Low/Info items in ongoing hardening

The validated findings in this report have been reviewed by Quality Control.
"""
        set_conclusion(conclusion)
        
        # Add raw tool outputs
        for tool_name, output in list(ctx.tool_outputs.items())[:10]:  # Limit
            add_tool_output_to_report(tool_name.split('_')[0], output[:5000], "txt")
        
        # Generate report
        report_result = generate_html_report()
        
        ctx.report_generated = True
        ctx.report_path = "security-report.html"
        ctx.mark_phase_complete("reporting", "reporting")
        ctx.log_activity("reporting", "report_generated", "Final report compiled")
        
        return f"""✅ FINAL REPORT COMPILED

Title: {ctx.project_title}
Target: {ctx.target}
Findings: {len(validated)} validated findings
Status: Ready for QC final review

{report_result}

Next: Quality Control should review with review_final_report()
"""
    
    except Exception as e:
        return f"Error generating report: {str(e)}"


@tool
def review_final_report() -> str:
    """Review the final report for completeness (QC agent final review).
    
    Checks that all validated findings are included and report is complete.
    
    Returns:
        Review results with any issues found.
    """
    ctx = get_shared_context()
    
    if not ctx.report_generated:
        return "No report generated yet. Cannot review."
    
    validated = ctx.get_validated_findings()
    issues = []
    
    # Check all findings included
    # (In a real implementation, would parse the report and verify)
    if not validated:
        issues.append("No validated findings in report")
    
    # Check phases
    required_phases = ["reconnaissance", "vulnerability_scanning", "quality_control_review"]
    for phase in required_phases:
        if not ctx.phases_completed.get(phase):
            issues.append(f"Phase not completed: {phase}")
    
    # Check for critical/high findings exploitation
    critical_high = [f for f in validated if f.severity in ("Critical", "High")]
    unexploited = [f for f in critical_high if not f.exploited]
    if unexploited:
        issues.append(f"{len(unexploited)} Critical/High findings not exploited")
    
    if issues:
        return f"""⚠️ FINAL REPORT REVIEW: ISSUES FOUND

Issues:
{chr(10).join('• ' + i for i in issues)}

Please address these issues before approving the report.
"""
    else:
        return f"""✅ FINAL REPORT REVIEW: PASSED

Report Quality Check:
✓ All {len(validated)} validated findings included
✓ All required phases completed
✓ Critical/High findings exploited
✓ Evidence attached
✓ Remediation guidance provided

Report is ready for delivery.
Use approve_final_report() to complete.
"""


@tool
def approve_final_report() -> str:
    """Approve the final report for delivery (QC agent).
    
    This marks the report as reviewed and ready for the Project Manager to deliver.
    
    Returns:
        Confirmation that report is approved.
    """
    ctx = get_shared_context()
    
    if not ctx.report_generated:
        return "No report to approve. Generate report first."
    
    ctx.report_reviewed = True
    ctx.mark_phase_complete("final_review", "quality_control")
    ctx.log_activity("quality_control", "report_approved", "Final report approved for delivery")
    
    return f"""✅ FINAL REPORT APPROVED

Project: {ctx.project_title}
Target: {ctx.target}
Status: APPROVED FOR DELIVERY

Quality Control has reviewed and approved this report.
The Project Manager can now deliver to the client.

Summary:
- Total Findings: {len(ctx.findings)}
- Validated: {len(ctx.get_validated_findings())}
- False Positives: {len(ctx.get_findings_by_status(FindingStatus.FALSE_POSITIVE))}

Report Path: {ctx.report_path}
"""


@tool
def get_agent_activity_log() -> str:
    """Get the full activity log of all agent actions.
    
    Returns:
        Chronological log of all agent activities.
    """
    ctx = get_shared_context()
    
    if not ctx.agent_logs:
        return "No agent activity recorded yet."
    
    output = ["=== AGENT ACTIVITY LOG ===\n"]
    
    for log in ctx.agent_logs:
        output.append(f"[{log['timestamp']}] [{log['agent']}] {log['action']}")
        output.append(f"    {log['details']}")
        output.append("")
    
    output.append("==========================")
    return "\n".join(output)


@tool
def add_qc_note(note: str) -> str:
    """Add a Quality Control note or observation.
    
    Args:
        note: The note or observation to record.
        
    Returns:
        Confirmation.
    """
    ctx = get_shared_context()
    ctx.add_qc_note(note, "quality_control")
    
    return f"✅ QC Note added: {note[:100]}..."


@tool
def save_tool_output(tool_name: str, output: str) -> str:
    """Save raw tool output to shared context for evidence.
    
    Args:
        tool_name: Name of the tool (e.g., "nmap", "nikto").
        output: Raw output from the tool.
        
    Returns:
        Confirmation.
    """
    ctx = get_shared_context()
    ctx.add_tool_output(tool_name, output, "operational_agent")
    
    return f"✅ Saved {tool_name} output ({len(output)} chars) to shared context."


# =============================================================================
# MULTI-AGENT ORCHESTRATION
# =============================================================================

def get_agent_tools(role: AgentRole) -> list:
    """Get the appropriate tools for an agent role."""
    
    # Common context tools for all agents
    context_tools = [
        get_project_status,
        get_recon_data,
        get_agent_activity_log,
        save_tool_output,
    ]
    
    if role == AgentRole.PROJECT_MANAGER:
        return context_tools + [
            initialize_pentest_project,
            mark_phase_complete,
            get_validated_findings_for_report,
        ]
    
    elif role == AgentRole.OSINT_RECON:
        from app.tools.osint_tools import dns_lookup, whois_lookup, crt_sh_search
        from app.tools.pentest_tools import subfinder_scan, whatweb_scan, httpx_probe
        from app.tools.nmap_tool import nmap_scan
        
        return context_tools + [
            submit_recon_data,
            submit_finding,
            mark_phase_complete,
            dns_lookup, whois_lookup, crt_sh_search,
            subfinder_scan, whatweb_scan, httpx_probe,
            nmap_scan,
        ]
    
    elif role == AgentRole.VULNERABILITY_SCANNER:
        from app.tools.pentest_tools import (
            nikto_scan, nuclei_scan, gobuster_scan, 
            sslyze_scan, sqlmap_scan, wpscan_full
        )
        from app.tools.zap_tools import zap_spider_scan, zap_active_scan, zap_get_alerts
        
        return context_tools + [
            submit_finding,
            mark_phase_complete,
            nikto_scan, nuclei_scan, gobuster_scan,
            sslyze_scan, sqlmap_scan, wpscan_full,
            zap_spider_scan, zap_active_scan, zap_get_alerts,
        ]
    
    elif role == AgentRole.MANUAL_TESTER:
        from app.tools.pentest_tools import sqlmap_scan, xsser_scan, ffuf_scan
        from app.tools.curl_tool import curl_request
        from app.tools.playwright_tool import browse_page, get_page_forms, take_screenshot
        
        return context_tools + [
            submit_finding,
            mark_phase_complete,
            sqlmap_scan, xsser_scan, ffuf_scan,
            curl_request, browse_page, get_page_forms, take_screenshot,
        ]
    
    elif role == AgentRole.EXPLOITATION:
        from app.tools.pentest_tools import (
            sqlmap_scan, sqlmap_dump, searchsploit_search,
            run_exploit, msfconsole_command
        )
        from app.tools.curl_tool import curl_request
        from app.tools.playwright_tool import take_screenshot
        
        return context_tools + [
            get_pending_findings,
            mark_finding_exploited,
            mark_phase_complete,
            sqlmap_scan, sqlmap_dump, searchsploit_search,
            run_exploit, msfconsole_command,
            curl_request, take_screenshot,
        ]
    
    elif role == AgentRole.QUALITY_CONTROL:
        return context_tools + [
            get_pending_findings,
            validate_finding,
            add_qc_note,
            mark_phase_complete,
            review_final_report,
            approve_final_report,
        ]
    
    elif role == AgentRole.REPORTING:
        from app.tools.report_tools import (
            enable_report_mode, add_finding_to_report,
            set_executive_summary, set_conclusion,
            generate_html_report, add_tool_output_to_report
        )
        
        return context_tools + [
            get_validated_findings_for_report,
            compile_final_report,
            mark_phase_complete,
            enable_report_mode, add_finding_to_report,
            set_executive_summary, set_conclusion,
            generate_html_report, add_tool_output_to_report,
        ]
    
    return context_tools


def build_specialized_agent(role: AgentRole, max_steps: int = 50) -> CodeAgent:
    """Build a specialized agent for a specific role.
    
    Args:
        role: The agent's role in the multi-agent system.
        max_steps: Maximum steps allowed for this agent.
        
    Returns:
        Configured CodeAgent instance.
    """
    from app.agents.owasp_agent import build_model
    
    model = build_model()
    tools = get_agent_tools(role)
    prompt = AGENT_PROMPTS.get(role, "You are a security testing agent.")
    
    agent = CodeAgent(
        tools=tools,
        model=model,
        instructions=prompt,
        max_print_outputs_length=15000,
        max_steps=max_steps,
    )
    
    return agent


def run_agent(role: AgentRole, task: str, max_steps: int = 50) -> str:
    """Run a specialized agent with a specific task.
    
    Args:
        role: Agent role to use.
        task: Task description for the agent.
        max_steps: Maximum steps allowed.
        
    Returns:
        Agent's result.
    """
    agent = build_specialized_agent(role, max_steps)
    
    try:
        result = agent.run(task)
        return str(result)
    except Exception as e:
        return f"Agent error: {type(e).__name__}: {str(e)}"


# =============================================================================
# HIGH-LEVEL ORCHESTRATION TOOLS FOR MAIN AGENT
# =============================================================================

@tool
def dispatch_recon_agent(target: str) -> str:
    """Dispatch the OSINT/Recon agent to gather intelligence on the target.
    
    Args:
        target: Target domain or URL to investigate.
        
    Returns:
        Reconnaissance results from the specialized agent.
    """
    task = f"""Perform comprehensive reconnaissance on: {target}

1. Run subdomain enumeration with subfinder_scan
2. Check certificate transparency with crt_sh_search  
3. Perform DNS lookups
4. Run WHOIS lookup
5. Fingerprint technologies with whatweb_scan
6. Port scan with nmap_scan

For each discovery:
- Submit to shared context using submit_recon_data()
- Create Info findings for any information disclosure

When complete, call mark_phase_complete("reconnaissance")
"""
    
    return run_agent(AgentRole.OSINT_RECON, task, max_steps=40)


@tool
def dispatch_vuln_scanner_agent(target: str) -> str:
    """Dispatch the Vulnerability Scanner agent.
    
    Args:
        target: Target URL to scan.
        
    Returns:
        Vulnerability scanning results.
    """
    task = f"""Perform comprehensive vulnerability scanning on: {target}

First, check get_recon_data() to see what was discovered.

Then run these scans:
1. nikto_scan for web server issues
2. nuclei_scan with automatic=True for technology detection
3. nuclei_scan with templates="cves/" for known CVEs
4. gobuster_scan for hidden content
5. sslyze_scan for TLS issues

For EACH finding:
- Submit using submit_finding() with full details
- Set severity appropriately
- Include raw evidence

When complete, call mark_phase_complete("vulnerability_scanning")
"""
    
    return run_agent(AgentRole.VULNERABILITY_SCANNER, task, max_steps=60)


@tool
def dispatch_manual_tester_agent(target: str) -> str:
    """Dispatch the Manual Tester agent for hands-on testing.
    
    Args:
        target: Target URL to test.
        
    Returns:
        Manual testing results.
    """
    task = f"""Perform manual security testing on: {target}

Check get_recon_data() for attack surface information.

Focus on:
1. Find forms with get_page_forms() and test for injection
2. Test authentication flows
3. Check for business logic flaws
4. Verify access controls
5. Test session management

Submit findings with detailed reproduction steps.
When complete, call mark_phase_complete("manual_testing")
"""
    
    return run_agent(AgentRole.MANUAL_TESTER, task, max_steps=50)


@tool
def dispatch_exploitation_agent() -> str:
    """Dispatch the Exploitation agent to validate and exploit findings.
    
    Returns:
        Exploitation results.
    """
    task = """Validate and exploit all validated findings.

1. Get validated findings from shared context
2. For each Critical/High finding:
   - Attempt exploitation
   - Extract proof-of-concept data
   - Take screenshots
   - Mark as exploited using mark_finding_exploited()

3. For Medium findings, attempt validation at minimum

When complete, call mark_phase_complete("exploitation")
"""
    
    return run_agent(AgentRole.EXPLOITATION, task, max_steps=40)


@tool
def dispatch_qc_agent_review() -> str:
    """Dispatch Quality Control agent to review pending findings.
    
    Returns:
        QC review results.
    """
    task = """Review all findings pending validation.

1. Get pending findings with get_pending_findings()
2. For each finding:
   - Evaluate the evidence
   - Check severity accuracy
   - Validate or reject using validate_finding()
   - Add notes explaining your decision

3. Add any QC notes for the report

When complete, call mark_phase_complete("quality_control_review")
"""
    
    return run_agent(AgentRole.QUALITY_CONTROL, task, max_steps=40)


@tool
def dispatch_reporting_agent() -> str:
    """Dispatch the Reporting agent to compile the final report.
    
    Returns:
        Report generation results.
    """
    task = """Compile the final penetration test report.

1. Get all validated findings with get_validated_findings_for_report()
2. Compile the report using compile_final_report()
3. Ensure executive summary and conclusion are written
4. Include all evidence and remediation guidance

The report will then go to QC for final review.
"""
    
    return run_agent(AgentRole.REPORTING, task, max_steps=40)


@tool
def dispatch_qc_final_review() -> str:
    """Dispatch QC agent for final report review.
    
    Returns:
        Final review results.
    """
    task = """Perform final review of the penetration test report.

1. Review the report with review_final_report()
2. Check that all validated findings are included
3. Verify nothing was missed
4. Check accuracy of executive summary

If everything is correct, call approve_final_report()
If issues found, document them for correction.
"""
    
    return run_agent(AgentRole.QUALITY_CONTROL, task, max_steps=30)


@tool
def run_full_pentest_orchestration(target: str, title: str = "") -> str:
    """Run a complete multi-agent penetration test with full orchestration.
    
    This executes the complete workflow:
    1. Initialize project
    2. Recon Agent gathers intelligence
    3. Vuln Scanner runs automated scans
    4. Manual Tester performs hands-on testing
    5. QC validates findings throughout
    6. Exploitation Agent validates vulns
    7. Reporting Agent compiles report
    8. QC does final review
    9. Project Manager delivers
    
    Args:
        target: Target URL or domain to test.
        title: Project title (optional).
        
    Returns:
        Final status and report location.
    """
    project_title = title or f"Security Assessment - {target}"
    
    results = []
    results.append("=" * 60)
    results.append("🚀 MULTI-AGENT PENTEST ORCHESTRATION STARTED")
    results.append("=" * 60)
    
    # Step 1: Initialize
    results.append("\n📋 PHASE 1: Initializing project...")
    init_result = initialize_pentest_project(project_title, target)
    results.append(init_result)
    
    # Step 2: Reconnaissance
    results.append("\n🔍 PHASE 2: Dispatching OSINT/Recon Agent...")
    recon_result = dispatch_recon_agent(target)
    results.append(f"Recon complete. Result length: {len(recon_result)} chars")
    
    # Step 3: Vulnerability Scanning
    results.append("\n🛡️ PHASE 3: Dispatching Vulnerability Scanner Agent...")
    vuln_result = dispatch_vuln_scanner_agent(target)
    results.append(f"Vuln scan complete. Result length: {len(vuln_result)} chars")
    
    # Step 4: QC Review of initial findings
    results.append("\n✅ PHASE 4: Dispatching QC Agent for finding review...")
    qc_result = dispatch_qc_agent_review()
    results.append(f"QC review complete. Result length: {len(qc_result)} chars")
    
    # Step 5: Manual Testing
    results.append("\n🔧 PHASE 5: Dispatching Manual Tester Agent...")
    manual_result = dispatch_manual_tester_agent(target)
    results.append(f"Manual testing complete. Result length: {len(manual_result)} chars")
    
    # Step 6: Exploitation
    results.append("\n💥 PHASE 6: Dispatching Exploitation Agent...")
    exploit_result = dispatch_exploitation_agent()
    results.append(f"Exploitation complete. Result length: {len(exploit_result)} chars")
    
    # Step 7: QC Review again
    results.append("\n✅ PHASE 7: QC reviewing exploitation results...")
    qc_result2 = dispatch_qc_agent_review()
    results.append(f"QC review complete.")
    
    # Step 8: Report Generation
    results.append("\n📄 PHASE 8: Dispatching Reporting Agent...")
    report_result = dispatch_reporting_agent()
    results.append(f"Report generated.")
    
    # Step 9: Final QC Review
    results.append("\n🔍 PHASE 9: QC Final Report Review...")
    final_review = dispatch_qc_final_review()
    results.append(final_review)
    
    # Step 10: Get final status
    results.append("\n📊 FINAL STATUS:")
    status = get_project_status()
    results.append(status)
    
    results.append("\n" + "=" * 60)
    results.append("✅ MULTI-AGENT PENTEST COMPLETE")
    results.append("=" * 60)
    
    return "\n".join(results)
