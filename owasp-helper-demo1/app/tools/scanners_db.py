"""
Scanners Database - Store and retrieve raw scan results from security tools.

This module provides tools for storing raw scanner outputs in a structured database,
separate from the validated Vulnerabilities Database. This allows:
1. Raw results to be stored immediately after scans complete
2. Validation agents to review and promote findings to VulnDB
3. Quality control to review scanner coverage
4. Avoiding context overflow by persisting data instead of keeping in memory
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from smolagents import tool

# Database file location
SCANNERS_DB_FILE = Path("reports/scanners_db.json")

def _load_scanners_db() -> dict:
    """Load the scanners database from disk."""
    if SCANNERS_DB_FILE.exists():
        try:
            return json.loads(SCANNERS_DB_FILE.read_text(encoding='utf-8'))
        except:
            pass
    return {
        "metadata": {
            "created_at": datetime.now().isoformat(),
            "version": "1.0"
        },
        "projects": {}
    }

def _save_scanners_db(db: dict):
    """Save the scanners database to disk."""
    SCANNERS_DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCANNERS_DB_FILE.write_text(json.dumps(db, indent=2), encoding='utf-8')

def _get_project_scanners(project_id: str) -> dict:
    """Get or create scanner data for a project."""
    db = _load_scanners_db()
    if project_id not in db["projects"]:
        db["projects"][project_id] = {
            "created_at": datetime.now().isoformat(),
            "scan_groups": {},  # Grouped by tool name
            "total_scans": 0,
            "pending_validation": 0,
            "validated": 0
        }
        _save_scanners_db(db)
    return db["projects"][project_id]


@tool
def add_scan_result(
    project_id: str,
    tool_name: str,
    target: str,
    raw_output: str,
    findings_count: int = 0,
    command_used: str = "",
    scan_type: str = "automatic",
    severity_summary: str = ""
) -> str:
    """Add a raw scan result to the Scanners Database.
    
    IMPORTANT: Use this tool IMMEDIATELY after running any security scanner to persist results.
    This prevents context overflow and ensures no data is lost.
    
    Args:
        project_id: The project ID to associate this scan with
        tool_name: Name of the scanner (e.g., 'nmap', 'nuclei', 'nikto', 'zap', 'sqlmap')
        target: The target that was scanned
        raw_output: The complete raw output from the scanner (will be stored, not kept in memory)
        findings_count: Number of potential findings identified (for tracking)
        command_used: The exact command that was run
        scan_type: Type of scan ('automatic', 'targeted', 'manual', 'cve', 'vuln')
        severity_summary: Brief summary of severities found (e.g., "2 critical, 5 high")
        
    Returns:
        Confirmation with scan ID for reference
    """
    db = _load_scanners_db()
    
    if project_id not in db["projects"]:
        db["projects"][project_id] = {
            "created_at": datetime.now().isoformat(),
            "scan_groups": {},
            "total_scans": 0,
            "pending_validation": 0,
            "validated": 0
        }
    
    project = db["projects"][project_id]
    
    # Create tool group if doesn't exist
    if tool_name not in project["scan_groups"]:
        project["scan_groups"][tool_name] = {
            "tool_name": tool_name,
            "scans": [],
            "total_findings": 0
        }
    
    # Generate scan ID
    scan_id = f"scan_{tool_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{project['total_scans']}"
    
    # Add scan result
    scan_entry = {
        "scan_id": scan_id,
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "command_used": command_used,
        "scan_type": scan_type,
        "findings_count": findings_count,
        "severity_summary": severity_summary,
        "raw_output": raw_output,  # Store full output
        "status": "pending_validation",
        "validated_findings": [],
        "false_positives": []
    }
    
    project["scan_groups"][tool_name]["scans"].append(scan_entry)
    project["scan_groups"][tool_name]["total_findings"] += findings_count
    project["total_scans"] += 1
    project["pending_validation"] += findings_count
    
    _save_scanners_db(db)
    
    return f"""✅ Scan result saved to Scanners Database
📋 Scan ID: {scan_id}
🔧 Tool: {tool_name}
🎯 Target: {target}
📊 Findings: {findings_count} potential findings ({severity_summary or 'no severity info'})
📁 Status: Pending validation

The raw output has been persisted. You can now clear this from your working memory.
Use get_scan_results('{project_id}', '{tool_name}') to retrieve when needed."""


@tool
def get_scan_results(
    project_id: str,
    tool_name: str = "",
    status: str = "",
    limit: int = 5
) -> str:
    """Retrieve scan results from the Scanners Database.
    
    Use this to get previously stored scan results without keeping them in memory.
    
    Args:
        project_id: The project ID to get scans for
        tool_name: Filter by specific tool (optional, empty = all tools)
        status: Filter by status ('pending_validation', 'validated', 'false_positive')
        limit: Maximum number of scans to return per tool (default 5)
        
    Returns:
        Summary of scan results with key information
    """
    db = _load_scanners_db()
    
    if project_id not in db["projects"]:
        return f"❌ Project '{project_id}' not found in Scanners Database"
    
    project = db["projects"][project_id]
    results = []
    
    tools_to_check = [tool_name] if tool_name else list(project["scan_groups"].keys())
    
    for tname in tools_to_check:
        if tname not in project["scan_groups"]:
            continue
            
        group = project["scan_groups"][tname]
        scans = group["scans"]
        
        # Filter by status if specified
        if status:
            scans = [s for s in scans if s.get("status") == status]
        
        # Limit results
        scans = scans[-limit:]
        
        if scans:
            results.append(f"\n### 🔧 {tname.upper()} ({len(group['scans'])} total scans)")
            for scan in scans:
                results.append(f"""
**Scan ID**: {scan['scan_id']}
- Target: {scan['target']}
- Time: {scan['timestamp']}
- Findings: {scan['findings_count']} ({scan.get('severity_summary', 'N/A')})
- Status: {scan['status']}
- Command: `{scan.get('command_used', 'N/A')[:100]}...`
""")
    
    if not results:
        return f"No scan results found for project '{project_id}'" + (f" with tool '{tool_name}'" if tool_name else "")
    
    summary = f"""## Scanners Database - Project: {project_id}

📊 **Summary**:
- Total Scans: {project['total_scans']}
- Pending Validation: {project['pending_validation']}
- Validated: {project['validated']}

{"".join(results)}"""
    
    return summary


@tool
def get_scan_raw_output(project_id: str, scan_id: str) -> str:
    """Get the full raw output of a specific scan.
    
    Use this when you need to analyze the complete scanner output for validation.
    
    Args:
        project_id: The project ID
        scan_id: The specific scan ID to retrieve
        
    Returns:
        The complete raw output from the scanner
    """
    db = _load_scanners_db()
    
    if project_id not in db["projects"]:
        return f"❌ Project '{project_id}' not found"
    
    project = db["projects"][project_id]
    
    for tool_group in project["scan_groups"].values():
        for scan in tool_group["scans"]:
            if scan["scan_id"] == scan_id:
                return f"""## Raw Output for {scan_id}

**Tool**: {tool_group['tool_name']}
**Target**: {scan['target']}
**Command**: {scan.get('command_used', 'N/A')}
**Timestamp**: {scan['timestamp']}

---
### OUTPUT:
```
{scan['raw_output']}
```
"""
    
    return f"❌ Scan '{scan_id}' not found in project '{project_id}'"


@tool
def mark_scan_finding_validated(
    project_id: str,
    scan_id: str,
    finding_description: str,
    is_valid: bool = True,
    vuln_id: str = "",
    notes: str = ""
) -> str:
    """Mark a finding from a scan as validated or false positive.
    
    Use this after manually validating a scanner finding.
    
    Args:
        project_id: The project ID
        scan_id: The scan ID containing the finding
        finding_description: Brief description of the finding being validated
        is_valid: True if the finding is valid, False if it's a false positive
        vuln_id: If valid, the vulnerability ID it was added to in VulnDB
        notes: Additional notes about the validation
        
    Returns:
        Confirmation of the validation
    """
    db = _load_scanners_db()
    
    if project_id not in db["projects"]:
        return f"❌ Project '{project_id}' not found"
    
    project = db["projects"][project_id]
    
    for tool_group in project["scan_groups"].values():
        for scan in tool_group["scans"]:
            if scan["scan_id"] == scan_id:
                validation_entry = {
                    "description": finding_description,
                    "validated_at": datetime.now().isoformat(),
                    "is_valid": is_valid,
                    "vuln_id": vuln_id,
                    "notes": notes
                }
                
                if is_valid:
                    scan["validated_findings"].append(validation_entry)
                    project["validated"] += 1
                else:
                    scan["false_positives"].append(validation_entry)
                
                project["pending_validation"] = max(0, project["pending_validation"] - 1)
                
                # Update status if all findings validated
                total_validated = len(scan["validated_findings"]) + len(scan["false_positives"])
                if total_validated >= scan["findings_count"]:
                    scan["status"] = "validated"
                
                _save_scanners_db(db)
                
                status = "✅ VALID" if is_valid else "❌ FALSE POSITIVE"
                return f"""{status} - Finding marked in Scanners Database
                
Scan: {scan_id}
Finding: {finding_description}
{"Linked to VulnDB: " + vuln_id if vuln_id else ""}
Notes: {notes or 'None'}"""
    
    return f"❌ Scan '{scan_id}' not found"


@tool
def get_pending_validations(project_id: str, limit: int = 10) -> str:
    """Get all scanner findings that need validation.
    
    Use this to see what findings from automated scans need to be manually validated.
    
    Args:
        project_id: The project ID
        limit: Maximum number of pending items to return
        
    Returns:
        List of findings pending validation with details
    """
    db = _load_scanners_db()
    
    if project_id not in db["projects"]:
        return f"❌ Project '{project_id}' not found"
    
    project = db["projects"][project_id]
    pending = []
    
    for tool_name, tool_group in project["scan_groups"].items():
        for scan in tool_group["scans"]:
            if scan["status"] == "pending_validation" and scan["findings_count"] > 0:
                validated_count = len(scan["validated_findings"]) + len(scan["false_positives"])
                remaining = scan["findings_count"] - validated_count
                if remaining > 0:
                    pending.append({
                        "scan_id": scan["scan_id"],
                        "tool": tool_name,
                        "target": scan["target"],
                        "findings": scan["findings_count"],
                        "remaining": remaining,
                        "severity": scan.get("severity_summary", "Unknown")
                    })
    
    if not pending:
        return f"✅ No pending validations for project '{project_id}'. All findings have been reviewed."
    
    pending = pending[:limit]
    
    result = f"""## Pending Validations - Project: {project_id}

⚠️ **{len(pending)} scans need validation**

"""
    for i, p in enumerate(pending, 1):
        result += f"""### {i}. {p['tool'].upper()} Scan
- **Scan ID**: {p['scan_id']}
- **Target**: {p['target']}
- **Findings**: {p['remaining']} of {p['findings']} remaining
- **Severity**: {p['severity']}

"""
    
    result += """
**Next Steps**:
1. Use `get_scan_raw_output(project_id, scan_id)` to review the full output
2. Validate each finding manually
3. Use `mark_scan_finding_validated()` to record validation results
4. Add valid findings to VulnDB using `add_vulnerability_to_project()`
"""
    
    return result


@tool
def get_scanners_db_summary(project_id: str) -> str:
    """Get a high-level summary of the Scanners Database for a project.
    
    Use this for quick status checks and quality control reviews.
    
    Args:
        project_id: The project ID
        
    Returns:
        Summary statistics and coverage information
    """
    db = _load_scanners_db()
    
    if project_id not in db["projects"]:
        return f"❌ Project '{project_id}' not found in Scanners Database"
    
    project = db["projects"][project_id]
    
    tool_stats = []
    for tool_name, group in project["scan_groups"].items():
        total_scans = len(group["scans"])
        total_findings = sum(s["findings_count"] for s in group["scans"])
        validated = sum(len(s["validated_findings"]) for s in group["scans"])
        false_pos = sum(len(s["false_positives"]) for s in group["scans"])
        pending = total_findings - validated - false_pos
        
        tool_stats.append(f"""
### 🔧 {tool_name.upper()}
- Scans: {total_scans}
- Total Findings: {total_findings}
- Validated: {validated} ✅
- False Positives: {false_pos} ❌
- Pending: {pending} ⏳
""")
    
    return f"""## Scanners Database Summary - Project: {project_id}

📅 Created: {project['created_at']}

### 📊 Overall Statistics
- **Total Scans**: {project['total_scans']}
- **Pending Validation**: {project['pending_validation']}
- **Validated Findings**: {project['validated']}

### 🔧 Tools Used
{"".join(tool_stats) if tool_stats else "No scans recorded yet."}

### 📋 Recommended Actions
1. Review pending validations with `get_pending_validations('{project_id}')`
2. Validate high-severity findings first
3. Document false positives with reasons
4. Promote valid findings to Vulnerabilities Database
"""


# Export all tools
__all__ = [
    'add_scan_result',
    'get_scan_results', 
    'get_scan_raw_output',
    'mark_scan_finding_validated',
    'get_pending_validations',
    'get_scanners_db_summary'
]
