"""
Sub-Agent Task Management System

This module provides tools for the main orchestrator agent to:
1. Create and delegate tasks to specialized sub-agents
2. Monitor task progress and status
3. Coordinate work between scanning, validation, QC, and reporting agents
4. Track which findings need attention

The system helps avoid context overflow by:
- Breaking work into discrete tasks
- Persisting task state to disk
- Allowing agents to focus on specific responsibilities
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from smolagents import tool

# Task database file
TASKS_DB_FILE = Path("reports/agent_tasks.json")


class SubAgentType(str, Enum):
    SCANNER = "scanner"           # Runs automated scans
    VALIDATOR = "validator"       # Validates and exploits findings
    QC = "quality_control"        # Reviews quality of findings
    REPORTER = "reporter"         # Prepares final reports
    ORCHESTRATOR = "orchestrator" # Main coordinator


class TaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    NEEDS_REVIEW = "needs_review"


def _load_tasks_db() -> dict:
    """Load the tasks database."""
    if TASKS_DB_FILE.exists():
        try:
            return json.loads(TASKS_DB_FILE.read_text(encoding='utf-8'))
        except:
            pass
    return {
        "metadata": {
            "created_at": datetime.now().isoformat(),
            "version": "1.0"
        },
        "projects": {}
    }


def _save_tasks_db(db: dict):
    """Save the tasks database."""
    TASKS_DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    TASKS_DB_FILE.write_text(json.dumps(db, indent=2), encoding='utf-8')


def _get_project_tasks(project_id: str) -> dict:
    """Get or create task data for a project."""
    db = _load_tasks_db()
    if project_id not in db["projects"]:
        db["projects"][project_id] = {
            "created_at": datetime.now().isoformat(),
            "tasks": [],
            "task_counter": 0,
            "summary": {
                "total": 0,
                "pending": 0,
                "in_progress": 0,
                "completed": 0,
                "failed": 0
            }
        }
        _save_tasks_db(db)
    return db["projects"][project_id]


@tool
def create_subagent_task(
    project_id: str,
    agent_type: str,
    task_title: str,
    task_description: str,
    target: str = "",
    priority: str = "medium",
    depends_on: str = "",
    metadata: str = "{}"
) -> str:
    """Create a new task for a sub-agent to execute.
    
    Use this as the ORCHESTRATOR to delegate work to specialized sub-agents.
    
    Agent Types:
    - 'scanner': Run automated security scans (nmap, nuclei, nikto, etc.)
    - 'validator': Validate findings, exploit vulnerabilities, eliminate false positives
    - 'quality_control': Review findings quality, ensure completeness
    - 'reporter': Prepare and format final report sections
    
    Args:
        project_id: The project ID
        agent_type: Type of sub-agent ('scanner', 'validator', 'quality_control', 'reporter')
        task_title: Brief title for the task
        task_description: Detailed description of what needs to be done
        target: Target URL/IP for scanning tasks
        priority: Task priority ('critical', 'high', 'medium', 'low')
        depends_on: Comma-separated list of task IDs this depends on
        metadata: JSON string with additional task-specific data
        
    Returns:
        Task ID and confirmation
    """
    db = _load_tasks_db()
    
    # Validate agent type
    valid_types = ['scanner', 'validator', 'quality_control', 'reporter', 'orchestrator']
    if agent_type not in valid_types:
        return f"❌ Invalid agent_type. Must be one of: {', '.join(valid_types)}"
    
    if project_id not in db["projects"]:
        db["projects"][project_id] = {
            "created_at": datetime.now().isoformat(),
            "tasks": [],
            "task_counter": 0,
            "summary": {"total": 0, "pending": 0, "in_progress": 0, "completed": 0, "failed": 0}
        }
    
    project = db["projects"][project_id]
    project["task_counter"] += 1
    
    task_id = f"task_{agent_type}_{project['task_counter']:04d}"
    
    # Parse metadata
    try:
        meta = json.loads(metadata) if metadata else {}
    except:
        meta = {}
    
    task = {
        "task_id": task_id,
        "agent_type": agent_type,
        "title": task_title,
        "description": task_description,
        "target": target,
        "priority": priority,
        "status": TaskStatus.PENDING.value,
        "depends_on": [d.strip() for d in depends_on.split(",") if d.strip()],
        "created_at": datetime.now().isoformat(),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None,
        "metadata": meta,
        "artifacts": [],  # References to scan results, findings, etc.
        "notes": []
    }
    
    project["tasks"].append(task)
    project["summary"]["total"] += 1
    project["summary"]["pending"] += 1
    
    _save_tasks_db(db)
    
    # Icons for agent types
    icons = {
        "scanner": "🔍",
        "validator": "✅",
        "quality_control": "📋",
        "reporter": "📝",
        "orchestrator": "🎯"
    }
    
    return f"""{icons.get(agent_type, '📌')} Task Created Successfully

**Task ID**: {task_id}
**Type**: {agent_type.upper()}
**Title**: {task_title}
**Target**: {target or 'N/A'}
**Priority**: {priority.upper()}
**Status**: PENDING

**Description**:
{task_description}

{"**Depends On**: " + depends_on if depends_on else ""}

---
Next: Use `get_pending_tasks('{project_id}', '{agent_type}')` to see tasks for this agent type.
"""


@tool
def get_pending_tasks(project_id: str, agent_type: str = "") -> str:
    """Get pending tasks, optionally filtered by agent type.
    
    Use this to see what work needs to be done by a specific sub-agent.
    
    Args:
        project_id: The project ID
        agent_type: Filter by agent type (optional)
        
    Returns:
        List of pending tasks with details
    """
    db = _load_tasks_db()
    
    if project_id not in db["projects"]:
        return f"❌ Project '{project_id}' not found"
    
    project = db["projects"][project_id]
    tasks = project["tasks"]
    
    # Filter by status and optionally agent type
    pending = [t for t in tasks if t["status"] in [TaskStatus.PENDING.value, TaskStatus.NEEDS_REVIEW.value]]
    if agent_type:
        pending = [t for t in pending if t["agent_type"] == agent_type]
    
    # Check dependencies
    completed_ids = {t["task_id"] for t in tasks if t["status"] == TaskStatus.COMPLETED.value}
    
    if not pending:
        return f"✅ No pending tasks for project '{project_id}'" + (f" (agent type: {agent_type})" if agent_type else "")
    
    # Sort by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    pending.sort(key=lambda t: priority_order.get(t["priority"], 2))
    
    icons = {"scanner": "🔍", "validator": "✅", "quality_control": "📋", "reporter": "📝"}
    priority_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    
    result = f"## Pending Tasks - Project: {project_id}\n\n"
    if agent_type:
        result += f"**Filtered by**: {agent_type}\n\n"
    
    for task in pending:
        # Check if dependencies are met
        deps_met = all(d in completed_ids for d in task["depends_on"])
        blocked = "⛔ BLOCKED (dependencies)" if not deps_met and task["depends_on"] else ""
        
        result += f"""### {icons.get(task['agent_type'], '📌')} {task['task_id']}
**{task['title']}** {priority_icons.get(task['priority'], '')} {task['priority'].upper()} {blocked}
- Agent: {task['agent_type']}
- Target: {task.get('target') or 'N/A'}
- Created: {task['created_at']}
{f"- Depends on: {', '.join(task['depends_on'])}" if task['depends_on'] else ""}

{task['description'][:200]}{'...' if len(task['description']) > 200 else ''}

---
"""
    
    result += f"\n**Total Pending**: {len(pending)} task(s)"
    result += f"\n\nUse `start_task('{project_id}', 'TASK_ID')` to begin working on a task."
    
    return result


@tool
def start_task(project_id: str, task_id: str) -> str:
    """Mark a task as started/in-progress.
    
    Call this when beginning work on a task.
    
    Args:
        project_id: The project ID
        task_id: The task ID to start
        
    Returns:
        Task details and instructions
    """
    db = _load_tasks_db()
    
    if project_id not in db["projects"]:
        return f"❌ Project '{project_id}' not found"
    
    project = db["projects"][project_id]
    
    for task in project["tasks"]:
        if task["task_id"] == task_id:
            if task["status"] == TaskStatus.IN_PROGRESS.value:
                return f"⚠️ Task '{task_id}' is already in progress"
            
            # Check dependencies
            completed_ids = {t["task_id"] for t in project["tasks"] if t["status"] == TaskStatus.COMPLETED.value}
            unmet_deps = [d for d in task["depends_on"] if d not in completed_ids]
            if unmet_deps:
                return f"⛔ Cannot start task '{task_id}' - waiting on dependencies: {', '.join(unmet_deps)}"
            
            old_status = task["status"]
            task["status"] = TaskStatus.IN_PROGRESS.value
            task["started_at"] = datetime.now().isoformat()
            
            project["summary"]["pending"] = max(0, project["summary"]["pending"] - 1)
            project["summary"]["in_progress"] += 1
            
            _save_tasks_db(db)
            
            icons = {"scanner": "🔍", "validator": "✅", "quality_control": "📋", "reporter": "📝"}
            
            return f"""## {icons.get(task['agent_type'], '📌')} Task Started: {task_id}

**Title**: {task['title']}
**Agent Type**: {task['agent_type']}
**Target**: {task.get('target') or 'N/A'}
**Priority**: {task['priority'].upper()}

### Description:
{task['description']}

### Metadata:
```json
{json.dumps(task.get('metadata', {}), indent=2)}
```

---
**Instructions**:
1. Execute the task as described
2. Use appropriate tools based on agent type
3. Save artifacts with `add_task_artifact()`
4. Complete with `complete_task()` when done
"""
    
    return f"❌ Task '{task_id}' not found in project '{project_id}'"


@tool
def complete_task(
    project_id: str,
    task_id: str,
    result_summary: str,
    artifacts_created: str = "",
    follow_up_needed: bool = False,
    follow_up_description: str = ""
) -> str:
    """Mark a task as completed with results.
    
    Call this when you've finished a task.
    
    Args:
        project_id: The project ID
        task_id: The task ID to complete
        result_summary: Summary of what was accomplished
        artifacts_created: Comma-separated list of artifact IDs created (scan IDs, vuln IDs, etc.)
        follow_up_needed: If True, creates a follow-up task
        follow_up_description: Description for the follow-up task
        
    Returns:
        Completion confirmation
    """
    db = _load_tasks_db()
    
    if project_id not in db["projects"]:
        return f"❌ Project '{project_id}' not found"
    
    project = db["projects"][project_id]
    
    for task in project["tasks"]:
        if task["task_id"] == task_id:
            task["status"] = TaskStatus.COMPLETED.value
            task["completed_at"] = datetime.now().isoformat()
            task["result"] = result_summary
            
            if artifacts_created:
                task["artifacts"].extend([a.strip() for a in artifacts_created.split(",") if a.strip()])
            
            project["summary"]["in_progress"] = max(0, project["summary"]["in_progress"] - 1)
            project["summary"]["completed"] += 1
            
            _save_tasks_db(db)
            
            result = f"""✅ Task Completed: {task_id}

**Title**: {task['title']}
**Duration**: {task['started_at']} → {task['completed_at']}

### Result Summary:
{result_summary}

{"### Artifacts Created: " + artifacts_created if artifacts_created else ""}
"""
            
            # Create follow-up task if needed
            if follow_up_needed and follow_up_description:
                result += f"\n\n🔄 Follow-up task will be created..."
                # The orchestrator should create the follow-up task
            
            return result
    
    return f"❌ Task '{task_id}' not found"


@tool
def fail_task(project_id: str, task_id: str, error_message: str, retry: bool = False) -> str:
    """Mark a task as failed with error details.
    
    Call this if a task cannot be completed.
    
    Args:
        project_id: The project ID
        task_id: The task ID that failed
        error_message: Description of what went wrong
        retry: If True, reset to pending for retry
        
    Returns:
        Failure acknowledgment
    """
    db = _load_tasks_db()
    
    if project_id not in db["projects"]:
        return f"❌ Project '{project_id}' not found"
    
    project = db["projects"][project_id]
    
    for task in project["tasks"]:
        if task["task_id"] == task_id:
            if retry:
                task["status"] = TaskStatus.PENDING.value
                task["notes"].append({
                    "timestamp": datetime.now().isoformat(),
                    "note": f"RETRY: {error_message}"
                })
                project["summary"]["in_progress"] = max(0, project["summary"]["in_progress"] - 1)
                project["summary"]["pending"] += 1
            else:
                task["status"] = TaskStatus.FAILED.value
                task["completed_at"] = datetime.now().isoformat()
                task["error"] = error_message
                project["summary"]["in_progress"] = max(0, project["summary"]["in_progress"] - 1)
                project["summary"]["failed"] += 1
            
            _save_tasks_db(db)
            
            if retry:
                return f"🔄 Task '{task_id}' marked for retry. Error: {error_message}"
            else:
                return f"❌ Task '{task_id}' marked as FAILED. Error: {error_message}"
    
    return f"❌ Task '{task_id}' not found"


@tool
def get_task_status(project_id: str, task_id: str = "") -> str:
    """Get status of a specific task or all tasks in the project.
    
    Use this to monitor progress.
    
    Args:
        project_id: The project ID
        task_id: Specific task ID (optional, empty = show summary)
        
    Returns:
        Task status information
    """
    db = _load_tasks_db()
    
    if project_id not in db["projects"]:
        return f"❌ Project '{project_id}' not found"
    
    project = db["projects"][project_id]
    
    if task_id:
        for task in project["tasks"]:
            if task["task_id"] == task_id:
                status_icons = {
                    "pending": "⏳",
                    "in_progress": "🔄",
                    "completed": "✅",
                    "failed": "❌",
                    "blocked": "⛔",
                    "needs_review": "👀"
                }
                
                return f"""## Task Status: {task_id}

**Status**: {status_icons.get(task['status'], '❓')} {task['status'].upper()}
**Title**: {task['title']}
**Agent Type**: {task['agent_type']}
**Priority**: {task['priority']}

**Timeline**:
- Created: {task['created_at']}
- Started: {task['started_at'] or 'Not started'}
- Completed: {task['completed_at'] or 'Not completed'}

**Result**: {task.get('result') or 'N/A'}
**Error**: {task.get('error') or 'None'}

**Artifacts**: {', '.join(task['artifacts']) or 'None'}
"""
        return f"❌ Task '{task_id}' not found"
    
    # Show summary
    summary = project["summary"]
    tasks_by_type = {}
    for task in project["tasks"]:
        atype = task["agent_type"]
        if atype not in tasks_by_type:
            tasks_by_type[atype] = {"total": 0, "completed": 0, "in_progress": 0, "pending": 0}
        tasks_by_type[atype]["total"] += 1
        if task["status"] == "completed":
            tasks_by_type[atype]["completed"] += 1
        elif task["status"] == "in_progress":
            tasks_by_type[atype]["in_progress"] += 1
        elif task["status"] == "pending":
            tasks_by_type[atype]["pending"] += 1
    
    result = f"""## Task Summary - Project: {project_id}

### Overall Progress
- **Total Tasks**: {summary['total']}
- ⏳ Pending: {summary['pending']}
- 🔄 In Progress: {summary['in_progress']}
- ✅ Completed: {summary['completed']}
- ❌ Failed: {summary['failed']}

### By Agent Type
"""
    
    icons = {"scanner": "🔍", "validator": "✅", "quality_control": "📋", "reporter": "📝"}
    for atype, stats in tasks_by_type.items():
        result += f"""
{icons.get(atype, '📌')} **{atype.upper()}**: {stats['completed']}/{stats['total']} completed ({stats['in_progress']} in progress)"""
    
    return result


@tool
def add_task_note(project_id: str, task_id: str, note: str) -> str:
    """Add a note to a task for tracking progress or issues.
    
    Args:
        project_id: The project ID
        task_id: The task ID
        note: The note to add
        
    Returns:
        Confirmation
    """
    db = _load_tasks_db()
    
    if project_id not in db["projects"]:
        return f"❌ Project '{project_id}' not found"
    
    for task in db["projects"][project_id]["tasks"]:
        if task["task_id"] == task_id:
            task["notes"].append({
                "timestamp": datetime.now().isoformat(),
                "note": note
            })
            _save_tasks_db(db)
            return f"📝 Note added to task '{task_id}'"
    
    return f"❌ Task '{task_id}' not found"


# Export all tools
__all__ = [
    'create_subagent_task',
    'get_pending_tasks',
    'start_task',
    'complete_task',
    'fail_task',
    'get_task_status',
    'add_task_note'
]
