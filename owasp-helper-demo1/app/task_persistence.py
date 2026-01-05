"""
Task Persistence Module
=======================
Handles saving and restoring task state for crash recovery and resume functionality.

Tasks are persisted to disk (JSON files) and can be resumed after:
- Agent crashes
- Server restarts
- Manual stops
- Browser disconnections

File structure:
    data/tasks/
        {task_id}.json          # Task state file
        {task_id}_steps.json    # Step-by-step execution log
"""

import json
import os
import time
import threading
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
from enum import Enum


class TaskStatus(str, Enum):
    """Task execution status."""
    PENDING = "pending"           # Created but not started
    RUNNING = "running"           # Currently executing
    PAUSED = "paused"             # Manually paused by user
    INTERRUPTED = "interrupted"   # Stopped unexpectedly (crash, restart)
    COMPLETED = "completed"       # Successfully finished
    FAILED = "failed"             # Finished with error
    CANCELLED = "cancelled"       # Cancelled by user


class TaskStep:
    """Represents a single execution step in a task."""
    def __init__(
        self,
        step_number: int,
        step_type: str,  # "thought", "tool_call", "tool_result", "final"
        content: Any,
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict] = None,
        tool_result: Optional[Any] = None,
        timestamp: Optional[float] = None,
        duration_ms: Optional[float] = None
    ):
        self.step_number = step_number
        self.step_type = step_type
        self.content = content
        self.tool_name = tool_name
        self.tool_args = tool_args
        self.tool_result = tool_result
        self.timestamp = timestamp or time.time()
        self.duration_ms = duration_ms

    def to_dict(self) -> Dict:
        return {
            "step_number": self.step_number,
            "step_type": self.step_type,
            "content": self.content,
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "tool_result": self._truncate_result(self.tool_result),
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms
        }
    
    def _truncate_result(self, result: Any, max_length: int = 50000) -> Any:
        """Truncate large results to prevent huge files."""
        if result is None:
            return None
        result_str = str(result)
        if len(result_str) > max_length:
            return result_str[:max_length] + f"\n... [TRUNCATED - {len(result_str) - max_length} chars omitted]"
        return result

    @classmethod
    def from_dict(cls, data: Dict) -> "TaskStep":
        return cls(
            step_number=data.get("step_number", 0),
            step_type=data.get("step_type", "unknown"),
            content=data.get("content"),
            tool_name=data.get("tool_name"),
            tool_args=data.get("tool_args"),
            tool_result=data.get("tool_result"),
            timestamp=data.get("timestamp"),
            duration_ms=data.get("duration_ms")
        )


class TaskState:
    """Complete state of a task for persistence and recovery."""
    
    def __init__(
        self,
        task_id: str,
        chat_id: str,
        prompt: str,
        task_label: str = "general",
        target_type: Optional[str] = None,
        status: TaskStatus = TaskStatus.PENDING,
        created_at: Optional[float] = None,
        started_at: Optional[float] = None,
        completed_at: Optional[float] = None,
        last_activity_at: Optional[float] = None,
        current_step: int = 0,
        total_steps: int = 0,
        tool_count: int = 0,
        steps: Optional[List[TaskStep]] = None,
        final_result: Optional[str] = None,
        error: Optional[str] = None,
        context: Optional[Dict] = None,  # Additional context for resumption
        report_mode: bool = False
    ):
        self.task_id = task_id
        self.chat_id = chat_id
        self.prompt = prompt
        self.task_label = task_label
        self.target_type = target_type
        self.status = status
        self.created_at = created_at or time.time()
        self.started_at = started_at
        self.completed_at = completed_at
        self.last_activity_at = last_activity_at or time.time()
        self.current_step = current_step
        self.total_steps = total_steps
        self.tool_count = tool_count
        self.steps = steps or []
        self.final_result = final_result
        self.error = error
        self.context = context or {}
        self.report_mode = report_mode

    def to_dict(self) -> Dict:
        return {
            "task_id": self.task_id,
            "chat_id": self.chat_id,
            "prompt": self.prompt,
            "task_label": self.task_label,
            "target_type": self.target_type,
            "status": self.status.value if isinstance(self.status, TaskStatus) else self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "last_activity_at": self.last_activity_at,
            "current_step": self.current_step,
            "total_steps": self.total_steps,
            "tool_count": self.tool_count,
            "final_result": self.final_result,
            "error": self.error,
            "context": self.context,
            "report_mode": self.report_mode,
            # Steps stored separately for large tasks
            "step_count": len(self.steps)
        }

    @classmethod
    def from_dict(cls, data: Dict, steps: Optional[List[TaskStep]] = None) -> "TaskState":
        status = data.get("status", "pending")
        if isinstance(status, str):
            try:
                status = TaskStatus(status)
            except ValueError:
                status = TaskStatus.PENDING
        
        return cls(
            task_id=data.get("task_id", ""),
            chat_id=data.get("chat_id", ""),
            prompt=data.get("prompt", ""),
            task_label=data.get("task_label", "general"),
            target_type=data.get("target_type"),
            status=status,
            created_at=data.get("created_at"),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            last_activity_at=data.get("last_activity_at"),
            current_step=data.get("current_step", 0),
            total_steps=data.get("total_steps", 0),
            tool_count=data.get("tool_count", 0),
            steps=steps or [],
            final_result=data.get("final_result"),
            error=data.get("error"),
            context=data.get("context", {}),
            report_mode=data.get("report_mode", False)
        )

    def add_step(self, step: TaskStep):
        """Add a step and update counters."""
        self.steps.append(step)
        self.current_step = step.step_number
        self.total_steps = max(self.total_steps, step.step_number)
        self.last_activity_at = time.time()
        if step.tool_name:
            self.tool_count += 1

    def mark_running(self):
        """Mark task as running."""
        self.status = TaskStatus.RUNNING
        if not self.started_at:
            self.started_at = time.time()
        self.last_activity_at = time.time()

    def mark_completed(self, result: Optional[str] = None):
        """Mark task as completed."""
        self.status = TaskStatus.COMPLETED
        self.completed_at = time.time()
        self.last_activity_at = time.time()
        if result:
            self.final_result = result

    def mark_failed(self, error: str):
        """Mark task as failed."""
        self.status = TaskStatus.FAILED
        self.completed_at = time.time()
        self.last_activity_at = time.time()
        self.error = error

    def mark_interrupted(self):
        """Mark task as interrupted (for recovery)."""
        self.status = TaskStatus.INTERRUPTED
        self.last_activity_at = time.time()

    def mark_cancelled(self):
        """Mark task as cancelled by user."""
        self.status = TaskStatus.CANCELLED
        self.completed_at = time.time()
        self.last_activity_at = time.time()

    def can_resume(self) -> bool:
        """Check if task can be resumed."""
        return self.status in [TaskStatus.INTERRUPTED, TaskStatus.PAUSED, TaskStatus.RUNNING]

    def get_resume_context(self) -> Dict:
        """Get context needed to resume this task."""
        # Build summary of completed steps
        completed_tools = []
        last_thought = None
        
        for step in self.steps:
            if step.step_type == "tool_call" and step.tool_name:
                completed_tools.append({
                    "tool": step.tool_name,
                    "args_summary": str(step.tool_args)[:200] if step.tool_args else "",
                    "result_summary": str(step.tool_result)[:500] if step.tool_result else ""
                })
            elif step.step_type == "thought":
                last_thought = step.content

        return {
            "task_id": self.task_id,
            "original_prompt": self.prompt,
            "completed_steps": self.current_step,
            "tools_executed": completed_tools,
            "last_thought": last_thought,
            "task_label": self.task_label,
            "target_type": self.target_type,
            "context": self.context
        }


class TaskPersistenceManager:
    """
    Manages task state persistence to disk.
    Thread-safe for concurrent access.
    """
    
    def __init__(self, data_dir: str = "data/tasks"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._cache: Dict[str, TaskState] = {}  # In-memory cache
        self._dirty: set = set()  # Tasks that need saving
        
        # Auto-save interval
        self._auto_save_interval = 5  # seconds
        self._auto_save_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Load interrupted tasks on startup
        self._load_interrupted_tasks()

    def _get_task_file(self, task_id: str) -> Path:
        """Get path to task state file."""
        return self.data_dir / f"{task_id}.json"

    def _get_steps_file(self, task_id: str) -> Path:
        """Get path to task steps file."""
        return self.data_dir / f"{task_id}_steps.json"

    def _load_interrupted_tasks(self):
        """Load all interrupted/running tasks on startup."""
        try:
            for file in self.data_dir.glob("*.json"):
                if file.name.endswith("_steps.json"):
                    continue
                try:
                    with open(file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    task_id = data.get("task_id")
                    status = data.get("status")
                    
                    # Mark running tasks as interrupted (server restarted)
                    if status == "running":
                        data["status"] = "interrupted"
                        with open(file, 'w', encoding='utf-8') as f:
                            json.dump(data, f, indent=2)
                    
                    # Load into cache if resumable
                    if status in ["running", "interrupted", "paused"]:
                        steps = self._load_steps(task_id)
                        self._cache[task_id] = TaskState.from_dict(data, steps)
                        print(f"[TaskPersistence] Loaded interrupted task: {task_id}")
                        
                except Exception as e:
                    print(f"[TaskPersistence] Error loading {file}: {e}")
        except Exception as e:
            print(f"[TaskPersistence] Error scanning task directory: {e}")

    def _load_steps(self, task_id: str) -> List[TaskStep]:
        """Load steps for a task."""
        steps_file = self._get_steps_file(task_id)
        if not steps_file.exists():
            return []
        
        try:
            with open(steps_file, 'r', encoding='utf-8') as f:
                steps_data = json.load(f)
            return [TaskStep.from_dict(s) for s in steps_data]
        except Exception as e:
            print(f"[TaskPersistence] Error loading steps for {task_id}: {e}")
            return []

    def _save_task(self, task: TaskState):
        """Save task state to disk."""
        task_file = self._get_task_file(task.task_id)
        steps_file = self._get_steps_file(task.task_id)
        
        try:
            # Save task state
            with open(task_file, 'w', encoding='utf-8') as f:
                json.dump(task.to_dict(), f, indent=2, default=str)
            
            # Save steps separately (can be large)
            steps_data = [s.to_dict() for s in task.steps]
            with open(steps_file, 'w', encoding='utf-8') as f:
                json.dump(steps_data, f, indent=2, default=str)
                
        except Exception as e:
            print(f"[TaskPersistence] Error saving task {task.task_id}: {e}")

    def create_task(
        self,
        task_id: str,
        chat_id: str,
        prompt: str,
        task_label: str = "general",
        target_type: Optional[str] = None,
        report_mode: bool = False
    ) -> TaskState:
        """Create and persist a new task."""
        with self._lock:
            task = TaskState(
                task_id=task_id,
                chat_id=chat_id,
                prompt=prompt,
                task_label=task_label,
                target_type=target_type,
                status=TaskStatus.PENDING,
                report_mode=report_mode
            )
            self._cache[task_id] = task
            self._dirty.add(task_id)
            self._save_task(task)  # Immediate save for new tasks
            return task

    def get_task(self, task_id: str) -> Optional[TaskState]:
        """Get task by ID."""
        with self._lock:
            if task_id in self._cache:
                return self._cache[task_id]
            
            # Try loading from disk
            task_file = self._get_task_file(task_id)
            if task_file.exists():
                try:
                    with open(task_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    steps = self._load_steps(task_id)
                    task = TaskState.from_dict(data, steps)
                    self._cache[task_id] = task
                    return task
                except Exception as e:
                    print(f"[TaskPersistence] Error loading task {task_id}: {e}")
            return None

    def update_task(self, task_id: str, **kwargs):
        """Update task properties."""
        with self._lock:
            task = self.get_task(task_id)
            if task:
                for key, value in kwargs.items():
                    if hasattr(task, key):
                        setattr(task, key, value)
                task.last_activity_at = time.time()
                self._dirty.add(task_id)

    def add_step(self, task_id: str, step: TaskStep):
        """Add a step to a task."""
        with self._lock:
            task = self.get_task(task_id)
            if task:
                task.add_step(step)
                self._dirty.add(task_id)

    def mark_running(self, task_id: str):
        """Mark task as running."""
        with self._lock:
            task = self.get_task(task_id)
            if task:
                task.mark_running()
                self._dirty.add(task_id)
                self._save_task(task)  # Immediate save

    def mark_completed(self, task_id: str, result: Optional[str] = None):
        """Mark task as completed."""
        with self._lock:
            task = self.get_task(task_id)
            if task:
                task.mark_completed(result)
                self._dirty.add(task_id)
                self._save_task(task)  # Immediate save

    def mark_failed(self, task_id: str, error: str):
        """Mark task as failed."""
        with self._lock:
            task = self.get_task(task_id)
            if task:
                task.mark_failed(error)
                self._dirty.add(task_id)
                self._save_task(task)  # Immediate save

    def mark_interrupted(self, task_id: str):
        """Mark task as interrupted."""
        with self._lock:
            task = self.get_task(task_id)
            if task:
                task.mark_interrupted()
                self._dirty.add(task_id)
                self._save_task(task)  # Immediate save

    def mark_cancelled(self, task_id: str):
        """Mark task as cancelled."""
        with self._lock:
            task = self.get_task(task_id)
            if task:
                task.mark_cancelled()
                self._dirty.add(task_id)
                self._save_task(task)  # Immediate save

    def get_active_tasks(self, chat_id: Optional[str] = None) -> List[TaskState]:
        """Get all currently running or interrupted tasks."""
        with self._lock:
            active_tasks = []
            for task in self._cache.values():
                if task.status in [TaskStatus.RUNNING, TaskStatus.INTERRUPTED, TaskStatus.PAUSED]:
                    if chat_id is None or task.chat_id == chat_id:
                        active_tasks.append(task)
            return active_tasks

    def get_resumable_tasks(self) -> List[TaskState]:
        """Get all tasks that can be resumed."""
        with self._lock:
            resumable = []
            for task in self._cache.values():
                if task.can_resume():
                    resumable.append(task)
            return resumable

    def get_all_tasks(self, status_filter: Optional[List[str]] = None) -> List[TaskState]:
        """Get all tasks, optionally filtered by status."""
        with self._lock:
            # Load all tasks from disk
            for file in self.data_dir.glob("*.json"):
                if file.name.endswith("_steps.json"):
                    continue
                task_id = file.stem
                if task_id not in self._cache:
                    self.get_task(task_id)  # Load into cache
            
            tasks = list(self._cache.values())
            
            if status_filter:
                tasks = [t for t in tasks if t.status.value in status_filter]
            
            # Sort by created_at descending
            tasks.sort(key=lambda t: t.created_at or 0, reverse=True)
            return tasks

    def delete_task(self, task_id: str):
        """Delete a task and its files."""
        with self._lock:
            if task_id in self._cache:
                del self._cache[task_id]
            if task_id in self._dirty:
                self._dirty.remove(task_id)
            
            task_file = self._get_task_file(task_id)
            steps_file = self._get_steps_file(task_id)
            
            try:
                if task_file.exists():
                    task_file.unlink()
                if steps_file.exists():
                    steps_file.unlink()
            except Exception as e:
                print(f"[TaskPersistence] Error deleting task {task_id}: {e}")

    def cleanup_old_tasks(self, max_age_hours: int = 168):  # 7 days default
        """Remove completed/failed/cancelled tasks older than max_age_hours."""
        with self._lock:
            current_time = time.time()
            max_age_seconds = max_age_hours * 3600
            
            tasks_to_remove = []
            for task_id, task in self._cache.items():
                if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
                    age = current_time - (task.completed_at or task.created_at or current_time)
                    if age > max_age_seconds:
                        tasks_to_remove.append(task_id)
            
            for task_id in tasks_to_remove:
                self.delete_task(task_id)
            
            if tasks_to_remove:
                print(f"[TaskPersistence] Cleaned up {len(tasks_to_remove)} old tasks")

    def flush(self):
        """Save all dirty tasks to disk."""
        with self._lock:
            for task_id in list(self._dirty):
                task = self._cache.get(task_id)
                if task:
                    self._save_task(task)
            self._dirty.clear()

    def start_auto_save(self):
        """Start background auto-save thread."""
        if self._auto_save_thread and self._auto_save_thread.is_alive():
            return
        
        self._stop_event.clear()
        
        def auto_save_worker():
            while not self._stop_event.is_set():
                try:
                    self.flush()
                except Exception as e:
                    print(f"[TaskPersistence] Auto-save error: {e}")
                self._stop_event.wait(self._auto_save_interval)
        
        self._auto_save_thread = threading.Thread(target=auto_save_worker, daemon=True)
        self._auto_save_thread.start()
        print("[TaskPersistence] Auto-save thread started")

    def stop_auto_save(self):
        """Stop auto-save thread and flush pending changes."""
        self._stop_event.set()
        if self._auto_save_thread:
            self._auto_save_thread.join(timeout=5)
        self.flush()
        print("[TaskPersistence] Auto-save thread stopped")


# Global instance
_persistence_manager: Optional[TaskPersistenceManager] = None

def get_task_persistence() -> TaskPersistenceManager:
    """Get or create the global task persistence manager."""
    global _persistence_manager
    if _persistence_manager is None:
        _persistence_manager = TaskPersistenceManager()
    return _persistence_manager


def build_resume_prompt(task: TaskState) -> str:
    """
    Build a prompt that allows the agent to resume an interrupted task.
    Includes context about what was already done.
    """
    context = task.get_resume_context()
    
    tools_summary = ""
    if context["tools_executed"]:
        tools_summary = "\n\n### Tools Already Executed:\n"
        for i, tool in enumerate(context["tools_executed"][-10:], 1):  # Last 10 tools
            tools_summary += f"{i}. **{tool['tool']}**\n"
            if tool['args_summary']:
                tools_summary += f"   Args: {tool['args_summary']}\n"
            if tool['result_summary']:
                tools_summary += f"   Result: {tool['result_summary']}\n"
    
    last_thought_section = ""
    if context["last_thought"]:
        last_thought_section = f"\n\n### Last Agent Thought:\n{context['last_thought']}"
    
    resume_prompt = f"""[RESUMING INTERRUPTED TASK]

This task was interrupted and is being resumed. Here is the context:

### Original Request:
{context['original_prompt']}

### Progress Before Interruption:
- Completed Steps: {context['completed_steps']}
- Task Type: {context['task_label']}
- Target: {context['target_type'] or 'Not specified'}
{tools_summary}{last_thought_section}

### Instructions:
Continue this task from where it was interrupted. Do NOT repeat tools that have already been executed unless you need updated results. Focus on completing the remaining work.

If you're unsure what was already done, briefly summarize the progress based on the tool history above, then continue with the next logical step.
"""
    return resume_prompt
