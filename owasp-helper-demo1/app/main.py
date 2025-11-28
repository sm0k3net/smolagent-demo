from __future__ import annotations
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from enum import Enum
from app.agents.owasp_agent import build_owasp_agent
from app.tools.report_tools import (
    enable_report_mode, disable_report_mode, get_report_status,
    generate_html_report, generate_markdown_report,
    is_report_mode_enabled, get_report_data, add_recon_data,
    track_tool_usage, get_session_tools
)
import asyncio
import json
import base64
import queue
import threading
import uuid
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, Any


# Task management enums and models
class TaskStatus(str, Enum):
    pending = "pending"
    running = "running"
    paused = "paused"
    completed = "completed"
    cancelled = "cancelled"
    failed = "failed"


class Task(BaseModel):
    id: str
    prompt: str
    status: TaskStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[str] = None
    error: Optional[str] = None
    tool_count: int = 0
    step_count: int = 0


app = FastAPI(title="OWASP SmolAgent")
agent = None
startup_lock = asyncio.Lock()
executor = ThreadPoolExecutor(max_workers=8)

# File storage for sessions
file_store: dict[str, list[dict]] = {}

# Task management
task_store: Dict[str, Task] = {}
tasks_store: Dict[str, Dict[str, Any]] = {}
task_queues: Dict[str, queue.Queue] = {}

# API Keys storage with file persistence
API_KEYS_FILE = os.path.join(os.path.dirname(__file__), ".api_keys.json")
api_keys_store: Dict[str, str] = {}

def load_api_keys_from_file():
    """Load API keys from file."""
    global api_keys_store
    default_keys = {
        "SHODAN_API_KEY": "",
        "VIRUSTOTAL_API_KEY": "",
        "HUNTER_API_KEY": "",
        "SECURITYTRAILS_API_KEY": "",
        "HIBP_API_KEY": "",
        "CENSYS_API_KEY": "",
        "ALIENVAULT_API_KEY": "",
    }
    
    # Try to load from file first
    if os.path.exists(API_KEYS_FILE):
        try:
            with open(API_KEYS_FILE, 'r') as f:
                saved_keys = json.load(f)
                api_keys_store = {**default_keys, **saved_keys}
        except Exception as e:
            print(f"Error loading API keys: {e}")
            api_keys_store = default_keys
    else:
        api_keys_store = default_keys
    
    # Also check environment variables (they override file)
    for key in api_keys_store:
        env_val = os.getenv(key, "")
        if env_val:
            api_keys_store[key] = env_val
    
    # Set environment variables for tools to use
    for key, value in api_keys_store.items():
        if value:
            os.environ[key] = value

def save_api_keys_to_file():
    """Save API keys to file."""
    try:
        # Only save non-empty keys
        keys_to_save = {k: v for k, v in api_keys_store.items() if v}
        with open(API_KEYS_FILE, 'w') as f:
            json.dump(keys_to_save, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving API keys: {e}")
        return False

class FileUpload(BaseModel):
    session_id: str
    filename: str
    content: str  # Base64 encoded content

class APIKeyUpdate(BaseModel):
    service: str
    api_key: str

@app.on_event("startup")
async def startup():
    global agent, api_keys_store
    async with startup_lock:
        if agent is None:
            # Load API keys from file/environment
            load_api_keys_from_file()
            agent = build_owasp_agent()

# API Keys management endpoints
@app.get("/api/keys")
async def get_api_keys():
    """Get list of configured API keys (masked)."""
    masked = {}
    for key, value in api_keys_store.items():
        if value:
            masked[key] = value[:4] + "..." + value[-4:] if len(value) > 8 else "****"
        else:
            masked[key] = ""
    return JSONResponse(masked)

@app.post("/api/keys")
async def update_api_key(update: APIKeyUpdate):
    """Update an API key and persist to file."""
    global api_keys_store
    # Allow adding new keys or updating existing ones
    api_keys_store[update.service] = update.api_key
    # Also update environment variable for tools to use
    os.environ[update.service] = update.api_key
    # Save to file
    save_api_keys_to_file()
    return JSONResponse({"success": True, "service": update.service})

@app.delete("/api/keys/{service}")
async def delete_api_key(service: str):
    """Delete an API key."""
    global api_keys_store
    if service in api_keys_store:
        api_keys_store[service] = ""
        if service in os.environ:
            del os.environ[service]
        save_api_keys_to_file()
        return JSONResponse({"success": True, "service": service})
    return JSONResponse({"error": "Unknown service"}, status_code=404)

@app.get("/api/keys/export")
async def export_api_keys():
    """Export API keys as JSON (for backup)."""
    # Only export non-empty keys
    keys_to_export = {k: v for k, v in api_keys_store.items() if v}
    return JSONResponse(keys_to_export)

@app.post("/api/keys/import")
async def import_api_keys(keys: Dict[str, str]):
    """Import API keys from JSON."""
    global api_keys_store
    for key, value in keys.items():
        if value:
            api_keys_store[key] = value
            os.environ[key] = value
    save_api_keys_to_file()
    return JSONResponse({"success": True, "imported": len(keys)})

# Task management endpoints
@app.get("/api/tasks")
async def get_tasks():
    """Get all tasks."""
    tasks = [task.model_dump() for task in task_store.values()]
    # Convert datetime to ISO strings for JSON serialization
    for task in tasks:
        if task.get("created_at"):
            task["created_at"] = task["created_at"].isoformat()
        if task.get("started_at"):
            task["started_at"] = task["started_at"].isoformat()
        if task.get("completed_at"):
            task["completed_at"] = task["completed_at"].isoformat()
    return JSONResponse(tasks)

@app.delete("/api/tasks/{task_id}")
async def cancel_task(task_id: str):
    """Cancel a running task."""
    if task_id in task_store:
        task_store[task_id].status = TaskStatus.cancelled
        return JSONResponse({"success": True, "task_id": task_id, "status": "cancelled"})
    return JSONResponse({"error": "Task not found"}, status_code=404)

@app.patch("/api/tasks/{task_id}")
async def update_task(task_id: str):
    """Pause/resume a task."""
    if task_id in task_store:
        task = task_store[task_id]
        if task.status == TaskStatus.paused:
            task.status = TaskStatus.running
        elif task.status == TaskStatus.running:
            task.status = TaskStatus.paused
        return JSONResponse({"success": True, "task_id": task_id, "status": task.status.value})
    return JSONResponse({"error": "Task not found"}, status_code=404)

@app.get("/api/tasks/{task_id}")
async def get_task(task_id: str):
    """Get a specific task with its full result."""
    if task_id in task_store:
        task = task_store[task_id].model_dump()
        if task.get("created_at"):
            task["created_at"] = task["created_at"].isoformat()
        if task.get("started_at"):
            task["started_at"] = task["started_at"].isoformat()
        if task.get("completed_at"):
            task["completed_at"] = task["completed_at"].isoformat()
        return JSONResponse(task)
    return JSONResponse({"error": "Task not found"}, status_code=404)

@app.on_event("startup")
async def startup():
    global agent
    async with startup_lock:
        if agent is None:
            agent = build_owasp_agent()

# File upload endpoint
@app.post("/upload")
async def upload_file(upload: FileUpload):
    """Handle file uploads via JSON with base64 content."""
    try:
        content = base64.b64decode(upload.content).decode('utf-8')
        is_text = True
    except Exception:
        try:
            content = base64.b64decode(upload.content)
            content = f"[Binary file: {len(content)} bytes]"
            is_text = False
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to decode file: {str(e)}")
    
    file_info = {
        "filename": upload.filename,
        "content": content,
        "is_text": is_text,
    }
    
    if upload.session_id not in file_store:
        file_store[upload.session_id] = []
    file_store[upload.session_id].append(file_info)
    
    return JSONResponse({"success": True, "filename": upload.filename, "is_text": is_text})

# Report download endpoint
@app.get("/api/report/{format}")
async def get_report(format: str):
    """Get report in specified format."""
    if not is_report_mode_enabled():
        return JSONResponse({"error": "Report mode not enabled"}, status_code=400)
    
    if format == "html":
        return JSONResponse({"content": generate_html_report(), "format": "html"})
    elif format == "markdown":
        return JSONResponse({"content": generate_markdown_report(), "format": "markdown"})
    else:
        return JSONResponse({"error": "Invalid format"}, status_code=400)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OWASP SmolAgent - Professional Security Testing Assistant</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
  --primary: #6366f1;
  --primary-dark: #4f46e5;
  --primary-light: #818cf8;
  --secondary: #0ea5e9;
  --success: #10b981;
  --warning: #f59e0b;
  --danger: #ef4444;
  --dark: #1e293b;
  --darker: #0f172a;
  --light: #f8fafc;
  --gray-100: #f1f5f9;
  --gray-200: #e2e8f0;
  --gray-300: #cbd5e1;
  --gray-400: #94a3b8;
  --gray-500: #64748b;
  --gray-600: #475569;
  --gradient-primary: linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #a855f7 100%);
  --gradient-dark: linear-gradient(135deg, #1e293b 0%, #334155 100%);
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
  --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -2px rgba(0,0,0,0.1);
  --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -4px rgba(0,0,0,0.1);
  --shadow-xl: 0 20px 25px -5px rgba(0,0,0,0.1), 0 8px 10px -6px rgba(0,0,0,0.1);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body {
  height: 100%;
  overflow: hidden;
}
body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: var(--darker);
  display: flex;
  flex-direction: column;
  color: var(--light);
}
header {
  background: var(--gradient-dark);
  padding: 1rem 2rem;
  border-bottom: 1px solid rgba(255,255,255,0.1);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 1rem;
  z-index: 100;
  backdrop-filter: blur(10px);
  flex-shrink: 0;
}
.logo-section {
  display: flex;
  align-items: center;
  gap: 1rem;
}
.logo-icon {
  width: 48px;
  height: 48px;
  background: var(--gradient-primary);
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.5rem;
  box-shadow: var(--shadow-lg);
}
h1 {
  font-size: 1.5rem;
  font-weight: 700;
  background: var(--gradient-primary);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}
.header-subtitle {
  font-size: 0.8rem;
  color: var(--gray-400);
  font-weight: 400;
}
.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.35rem 0.75rem;
  border-radius: 20px;
  font-size: 0.75rem;
  font-weight: 500;
  margin-left: 1rem;
}
.status-badge.connected {
  background: rgba(16, 185, 129, 0.15);
  color: var(--success);
  border: 1px solid rgba(16, 185, 129, 0.3);
}
.status-badge.disconnected {
  background: rgba(239, 68, 68, 0.15);
  color: var(--danger);
  border: 1px solid rgba(239, 68, 68, 0.3);
}
.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  animation: pulse 2s infinite;
}
.status-badge.connected .status-dot { background: var(--success); }
.status-badge.disconnected .status-dot { background: var(--danger); }
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}
.header-actions {
  display: flex;
  gap: 0.75rem;
  align-items: center;
  flex-wrap: wrap;
}
.btn {
  padding: 0.6rem 1.2rem;
  border: none;
  border-radius: 8px;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s ease;
  font-weight: 500;
  font-family: inherit;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
}
.btn-primary {
  background: var(--gradient-primary);
  color: white;
  box-shadow: var(--shadow-md);
}
.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg), 0 0 20px rgba(99, 102, 241, 0.4);
}
.btn-secondary {
  background: rgba(255,255,255,0.1);
  color: var(--gray-200);
  border: 1px solid rgba(255,255,255,0.15);
}
.btn-secondary:hover {
  background: rgba(255,255,255,0.15);
  border-color: rgba(255,255,255,0.25);
}
.btn-success {
  background: var(--success);
  color: white;
}
.btn-success:hover {
  background: #059669;
}

/* Report Mode Toggle - Switch Style */
.toggle-switch-wrapper {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem 1rem;
  background: rgba(255,255,255,0.05);
  border-radius: 10px;
  border: 1px solid rgba(255,255,255,0.1);
}
.toggle-switch {
  position: relative;
  width: 48px;
  height: 26px;
}
.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}
.toggle-slider {
  position: absolute;
  cursor: pointer;
  top: 0; left: 0; right: 0; bottom: 0;
  background: var(--gray-600);
  border-radius: 26px;
  transition: 0.3s;
}
.toggle-slider:before {
  position: absolute;
  content: "";
  height: 20px;
  width: 20px;
  left: 3px;
  bottom: 3px;
  background: white;
  border-radius: 50%;
  transition: 0.3s;
}
.toggle-switch input:checked + .toggle-slider {
  background: var(--success);
}
.toggle-switch input:checked + .toggle-slider:before {
  transform: translateX(22px);
}
.toggle-label {
  color: var(--gray-300);
  font-size: 0.85rem;
  font-weight: 500;
}
.toggle-switch-wrapper.active .toggle-label {
  color: var(--success);
}

/* Main layout with sidebar */
.main-wrapper {
  flex: 1;
  display: flex;
  max-width: 100%;
  overflow: hidden;
  min-height: 0;
}

/* Sidebar */
#sidebar {
  width: 56px;
  min-width: 56px;
  background: var(--dark);
  border-right: 1px solid rgba(255,255,255,0.1);
  display: flex;
  flex-direction: column;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  height: 100%;
  overflow: hidden;
}
#sidebar.expanded {
  width: 400px;
  min-width: 400px;
}
/* Hide all content except toggle when collapsed */
#sidebar:not(.expanded) .sidebar-tabs,
#sidebar:not(.expanded) .tab-content,
#sidebar:not(.expanded) .sidebar-header,
#sidebar:not(.expanded) .sidebar-stats {
  display: none !important;
}
.sidebar-toggle {
  padding: 1rem;
  background: transparent;
  color: var(--gray-400);
  border: none;
  cursor: pointer;
  font-size: 1.25rem;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.sidebar-toggle:hover {
  color: var(--primary-light);
  background: rgba(99, 102, 241, 0.1);
}
/* Sidebar Tabs */
.sidebar-tabs {
  display: none;
  border-bottom: 1px solid rgba(255,255,255,0.1);
  flex-shrink: 0;
}
#sidebar.expanded .sidebar-tabs {
  display: flex;
}
.sidebar-tab {
  flex: 1;
  padding: 0.75rem 1rem;
  background: transparent;
  border: none;
  color: var(--gray-400);
  cursor: pointer;
  font-size: 0.8rem;
  font-weight: 500;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
  font-family: inherit;
}
.sidebar-tab:hover {
  background: rgba(99, 102, 241, 0.1);
  color: var(--gray-200);
}
.sidebar-tab.active {
  background: rgba(99, 102, 241, 0.15);
  color: var(--primary-light);
  border-bottom: 2px solid var(--primary);
}
.sidebar-header {
  padding: 1rem 1.25rem;
  background: rgba(99, 102, 241, 0.1);
  border-bottom: 1px solid rgba(255,255,255,0.1);
  font-weight: 600;
  color: var(--primary-light);
  display: none;
  font-size: 0.9rem;
  flex-shrink: 0;
}
#sidebar.expanded .sidebar-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.header-icon {
  font-size: 1.1rem;
}
/* Tab Content Areas */
.tab-content {
  display: none;
  flex: 1;
  overflow-y: auto;
  min-height: 0;
}
.tab-content.active {
  display: flex;
  flex-direction: column;
}
#activity-log {
  flex: 1;
  overflow-y: auto;
  padding: 0;
  min-height: 0;
}
#sidebar.expanded #activity-log {
  padding: 1rem;
}
#activity-log::-webkit-scrollbar {
  width: 6px;
}
#activity-log::-webkit-scrollbar-track {
  background: transparent;
}
#activity-log::-webkit-scrollbar-thumb {
  background: var(--gray-600);
  border-radius: 3px;
}
/* Tasks Tab */
#tasks-list {
  flex: 1;
  overflow-y: auto;
  padding: 1rem;
  min-height: 0;
}
#tasks-list::-webkit-scrollbar {
  width: 6px;
}
#tasks-list::-webkit-scrollbar-track {
  background: transparent;
}
#tasks-list::-webkit-scrollbar-thumb {
  background: var(--gray-600);
  border-radius: 3px;
}
.task-item {
  padding: 1rem;
  margin-bottom: 0.75rem;
  border-radius: 10px;
  background: rgba(255,255,255,0.05);
  border: 1px solid rgba(255,255,255,0.1);
  animation: slideIn 0.3s ease;
}
.task-item.running {
  border-color: var(--secondary);
  background: rgba(14, 165, 233, 0.1);
}
.task-item.completed {
  border-color: var(--success);
  background: rgba(16, 185, 129, 0.1);
}
.task-item.paused {
  border-color: var(--warning);
  background: rgba(245, 158, 11, 0.1);
}
.task-item.cancelled, .task-item.failed {
  border-color: var(--danger);
  background: rgba(239, 68, 68, 0.1);
}
.task-result-preview {
  margin-top: 0.5rem;
  padding: 0.5rem;
  background: rgba(0,0,0,0.2);
  border-radius: 6px;
  font-size: 0.75rem;
  color: var(--gray-300);
  max-height: 60px;
  overflow: hidden;
  cursor: pointer;
  font-family: 'JetBrains Mono', monospace;
}
.task-result-preview:hover {
  background: rgba(0,0,0,0.3);
}
.task-btn-view {
  background: rgba(99, 102, 241, 0.2);
  color: var(--primary-light);
}
.task-btn-view:hover {
  background: var(--primary);
  color: white;
}
/* Task result modal */
.task-modal {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0,0,0,0.8);
  z-index: 1000;
  justify-content: center;
  align-items: center;
}
.task-modal.active {
  display: flex;
}
.task-modal-content {
  background: var(--dark);
  border-radius: 12px;
  max-width: 80%;
  max-height: 80%;
  overflow: auto;
  padding: 1.5rem;
  border: 1px solid rgba(255,255,255,0.1);
  box-shadow: var(--shadow-xl);
}
.task-modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid rgba(255,255,255,0.1);
}
.task-modal-title {
  font-weight: 600;
  color: var(--primary-light);
}
.task-modal-close {
  background: transparent;
  border: none;
  color: var(--gray-400);
  font-size: 1.5rem;
  cursor: pointer;
}
.task-modal-close:hover {
  color: var(--light);
}
.task-modal-body {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  color: var(--gray-200);
  white-space: pre-wrap;
  word-break: break-word;
}
.task-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 0.5rem;
}
.task-title {
  font-weight: 600;
  color: var(--gray-200);
  font-size: 0.85rem;
  flex: 1;
  margin-right: 0.5rem;
  word-break: break-word;
}
.task-status {
  font-size: 0.7rem;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  font-weight: 500;
  text-transform: uppercase;
  flex-shrink: 0;
}
.task-status.running { background: var(--secondary); color: white; }
.task-status.completed { background: var(--success); color: white; }
.task-status.paused { background: var(--warning); color: white; }
.task-status.cancelled, .task-status.failed { background: var(--danger); color: white; }
.task-status.pending { background: var(--gray-600); color: white; }
.task-meta {
  font-size: 0.75rem;
  color: var(--gray-500);
  margin-bottom: 0.75rem;
}
.task-actions {
  display: flex;
  gap: 0.5rem;
}
.task-btn {
  padding: 0.4rem 0.75rem;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 0.75rem;
  font-weight: 500;
  transition: all 0.2s;
  font-family: inherit;
  display: flex;
  align-items: center;
  gap: 0.3rem;
}
.task-btn-pause {
  background: rgba(245, 158, 11, 0.2);
  color: var(--warning);
}
.task-btn-pause:hover {
  background: var(--warning);
  color: white;
}
.task-btn-cancel {
  background: rgba(239, 68, 68, 0.2);
  color: var(--danger);
}
.task-btn-cancel:hover {
  background: var(--danger);
  color: white;
}
.task-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.no-tasks {
  text-align: center;
  color: var(--gray-500);
  padding: 2rem;
  font-size: 0.9rem;
}
/* Settings Tab */
#settings-content {
  flex: 1;
  overflow-y: auto;
  padding: 1rem;
  min-height: 0;
}
#settings-content::-webkit-scrollbar {
  width: 6px;
}
#settings-content::-webkit-scrollbar-track {
  background: transparent;
}
#settings-content::-webkit-scrollbar-thumb {
  background: var(--gray-600);
  border-radius: 3px;
}
.settings-section {
  margin-bottom: 1.5rem;
}
.settings-section-title {
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--gray-200);
  margin-bottom: 0.75rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.api-key-item {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
  padding: 0.75rem;
  background: rgba(255,255,255,0.05);
  border-radius: 8px;
  border: 1px solid rgba(255,255,255,0.1);
}
.api-key-label {
  min-width: 80px;
  font-size: 0.75rem;
  color: var(--gray-300);
  font-weight: 500;
}
.api-key-input {
  flex: 1;
  min-width: 100px;
  padding: 0.4rem 0.6rem;
  background: var(--darker);
  border: 1px solid rgba(255,255,255,0.15);
  border-radius: 6px;
  color: var(--light);
  font-size: 0.75rem;
  font-family: 'JetBrains Mono', monospace;
}
.api-key-input:focus {
  outline: none;
  border-color: var(--primary);
}
.api-key-btn {
  padding: 0.35rem 0.5rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.7rem;
  transition: all 0.2s;
  font-family: inherit;
  flex-shrink: 0;
}
.api-key-btn-save {
  background: var(--success);
  color: white;
}
.api-key-btn-save:hover {
  background: #059669;
}
.api-key-btn-delete {
  background: rgba(239, 68, 68, 0.2);
  color: var(--danger);
}
.api-key-btn-delete:hover {
  background: var(--danger);
  color: white;
}
.api-key-status {
  font-size: 0.7rem;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
}
.api-key-status.configured {
  background: rgba(16, 185, 129, 0.2);
  color: var(--success);
}
.api-key-status.not-configured {
  background: rgba(148, 163, 184, 0.2);
  color: var(--gray-400);
}
.activity-item {
  padding: 0.875rem 1rem;
  margin-bottom: 0.5rem;
  border-radius: 10px;
  font-size: 0.85rem;
  animation: slideIn 0.3s ease;
  position: relative;
  overflow: hidden;
}
@keyframes slideIn {
  from { opacity: 0; transform: translateX(-10px); }
  to { opacity: 1; transform: translateX(0); }
}
.activity-thinking {
  background: rgba(245, 158, 11, 0.1);
  border: 1px solid rgba(245, 158, 11, 0.3);
}
.activity-thinking::before {
  content: '🧠';
  position: absolute;
  right: 0.75rem;
  top: 50%;
  transform: translateY(-50%);
  font-size: 1.1rem;
  opacity: 0.5;
}
.activity-tool {
  background: rgba(14, 165, 233, 0.1);
  border: 1px solid rgba(14, 165, 233, 0.3);
}
.activity-tool::before {
  content: '🔧';
  position: absolute;
  right: 0.75rem;
  top: 50%;
  transform: translateY(-50%);
  font-size: 1.1rem;
  opacity: 0.5;
}
.activity-tool-result {
  background: rgba(16, 185, 129, 0.1);
  border: 1px solid rgba(16, 185, 129, 0.3);
}
.activity-tool-result::before {
  content: '✅';
  position: absolute;
  right: 0.75rem;
  top: 50%;
  transform: translateY(-50%);
  font-size: 1.1rem;
  opacity: 0.5;
}
.activity-error {
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
}
.activity-error::before {
  content: '❌';
  position: absolute;
  right: 0.75rem;
  top: 50%;
  transform: translateY(-50%);
  font-size: 1.1rem;
  opacity: 0.5;
}
.activity-step {
  background: rgba(148, 163, 184, 0.1);
  border: 1px solid rgba(148, 163, 184, 0.3);
}
.activity-step::before {
  content: '📍';
  position: absolute;
  right: 0.75rem;
  top: 50%;
  transform: translateY(-50%);
  font-size: 1.1rem;
  opacity: 0.5;
}
.activity-title {
  font-weight: 600;
  color: var(--gray-200);
  margin-bottom: 0.35rem;
  font-size: 0.8rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.activity-time {
  font-size: 0.7rem;
  color: var(--gray-500);
  font-weight: 400;
}
.activity-content {
  word-break: break-word;
  color: var(--gray-400);
  line-height: 1.5;
}
.activity-content pre {
  background: var(--darker);
  color: var(--gray-300);
  padding: 0.75rem;
  border-radius: 6px;
  font-size: 0.75rem;
  overflow-x: auto;
  margin-top: 0.5rem;
  font-family: 'JetBrains Mono', monospace;
  border: 1px solid rgba(255,255,255,0.1);
}

/* Main content area */
main {
  flex: 1;
  display: flex;
  flex-direction: column;
  padding: 1rem;
  gap: 1rem;
  overflow: hidden;
  background: linear-gradient(180deg, var(--darker) 0%, #1a1f2e 100%);
  min-height: 0;
}
#chat-container {
  background: var(--dark);
  border-radius: 16px;
  box-shadow: var(--shadow-xl);
  display: flex;
  flex-direction: column;
  flex: 1;
  overflow: hidden;
  border: 1px solid rgba(255,255,255,0.1);
  min-height: 0;
}
#messages {
  flex: 1;
  padding: 1.5rem;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 1rem;
  min-height: 0;
}
#messages::-webkit-scrollbar {
  width: 8px;
}
#messages::-webkit-scrollbar-track {
  background: transparent;
}
#messages::-webkit-scrollbar-thumb {
  background: var(--gray-600);
  border-radius: 4px;
}
.message {
  padding: 1rem 1.25rem;
  border-radius: 12px;
  max-width: 85%;
  word-wrap: break-word;
  animation: messageIn 0.3s ease;
  line-height: 1.6;
}
@keyframes messageIn {
  from { opacity: 0; transform: translateY(15px); }
  to { opacity: 1; transform: translateY(0); }
}
.msg-user {
  background: var(--gradient-primary);
  color: white;
  align-self: flex-end;
  border-bottom-right-radius: 4px;
  box-shadow: var(--shadow-md);
}
.msg-agent {
  background: rgba(255,255,255,0.05);
  color: var(--gray-200);
  align-self: flex-start;
  border-bottom-left-radius: 4px;
  border-left: 3px solid var(--primary);
}
.msg-agent pre {
  background: var(--darker);
  padding: 1rem;
  border-radius: 8px;
  overflow-x: auto;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  margin: 0.75rem 0;
  border: 1px solid rgba(255,255,255,0.1);
}
.msg-agent img {
  max-width: 100%;
  height: auto;
  border-radius: 8px;
  margin: 0.75rem 0;
  border: 1px solid rgba(255,255,255,0.1);
  cursor: pointer;
  transition: transform 0.2s;
}
.msg-agent img:hover {
  transform: scale(1.02);
}
/* Image modal for full-size view */
.image-modal {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0,0,0,0.9);
  z-index: 1000;
  justify-content: center;
  align-items: center;
  cursor: pointer;
}
.image-modal.active {
  display: flex;
}
.image-modal img {
  max-width: 95%;
  max-height: 95%;
  object-fit: contain;
}
.screenshot-placeholder {
  background: rgba(99, 102, 241, 0.1);
  border: 1px dashed var(--primary);
  border-radius: 8px;
  padding: 1rem;
  margin: 0.75rem 0;
  color: var(--primary-light);
  font-size: 0.9rem;
}
.msg-system {
  background: rgba(245, 158, 11, 0.15);
  color: var(--warning);
  align-self: center;
  max-width: 100%;
  text-align: center;
  font-size: 0.85rem;
  padding: 0.75rem 1.5rem;
  border: 1px solid rgba(245, 158, 11, 0.3);
}
.msg-progress {
  background: rgba(14, 165, 233, 0.1);
  color: var(--secondary);
  align-self: flex-start;
  max-width: 100%;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  border: 1px solid rgba(14, 165, 233, 0.3);
  display: flex;
  align-items: center;
  gap: 0.75rem;
}
.msg-progress .spinner {
  width: 16px;
  height: 16px;
  border: 2px solid rgba(14, 165, 233, 0.3);
  border-top-color: var(--secondary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
}
@keyframes spin {
  to { transform: rotate(360deg); }
}

/* Report buttons */
.report-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.75rem;
  flex-wrap: wrap;
}
.report-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 0.8rem;
  font-weight: 500;
  transition: all 0.2s;
  font-family: inherit;
}
.report-btn-html {
  background: var(--success);
  color: white;
}
.report-btn-html:hover {
  background: #059669;
  transform: translateY(-1px);
}
.report-btn-md {
  background: var(--secondary);
  color: white;
}
.report-btn-md:hover {
  background: #0284c7;
  transform: translateY(-1px);
}
.report-btn-preview {
  background: var(--primary);
  color: white;
}
.report-btn-preview:hover {
  background: var(--primary-dark);
  transform: translateY(-1px);
}

/* Input area */
#input-area {
  padding: 1rem;
  background: rgba(0,0,0,0.2);
  border-top: 1px solid rgba(255,255,255,0.1);
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  flex-shrink: 0;
}
.input-options {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.75rem;
}
.input-row {
  display: flex;
  gap: 0.75rem;
  align-items: flex-end;
}
.input-wrapper {
  flex: 1;
  position: relative;
}
#message-input {
  width: 100%;
  padding: 0.875rem 1rem;
  border: 2px solid rgba(255,255,255,0.1);
  border-radius: 12px;
  font-size: 0.9rem;
  background: var(--dark);
  color: var(--light);
  transition: all 0.2s;
  font-family: inherit;
}
#message-input::placeholder {
  color: var(--gray-500);
}
#message-input:focus {
  outline: none;
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
}

/* Background task checkbox */
.background-task-toggle {
  display: flex;
  align-items: center;
}
.checkbox-wrapper {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
  font-size: 0.8rem;
  color: var(--gray-400);
  user-select: none;
}
.checkbox-wrapper input[type="checkbox"] {
  display: none;
}
.checkmark {
  width: 18px;
  height: 18px;
  border: 2px solid var(--gray-500);
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}
.checkbox-wrapper input:checked + .checkmark {
  background: var(--primary);
  border-color: var(--primary);
}
.checkbox-wrapper input:checked + .checkmark::after {
  content: '✓';
  color: white;
  font-size: 0.75rem;
}
.checkbox-wrapper:hover .checkmark {
  border-color: var(--primary-light);
}
.checkbox-label {
  transition: color 0.2s;
}
.checkbox-wrapper:hover .checkbox-label {
  color: var(--gray-200);
}

/* File attachment */
.file-attachment-area {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
}
.file-input-wrapper {
  position: relative;
}
.file-input-wrapper input[type="file"] {
  position: absolute;
  left: -9999px;
}
.file-input-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.5rem 1rem;
  background: rgba(255,255,255,0.1);
  color: var(--gray-300);
  border: 1px dashed rgba(255,255,255,0.2);
  border-radius: 8px;
  cursor: pointer;
  font-size: 0.85rem;
  transition: all 0.2s;
}
.file-input-btn:hover {
  background: rgba(255,255,255,0.15);
  border-color: var(--primary);
  color: var(--primary-light);
}
#attached-files {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}
.attached-file {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.35rem 0.75rem;
  background: rgba(99, 102, 241, 0.2);
  color: var(--primary-light);
  border-radius: 20px;
  font-size: 0.8rem;
  border: 1px solid rgba(99, 102, 241, 0.3);
}
.attached-file .remove-file {
  cursor: pointer;
  opacity: 0.7;
  transition: opacity 0.2s;
}
.attached-file .remove-file:hover {
  opacity: 1;
}
#send-btn {
  padding: 1rem 2rem;
  min-width: 100px;
}

/* Stats bar at bottom of sidebar */
.sidebar-stats {
  padding: 1rem;
  background: rgba(0,0,0,0.2);
  border-top: 1px solid rgba(255,255,255,0.1);
  font-size: 0.8rem;
  flex-shrink: 0;
}
.stats-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 0.75rem;
}
.stat-item {
  text-align: center;
  padding: 0.5rem;
  background: rgba(255,255,255,0.05);
  border-radius: 8px;
}
.stat-value {
  font-size: 1.25rem;
  font-weight: 700;
  color: var(--primary-light);
}
.stat-label {
  font-size: 0.7rem;
  color: var(--gray-500);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* Tool badges */
.tool-badge {
  display: inline-block;
  background: var(--primary);
  color: white;
  padding: 0.2rem 0.6rem;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 500;
  margin-right: 0.25rem;
  font-family: 'JetBrains Mono', monospace;
}

/* Responsive */
@media (max-width: 768px) {
  header { padding: 1rem; }
  .header-actions { width: 100%; justify-content: center; }
  #sidebar.expanded { width: 100%; min-width: 100%; position: absolute; z-index: 50; height: 100%; }
  main { padding: 1rem; }
}
</style>
</head>
<body>
<header>
  <div class="logo-section">
    <div class="logo-icon">🛡️</div>
    <div>
      <h1>OWASP SmolAgent</h1>
      <div class="header-subtitle">Professional Security Testing Assistant</div>
    </div>
    <span class="status-badge disconnected" id="status-badge">
      <span class="status-dot"></span>
      <span id="status-text">Disconnected</span>
    </span>
  </div>
  <div class="header-actions">
    <div class="toggle-switch-wrapper" id="report-toggle">
      <label class="toggle-switch">
        <input type="checkbox" id="report-mode-checkbox">
        <span class="toggle-slider"></span>
      </label>
      <span class="toggle-label">📋 Report Mode</span>
    </div>
    <button class="btn btn-secondary" id="export-txt-btn">📥 Export</button>
    <button class="btn btn-secondary" id="clear-btn">🗑️ Clear</button>
  </div>
</header>
<div class="main-wrapper">
  <!-- Expandable Sidebar with Tabs -->
  <div id="sidebar">
    <button class="sidebar-toggle" id="sidebar-toggle" title="Toggle Sidebar">📊</button>
    
    <!-- Sidebar Tabs -->
    <div class="sidebar-tabs">
      <button class="sidebar-tab active" data-tab="activity">🔍 Activity</button>
      <button class="sidebar-tab" data-tab="tasks">📋 Tasks</button>
      <button class="sidebar-tab" data-tab="settings">⚙️ Settings</button>
    </div>
    
    <!-- Activity Tab Content -->
    <div class="tab-content active" id="tab-activity">
      <div class="sidebar-header"><span class="header-icon">🔍</span> Agent Activity Monitor</div>
      <div id="activity-log"></div>
      <div class="sidebar-stats">
        <div class="stats-grid">
          <div class="stat-item">
            <div class="stat-value" id="stat-steps">0</div>
            <div class="stat-label">Steps</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="stat-tools">0</div>
            <div class="stat-label">Tools</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="stat-duration">0s</div>
            <div class="stat-label">Duration</div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Tasks Tab Content -->
    <div class="tab-content" id="tab-tasks">
      <div class="sidebar-header"><span class="header-icon">📋</span> Running Tasks</div>
      <div id="tasks-list">
        <div class="no-tasks">No active tasks</div>
      </div>
    </div>
    
    <!-- Settings Tab Content -->
    <div class="tab-content" id="tab-settings">
      <div class="sidebar-header"><span class="header-icon">⚙️</span> API Configuration</div>
      <div id="settings-content">
        <div class="settings-section">
          <div class="settings-section-title">🔑 API Keys</div>
          
          <div class="api-key-item">
            <span class="api-key-label">Shodan</span>
            <input type="password" class="api-key-input" id="api-key-shodan" placeholder="Enter API key...">
            <button class="api-key-btn api-key-btn-save" onclick="saveApiKey('shodan')">💾</button>
            <button class="api-key-btn api-key-btn-delete" onclick="deleteApiKey('shodan')">🗑️</button>
          </div>
          
          <div class="api-key-item">
            <span class="api-key-label">VirusTotal</span>
            <input type="password" class="api-key-input" id="api-key-virustotal" placeholder="Enter API key...">
            <button class="api-key-btn api-key-btn-save" onclick="saveApiKey('virustotal')">💾</button>
            <button class="api-key-btn api-key-btn-delete" onclick="deleteApiKey('virustotal')">🗑️</button>
          </div>
          
          <div class="api-key-item">
            <span class="api-key-label">Hunter.io</span>
            <input type="password" class="api-key-input" id="api-key-hunter" placeholder="Enter API key...">
            <button class="api-key-btn api-key-btn-save" onclick="saveApiKey('hunter')">💾</button>
            <button class="api-key-btn api-key-btn-delete" onclick="deleteApiKey('hunter')">🗑️</button>
          </div>
          
          <div class="api-key-item">
            <span class="api-key-label">SecurityTrails</span>
            <input type="password" class="api-key-input" id="api-key-securitytrails" placeholder="Enter API key...">
            <button class="api-key-btn api-key-btn-save" onclick="saveApiKey('securitytrails')">💾</button>
            <button class="api-key-btn api-key-btn-delete" onclick="deleteApiKey('securitytrails')">🗑️</button>
          </div>
          
          <div class="api-key-item">
            <span class="api-key-label">Censys</span>
            <input type="password" class="api-key-input" id="api-key-censys" placeholder="Enter API key...">
            <button class="api-key-btn api-key-btn-save" onclick="saveApiKey('censys')">💾</button>
            <button class="api-key-btn api-key-btn-delete" onclick="deleteApiKey('censys')">🗑️</button>
          </div>
          
          <div class="api-key-item">
            <span class="api-key-label">AlienVault OTX</span>
            <input type="password" class="api-key-input" id="api-key-alienvault" placeholder="Enter API key...">
            <button class="api-key-btn api-key-btn-save" onclick="saveApiKey('alienvault')">💾</button>
            <button class="api-key-btn api-key-btn-delete" onclick="deleteApiKey('alienvault')">🗑️</button>
          </div>
        </div>
        
        <div class="settings-section">
          <div class="settings-section-title">📤 Export / Import</div>
          <div style="display: flex; gap: 10px; margin-bottom: 15px;">
            <button class="api-key-btn" style="padding: 8px 16px; font-size: 0.85rem;" onclick="exportApiKeys()">📤 Export Keys</button>
            <button class="api-key-btn" style="padding: 8px 16px; font-size: 0.85rem;" onclick="importApiKeysDialog()">📥 Import Keys</button>
            <input type="file" id="import-keys-input" accept=".json" style="display: none;" onchange="importApiKeys(this)">
          </div>
        </div>
        
        <div class="settings-section">
          <div class="settings-section-title">📝 Note</div>
          <p style="font-size: 0.8rem; color: var(--gray-400); line-height: 1.5;">
            API keys are now persisted to disk and will survive server restarts.
            Use Export/Import to backup or transfer your keys between installations.
          </p>
        </div>
      </div>
    </div>
  </div>
  
  <!-- Task Result Modal -->
  <div class="task-modal" id="task-modal">
    <div class="task-modal-content">
      <div class="task-modal-header">
        <span class="task-modal-title" id="task-modal-title">Task Result</span>
        <button class="task-modal-close" onclick="closeTaskModal()">&times;</button>
      </div>
      <div class="task-modal-body" id="task-modal-body"></div>
    </div>
  </div>
  
  <!-- Image Modal for full-size screenshots -->
  <div class="image-modal" id="image-modal">
    <img id="image-modal-img" src="" alt="Full size screenshot">
  </div>
  
  <main>
    <div id="chat-container">
      <div id="messages"></div>
      <div id="input-area">
        <div class="input-options">
          <div class="file-attachment-area">
            <div class="file-input-wrapper">
              <input type="file" id="file-input" multiple accept=".txt,.json,.xml,.html,.log,.csv,.md,.py,.js,.yaml,.yml,.conf,.cfg,.ini">
              <label for="file-input" class="file-input-btn">📎 Attach Files</label>
            </div>
            <div id="attached-files"></div>
          </div>
          <div class="background-task-toggle">
            <label class="checkbox-wrapper">
              <input type="checkbox" id="background-task-checkbox">
              <span class="checkmark"></span>
              <span class="checkbox-label">🔄 Run as Background Task</span>
            </label>
          </div>
        </div>
        <div class="input-row">
          <div class="input-wrapper">
            <input type="text" id="message-input" placeholder="Ask about OWASP, run security scans, use specific tools (e.g., 'run nmap against target.com')..." autocomplete="off">
          </div>
          <button class="btn btn-primary" id="send-btn">
            <span>Send</span>
            <span>➤</span>
          </button>
        </div>
      </div>
    </div>
  </main>
</div>
<script>
const messagesDiv = document.getElementById('messages');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const statusBadge = document.getElementById('status-badge');
const statusText = document.getElementById('status-text');
const exportTxtBtn = document.getElementById('export-txt-btn');
const clearBtn = document.getElementById('clear-btn');
const sidebar = document.getElementById('sidebar');
const sidebarToggle = document.getElementById('sidebar-toggle');
const activityLog = document.getElementById('activity-log');
const reportToggle = document.getElementById('report-toggle');
const reportCheckbox = document.getElementById('report-mode-checkbox');
const fileInput = document.getElementById('file-input');
const attachedFilesDiv = document.getElementById('attached-files');
const backgroundTaskCheckbox = document.getElementById('background-task-checkbox');

// Stats
let stepCount = 0;
let toolCount = 0;
let startTime = null;
let durationInterval = null;

// File attachments storage
let attachedFiles = [];
let sessionId = 'session_' + Date.now();

let chatHistory = [];
let currentReport = { html: null, markdown: null };
const ws = new WebSocket(`ws://${location.host}/ws`);

// Task store for UI
let taskStore = {};
let taskRefreshInterval = null;

// Sidebar toggle
sidebarToggle.onclick = () => {
  sidebar.classList.toggle('expanded');
  sidebarToggle.textContent = sidebar.classList.contains('expanded') ? '◀' : '📊';
};

// Sidebar tabs
document.querySelectorAll('.sidebar-tab').forEach(tab => {
  tab.onclick = () => {
    // Remove active from all tabs and content
    document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    // Add active to clicked tab
    tab.classList.add('active');
    const tabId = tab.getAttribute('data-tab');
    document.getElementById('tab-' + tabId).classList.add('active');
    
    // Start/stop task polling based on tab
    if (tabId === 'tasks') {
      startTaskPolling();
    } else {
      stopTaskPolling();
    }
    
    // Load API keys when settings tab is opened
    if (tabId === 'settings') {
      loadApiKeys();
    }
  };
});

// Task management functions
function startTaskPolling() {
  if (taskRefreshInterval) return;
  refreshTasks();
  taskRefreshInterval = setInterval(refreshTasks, 2000);
}

function stopTaskPolling() {
  if (taskRefreshInterval) {
    clearInterval(taskRefreshInterval);
    taskRefreshInterval = null;
  }
}

async function refreshTasks() {
  try {
    const response = await fetch('/api/tasks');
    const tasks = await response.json();
    taskStore = {};
    tasks.forEach(t => taskStore[t.id] = t);
    renderTasks();
  } catch (err) {
    console.error('Failed to refresh tasks:', err);
  }
}

function renderTasks() {
  const tasksList = document.getElementById('tasks-list');
  const tasks = Object.values(taskStore);
  
  if (tasks.length === 0) {
    tasksList.innerHTML = '<div class="no-tasks">No active tasks</div>';
    return;
  }
  
  // Sort by created_at descending
  tasks.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  
  tasksList.innerHTML = tasks.map(task => {
    const isActive = ['pending', 'running', 'paused'].includes(task.status);
    const createdAt = new Date(task.created_at).toLocaleTimeString();
    const truncatedPrompt = task.prompt.length > 50 ? task.prompt.substring(0, 50) + '...' : task.prompt;
    
    return `
      <div class="task-item ${task.status}">
        <div class="task-header">
          <span class="task-title">${escapeHtml(truncatedPrompt)}</span>
          <span class="task-status ${task.status}">${task.status}</span>
        </div>
        <div class="task-meta">
          Created: ${createdAt} | Steps: ${task.step_count} | Tools: ${task.tool_count}
        </div>
        ${isActive ? `
        <div class="task-actions">
          <button class="task-btn task-btn-pause" onclick="pauseTask('${task.id}')" ${task.status === 'paused' ? 'disabled' : ''}>
            ${task.status === 'paused' ? '▶️ Resume' : '⏸️ Pause'}
          </button>
          <button class="task-btn task-btn-cancel" onclick="cancelTask('${task.id}')">
            ❌ Cancel
          </button>
        </div>
        ` : ''}
        ${task.error ? `<div class="task-error" style="color: var(--danger); font-size: 0.75rem; margin-top: 0.5rem;">${escapeHtml(task.error)}</div>` : ''}
        ${task.result ? `
        <div class="task-result-preview" onclick="viewTaskResult('${task.id}')">
          ${escapeHtml(task.result.substring(0, 150))}${task.result.length > 150 ? '...' : ''}
        </div>
        <div class="task-actions" style="margin-top: 0.5rem;">
          <button class="task-btn task-btn-view" onclick="viewTaskResult('${task.id}')">
            👁️ View Full Result
          </button>
        </div>
        ` : ''}
      </div>
    `;
  }).join('');
}

async function pauseTask(taskId) {
  try {
    const task = taskStore[taskId];
    const action = task?.status === 'paused' ? 'resume' : 'pause';
    await fetch(`/api/tasks/${taskId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action })
    });
    refreshTasks();
  } catch (err) {
    addMessage('system', `⚠️ Failed to pause task: ${err.message}`);
  }
}

async function cancelTask(taskId) {
  if (!confirm('Are you sure you want to cancel this task?')) return;
  try {
    await fetch(`/api/tasks/${taskId}`, { method: 'DELETE' });
    refreshTasks();
  } catch (err) {
    addMessage('system', `⚠️ Failed to cancel task: ${err.message}`);
  }
}

async function viewTaskResult(taskId) {
  try {
    // Fetch fresh task data with full result
    const response = await fetch(`/api/tasks/${taskId}`);
    const task = await response.json();
    
    if (!task || task.error === 'Task not found') {
      alert('Task not found');
      return;
    }
    
    const modal = document.getElementById('task-modal');
    const title = document.getElementById('task-modal-title');
    const body = document.getElementById('task-modal-body');
    
    title.textContent = `Task Result: ${task.prompt.substring(0, 50)}${task.prompt.length > 50 ? '...' : ''}`;
    
    // Format result with markdown-like rendering
    let resultHtml = task.result || 'No result available';
    
    // Check for base64 images and render them
    const base64Pattern = /data:image\\/(png|jpg|jpeg|gif|webp);base64,([A-Za-z0-9+\\/=]+)/g;
    resultHtml = resultHtml.replace(base64Pattern, '<img src="$&" style="max-width: 100%; margin: 10px 0; border-radius: 8px;">');
    
    body.innerHTML = `
      <div style="margin-bottom: 1rem;">
        <strong>Status:</strong> <span class="task-status ${task.status}">${task.status}</span><br>
        <strong>Steps:</strong> ${task.step_count} | <strong>Tools Used:</strong> ${task.tool_count}<br>
        ${task.error ? `<strong style="color: var(--danger);">Error:</strong> ${task.error}` : ''}
      </div>
      <hr style="border-color: rgba(255,255,255,0.1); margin: 1rem 0;">
      <div style="white-space: pre-wrap; word-break: break-word;">${resultHtml}</div>
    `;
    
    modal.classList.add('active');
  } catch (err) {
    alert('Failed to load task result: ' + err.message);
  }
}

function closeTaskModal() {
  document.getElementById('task-modal').classList.remove('active');
}

// Close modal on escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeTaskModal();
    document.getElementById('image-modal').classList.remove('active');
  }
});

// Close modal on clicking outside
document.getElementById('task-modal').addEventListener('click', (e) => {
  if (e.target.id === 'task-modal') closeTaskModal();
});

// API Key management functions
const API_KEY_MAP = {
  'shodan': 'SHODAN_API_KEY',
  'virustotal': 'VIRUSTOTAL_API_KEY',
  'hunter': 'HUNTER_API_KEY',
  'securitytrails': 'SECURITYTRAILS_API_KEY',
  'hibp': 'HIBP_API_KEY',
  'censys': 'CENSYS_API_KEY',
  'alienvault': 'ALIENVAULT_API_KEY'
};

// Reverse mapping for display
const API_KEY_REVERSE_MAP = Object.fromEntries(
  Object.entries(API_KEY_MAP).map(([k, v]) => [v, k])
);

async function loadApiKeys() {
  try {
    const response = await fetch('/api/keys');
    const keys = await response.json();
    
    // Clear all inputs and show which are configured
    document.querySelectorAll('.api-key-input').forEach(input => {
      const service = input.id.replace('api-key-', '');
      const envKey = API_KEY_MAP[service] || service.toUpperCase() + '_API_KEY';
      if (keys[envKey] && keys[envKey].length > 4) {
        input.value = '••••••••••••••••';
        input.setAttribute('data-configured', 'true');
      } else {
        input.value = '';
        input.removeAttribute('data-configured');
      }
    });
  } catch (err) {
    console.error('Failed to load API keys:', err);
  }
}

async function saveApiKey(service) {
  const input = document.getElementById('api-key-' + service);
  const value = input.value.trim();
  
  if (!value || value === '••••••••••••••••') {
    addMessage('system', `⚠️ Please enter a valid API key for ${service}`);
    return;
  }
  
  // Map to environment variable name
  const envKey = API_KEY_MAP[service] || service.toUpperCase() + '_API_KEY';
  
  try {
    await fetch('/api/keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service: envKey, api_key: value })
    });
    input.value = '••••••••••••••••';
    input.setAttribute('data-configured', 'true');
    addMessage('system', `✅ ${service} API key saved successfully`);
  } catch (err) {
    addMessage('system', `⚠️ Failed to save API key: ${err.message}`);
  }
}

async function deleteApiKey(service) {
  if (!confirm(`Are you sure you want to delete the ${service} API key?`)) return;
  
  // Map to environment variable name
  const envKey = API_KEY_MAP[service] || service.toUpperCase() + '_API_KEY';
  
  try {
    await fetch(`/api/keys/${envKey}`, { method: 'DELETE' });
    const input = document.getElementById('api-key-' + service);
    input.value = '';
    input.removeAttribute('data-configured');
    addMessage('system', `🗑️ ${service} API key deleted`);
  } catch (err) {
    addMessage('system', `⚠️ Failed to delete API key: ${err.message}`);
  }
}

async function exportApiKeys() {
  try {
    const response = await fetch('/api/keys/export');
    const keys = await response.json();
    
    // Create download
    const blob = new Blob([JSON.stringify(keys, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'owasp-helper-api-keys.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    addMessage('system', '📤 API keys exported successfully');
  } catch (err) {
    addMessage('system', `⚠️ Failed to export API keys: ${err.message}`);
  }
}

function importApiKeysDialog() {
  document.getElementById('import-keys-input').click();
}

async function importApiKeys(input) {
  const file = input.files[0];
  if (!file) return;
  
  try {
    const content = await file.text();
    const keys = JSON.parse(content);
    
    const response = await fetch('/api/keys/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(keys)
    });
    
    if (response.ok) {
      addMessage('system', '📥 API keys imported successfully');
      await loadApiKeys(); // Refresh the display
    } else {
      throw new Error('Import failed');
    }
  } catch (err) {
    addMessage('system', `⚠️ Failed to import API keys: ${err.message}`);
  }
  
  // Clear the file input for future imports
  input.value = '';
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Report mode toggle
reportCheckbox.onchange = () => {
  const enabled = reportCheckbox.checked;
  reportToggle.classList.toggle('active', enabled);
  
  // Send command to enable/disable report mode
  if (enabled) {
    ws.send(JSON.stringify({ action: 'report_mode_on' }));
  } else {
    ws.send(JSON.stringify({ action: 'report_mode_off' }));
  }
};

// File attachment handling
fileInput.onchange = async (e) => {
  const files = Array.from(e.target.files);
  
  for (const file of files) {
    if (file.size > 5 * 1024 * 1024) { // 5MB limit
      addMessage('system', `⚠️ File "${file.name}" is too large (max 5MB)`);
      continue;
    }
    
    try {
      const content = await readFileAsText(file);
      attachedFiles.push({
        filename: file.name,
        content: content,
        size: file.size
      });
      renderAttachedFiles();
    } catch (err) {
      addMessage('system', `⚠️ Could not read file "${file.name}"`);
    }
  }
  
  fileInput.value = ''; // Reset file input
};

function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsText(file);
  });
}

function renderAttachedFiles() {
  attachedFilesDiv.innerHTML = attachedFiles.map((file, index) => `
    <span class="attached-file">
      📄 ${file.filename}
      <span class="remove-file" onclick="removeFile(${index})">✕</span>
    </span>
  `).join('');
}

function removeFile(index) {
  attachedFiles.splice(index, 1);
  renderAttachedFiles();
}

function addActivity(type, title, content, details = null) {
  const item = document.createElement('div');
  item.className = `activity-item activity-${type}`;
  
  const time = new Date().toLocaleTimeString('en-US', { hour12: false });
  item.innerHTML = `
    <div class="activity-title">
      ${title}
      <span class="activity-time">${time}</span>
    </div>
    <div class="activity-content">${content}${details ? '<pre>' + escapeHtml(details) + '</pre>' : ''}</div>
  `;
  
  activityLog.appendChild(item);
  activityLog.scrollTop = activityLog.scrollHeight;
  
  // Note: Counts are now updated from server data in ws.onmessage
}

function escapeHtml(text) {
  if (!text) return '';
  const str = String(text);
  const div = document.createElement('div');
  div.textContent = str.substring(0, 1000);
  return div.innerHTML + (str.length > 1000 ? '\\n... (truncated)' : '');
}

function startTimer() {
  startTime = Date.now();
  stepCount = 0;
  toolCount = 0;
  activityLog.innerHTML = '';
  
  if (durationInterval) clearInterval(durationInterval);
  durationInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const mins = Math.floor(elapsed / 60);
    const secs = elapsed % 60;
    document.getElementById('stat-duration').textContent = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
  }, 1000);
}

function stopTimer() {
  if (durationInterval) clearInterval(durationInterval);
}

function addMessage(type, content, meta = {}) {
  const msgDiv = document.createElement('div');
  msgDiv.className = `message msg-${type}`;
  
  if (type === 'progress') {
    msgDiv.innerHTML = `<div class="spinner"></div><span>${content}</span>`;
  }
  // Detect HTML content (full HTML document)
  else if (type === 'agent' && content.includes('<!DOCTYPE html>')) {
    const htmlCode = content;
    msgDiv.innerHTML = `
      <strong>📋 HTML Report Generated</strong><br>
      <small>A professional security report has been created</small>
      <div class="report-actions">
        <button class="report-btn report-btn-preview" onclick="previewReport(this, 'html')">👁️ Preview</button>
        <button class="report-btn report-btn-html" onclick="downloadReport('html')">📥 Download HTML</button>
      </div>
    `;
    currentReport.html = htmlCode;
  }
  // Check for report type message
  else if (type === 'report') {
    msgDiv.innerHTML = `
      <strong>📋 Security Report Ready</strong><br>
      <small>${content}</small>
      <div class="report-actions">
        <button class="report-btn report-btn-preview" onclick="previewReport(this, 'html')">👁️ Preview HTML</button>
        <button class="report-btn report-btn-html" onclick="downloadReport('html')">📥 HTML</button>
        <button class="report-btn report-btn-md" onclick="downloadReport('markdown')">📥 Markdown</button>
      </div>
    `;
    if (meta.html) currentReport.html = meta.html;
    if (meta.markdown) currentReport.markdown = meta.markdown;
  }
  // Detect HTML code blocks
  else if (type === 'agent' && content.match(/```html\\n([\\s\\S]*?)\\n```/)) {
    const htmlMatch = content.match(/```html\\n([\\s\\S]*?)\\n```/);
    currentReport.html = htmlMatch[1];
    msgDiv.innerHTML = `
      <div>${formatContent(content)}</div>
      <div class="report-actions">
        <button class="report-btn report-btn-preview" onclick="previewReport(this, 'html')">👁️ Preview</button>
        <button class="report-btn report-btn-html" onclick="downloadReport('html')">📥 Download HTML</button>
      </div>
    `;
  }
  // Handle SCREENSHOT_IMAGE_DATA format from agent
  else if (content.includes('SCREENSHOT_IMAGE_DATA:')) {
    const screenshotRegex = /SCREENSHOT_IMAGE_DATA:([A-Za-z0-9+\\/=]+):END_IMAGE_DATA/g;
    let formattedContent = content;
    let match;
    let imageCount = 0;
    
    while ((match = screenshotRegex.exec(content)) !== null) {
      imageCount++;
      const base64Data = match[0].replace('SCREENSHOT_IMAGE_DATA:', '').replace(':END_IMAGE_DATA', '');
      const imgSrc = 'data:image/png;base64,' + base64Data;
      const imgHtml = `
        <div class="screenshot-container" style="margin: 15px 0;">
          <div style="font-weight: bold; margin-bottom: 8px;">📸 Screenshot captured:</div>
          <img src="${imgSrc}" 
               onclick="showImageModal(this.src)" 
               alt="Screenshot" 
               style="max-width: 100%; max-height: 400px; border-radius: 8px; cursor: pointer; border: 1px solid var(--gray-600); box-shadow: 0 4px 12px rgba(0,0,0,0.3);">
          <div style="font-size: 0.75rem; color: var(--gray-400); margin-top: 5px;">Click image to view full size</div>
        </div>`;
      formattedContent = formattedContent.replace(match[0], imgHtml);
    }
    
    // Format the rest of the content (text before/after the image)
    const parts = formattedContent.split(/<div class="screenshot-container"/);
    if (parts.length > 1) {
      const textPart = formatContent(parts[0]);
      msgDiv.innerHTML = textPart + '<div class="screenshot-container"' + parts.slice(1).join('<div class="screenshot-container"');
    } else {
      msgDiv.innerHTML = formattedContent;
    }
  } else {
    // Check for base64 images in content and render them
    let formattedContent = formatContent(content);
    
    // Handle base64 image data
    const base64Pattern = /data:image\\/(png|jpg|jpeg|gif|webp);base64,([A-Za-z0-9+\\/=]+)/g;
    const matches = content.match(base64Pattern);
    if (matches) {
      matches.forEach(match => {
        const imgHtml = `<img src="${match}" onclick="showImageModal(this.src)" alt="Screenshot" style="max-width: 600px;">`;
        formattedContent = formattedContent.replace(escapeForRegex(match.substring(0, 100)), imgHtml);
      });
    }
    
    // Also handle markdown-style image references to local files
    formattedContent = formattedContent.replace(/!\\[([^\\]]*?)\\]\\(([^)]+\\.png)\\)/g, 
      '<div class="screenshot-placeholder">📷 Screenshot saved: $2</div>');
    
    msgDiv.innerHTML = formattedContent;
  }
  
  messagesDiv.appendChild(msgDiv);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
  
  chatHistory.push({ type, content, timestamp: new Date().toISOString(), ...meta });
}

function escapeForRegex(string) {
  return string.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');
}

function showImageModal(src) {
  const modal = document.getElementById('image-modal');
  const img = document.getElementById('image-modal-img');
  img.src = src;
  modal.classList.add('active');
}

document.getElementById('image-modal').addEventListener('click', () => {
  document.getElementById('image-modal').classList.remove('active');
});

function formatContent(content) {
  // Basic markdown-like formatting
  return String(content)
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/```(\\w+)?\\n([\\s\\S]*?)```/g, '<pre><code>$2</code></pre>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\\*\\*([^*]+)\\*\\*/g, '<strong>$1</strong>')
    .replace(/\\n/g, '<br>');
}

function previewReport(btn, type) {
  const report = type === 'html' ? currentReport.html : currentReport.markdown;
  if (!report) {
    alert('No report available');
    return;
  }
  
  if (type === 'html') {
    const newWindow = window.open();
    newWindow.document.write(report);
    newWindow.document.close();
  } else {
    const newWindow = window.open();
    newWindow.document.write('<pre style="white-space: pre-wrap; font-family: monospace; padding: 2rem;">' + escapeHtml(report) + '</pre>');
    newWindow.document.close();
  }
}

function downloadReport(type) {
  const report = type === 'html' ? currentReport.html : currentReport.markdown;
  const ext = type === 'html' ? 'html' : 'md';
  const mimeType = type === 'html' ? 'text/html' : 'text/markdown';
  
  if (!report) {
    alert('No report available');
    return;
  }
  
  const blob = new Blob([report], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `security-report-${new Date().toISOString().split('T')[0]}.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}

ws.onopen = () => {
  statusBadge.className = 'status-badge connected';
  statusText.textContent = 'Connected';
  addMessage('system', '🟢 Connected to OWASP SmolAgent - Ready for security analysis');
};

ws.onclose = () => {
  statusBadge.className = 'status-badge disconnected';
  statusText.textContent = 'Disconnected';
  addMessage('system', '🔴 Disconnected from server. Please refresh the page.');
};

ws.onmessage = (event) => {
  let data;
  try {
    data = JSON.parse(event.data);
  } catch {
    addMessage('agent', event.data);
    return;
  }
  
  if (data.type === 'progress') {
    // Update existing progress message or add new one
    const existingProgress = messagesDiv.querySelector('.msg-progress:last-child');
    if (existingProgress) {
      existingProgress.innerHTML = `<div class="spinner"></div><span>${data.content}</span>`;
    } else {
      addMessage('progress', data.content);
    }
  } else if (data.type === 'activity') {
    // Activity log update from agent steps - use server-provided counts
    addActivity(data.activity_type, data.title || '', data.content, data.details);
    
    // Update counters from server if provided
    if (typeof data.tool_count === 'number') {
      toolCount = data.tool_count;
      document.getElementById('stat-tools').textContent = toolCount;
    }
    if (typeof data.step_count === 'number') {
      stepCount = data.step_count;
      document.getElementById('stat-steps').textContent = stepCount;
    }
  } else if (data.type === 'final') {
    stopTimer();
    // Remove progress message if exists
    const progressMsg = messagesDiv.querySelector('.msg-progress:last-child');
    if (progressMsg) progressMsg.remove();
    addMessage('agent', data.content);
  } else if (data.type === 'report') {
    addMessage('report', data.content, { html: data.html, markdown: data.markdown });
    addActivity('tool-result', '📋 Report Generated', 'Professional security report is ready for download');
  } else if (data.type === 'report_mode') {
    addMessage('system', data.content);
  } else {
    addMessage('agent', event.data);
  }
};

async function sendMessage() {
  const content = messageInput.value.trim();
  if (!content) return;
  
  const isBackgroundTask = backgroundTaskCheckbox.checked;
  
  // Build message with file names
  let displayContent = content;
  if (attachedFiles.length > 0) {
    displayContent += '\\n📎 Attached: ' + attachedFiles.map(f => f.filename).join(', ');
  }
  if (isBackgroundTask) {
    displayContent = '🔄 [Background Task] ' + displayContent;
  }
  addMessage('user', displayContent);
  
  startTimer();
  addActivity('step', '🚀 Task Started', content.substring(0, 80) + (content.length > 80 ? '...' : ''));
  
  // Prepare message payload
  const payload = {
    content: content,
    session_id: sessionId,
    report_mode: reportCheckbox.checked,
    background_task: isBackgroundTask,
    files: attachedFiles.map(f => f.filename)
  };
  
  // Upload files first if any
  if (attachedFiles.length > 0) {
    addActivity('tool', '📤 Uploading Files', `Uploading ${attachedFiles.length} file(s) for analysis`);
    
    for (const file of attachedFiles) {
      try {
        const response = await fetch('/upload', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            session_id: sessionId,
            filename: file.filename,
            content: btoa(unescape(encodeURIComponent(file.content)))
          })
        });
        
        if (!response.ok) {
          throw new Error('Upload failed');
        }
      } catch (err) {
        addActivity('error', '❌ Upload Error', `Failed to upload ${file.filename}`);
      }
    }
    
    addActivity('tool-result', '✅ Files Uploaded', 'Files ready for analysis');
  }
  
  // Send message via WebSocket
  ws.send(JSON.stringify(payload));
  
  // Clear input and files
  messageInput.value = '';
  attachedFiles = [];
  renderAttachedFiles();
  
  // Reset background task checkbox
  if (isBackgroundTask) {
    backgroundTaskCheckbox.checked = false;
    // Switch to Tasks tab to show the new task
    document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.querySelector('.sidebar-tab[data-tab="tasks"]').classList.add('active');
    document.getElementById('tab-tasks').classList.add('active');
    startTaskPolling();
  }
  
  // Auto-expand sidebar when task starts
  if (!sidebar.classList.contains('expanded')) {
    sidebar.classList.add('expanded');
    sidebarToggle.textContent = '◀';
  }
}

sendBtn.onclick = sendMessage;
messageInput.onkeypress = (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
};

exportTxtBtn.onclick = () => {
  const txtContent = chatHistory.map(msg => 
    `[${msg.timestamp}] [${msg.type.toUpperCase()}]\\n${msg.content}\\n`
  ).join('\\n---\\n\\n');
  
  const blob = new Blob([txtContent], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `owasp-chat-${new Date().toISOString().split('T')[0]}.txt`;
  a.click();
  URL.revokeObjectURL(url);
};

clearBtn.onclick = () => {
  if (confirm('Clear all chat history and attached files?')) {
    messagesDiv.innerHTML = '';
    chatHistory = [];
    activityLog.innerHTML = '';
    stepCount = 0;
    toolCount = 0;
    attachedFiles = [];
    renderAttachedFiles();
    currentReport = { html: null, markdown: null };
    document.getElementById('stat-steps').textContent = '0';
    document.getElementById('stat-tools').textContent = '0';
    document.getElementById('stat-duration').textContent = '0s';
    addMessage('system', '🧹 Chat cleared - Ready for new session');
  }
};

// Expose functions globally for inline onclick handlers
window.removeFile = removeFile;
window.previewReport = previewReport;
window.downloadReport = downloadReport;
window.pauseTask = pauseTask;
window.cancelTask = cancelTask;
window.saveApiKey = saveApiKey;
window.deleteApiKey = deleteApiKey;
</script>
</body>
</html>
"""

@app.get("/")
async def index():
    return HTMLResponse(HTML)

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    if agent is None:
        await ws.send_text(json.dumps({"type": "system", "content": "Agent not ready"}))
        await ws.close()
        return
    
    try:
        while True:
            raw_msg = await ws.receive_text()
            
            # Parse JSON message if possible
            try:
                msg_data = json.loads(raw_msg)
            except json.JSONDecodeError:
                msg_data = {"content": raw_msg}
            
            msg_content = msg_data.get("content", raw_msg)
            session_id = msg_data.get("session_id", "default")
            report_mode_enabled = msg_data.get("report_mode", False)
            attached_files = msg_data.get("files", [])
            background_task = msg_data.get("background_task", False)
            
            # Handle report mode toggle commands
            if msg_content == "__REPORT_MODE_ON__" or msg_data.get("action") == "report_mode_on":
                enable_report_mode(
                    title="Security Assessment Report",
                    target="Target to be specified",
                    author="OWASP SmolAgent"
                )
                await ws.send_text(json.dumps({
                    "type": "report_mode",
                    "content": "📋 Report Mode ENABLED - Professional report will be generated with findings."
                }))
                continue
            
            if msg_content == "__REPORT_MODE_OFF__" or msg_data.get("action") == "report_mode_off":
                disable_report_mode()
                await ws.send_text(json.dumps({
                    "type": "report_mode", 
                    "content": "📋 Report Mode DISABLED"
                }))
                continue
            
            # Build message with file context
            full_message = msg_content
            if session_id in file_store and file_store[session_id]:
                relevant_files = [f for f in file_store[session_id] if f["filename"] in attached_files]
                if relevant_files:
                    full_message += "\n\n--- ATTACHED FILES ---"
                    for f in relevant_files:
                        full_message += f"\n\n### File: {f['filename']}\n```\n{f['content'][:15000]}\n```"
            
            # Add report mode instruction
            if report_mode_enabled:
                full_message += """

[IMPORTANT - REPORT MODE IS ENABLED]
After completing your security assessment, you MUST generate a professional report:
1. First call enable_report_mode() with proper title and target
2. For each vulnerability found, call add_finding_to_report() with complete details
3. Call set_executive_summary() with a management-level overview
4. Call set_conclusion() with prioritized recommendations
5. Finally call generate_html_report() to produce the final HTML report
The report should be comprehensive and professional, suitable for executive stakeholders."""
            
            # Handle background task
            if background_task:
                task_id = str(uuid.uuid4())
                new_task = Task(
                    id=task_id,
                    prompt=msg_content[:200],
                    status=TaskStatus.pending,
                    created_at=datetime.now(),
                    started_at=None,
                    completed_at=None,
                    result=None,
                    error=None,
                    tool_count=0,
                    step_count=0
                )
                task_store[task_id] = new_task
                
                # Notify client that task was created
                await ws.send_text(json.dumps({
                    "type": "task_created",
                    "task_id": task_id,
                    "content": f"🔄 Background task created. Check the Tasks tab to monitor progress."
                }))
                
                # Run task in background thread
                def run_background_task():
                    try:
                        task_store[task_id].status = TaskStatus.running
                        task_store[task_id].started_at = datetime.now()
                        
                        step_count = 0
                        tool_count = 0
                        final_result = None
                        all_outputs = []  # Collect all meaningful outputs
                        
                        for event in agent.run(full_message, stream=True):
                            # Check for cancellation
                            if task_store[task_id].status == TaskStatus.cancelled:
                                return
                            
                            step_count += 1
                            event_type = type(event).__name__
                            
                            # Collect tool calls and their results
                            if hasattr(event, 'tool_calls') and event.tool_calls:
                                for tc in event.tool_calls:
                                    tool_count += 1
                                    if hasattr(tc, 'name'):
                                        all_outputs.append(f"🔧 Tool: {tc.name}")
                            
                            # Collect tool results
                            if hasattr(event, 'tool_result') and event.tool_result:
                                result_str = str(event.tool_result)[:2000]
                                all_outputs.append(f"📤 Result: {result_str}")
                            
                            # Collect final output
                            if hasattr(event, 'output') and event.output is not None:
                                final_result = event.output
                            
                            # Update task counts
                            task_store[task_id].step_count = step_count
                            task_store[task_id].tool_count = tool_count
                        
                        # Build comprehensive result
                        result_parts = []
                        if final_result:
                            result_parts.append(str(final_result))
                        if not result_parts and all_outputs:
                            result_parts.append("\\n".join(all_outputs[-10:]))  # Last 10 outputs
                        
                        task_store[task_id].status = TaskStatus.completed
                        task_store[task_id].completed_at = datetime.now()
                        task_store[task_id].result = "\\n\\n".join(result_parts) if result_parts else "Task completed successfully"
                        
                    except Exception as e:
                        task_store[task_id].status = TaskStatus.failed
                        task_store[task_id].error = str(e)
                        task_store[task_id].completed_at = datetime.now()
                
                threading.Thread(target=run_background_task, daemon=True).start()
                continue  # Don't block, move to next message
            
            # Stream real agent execution with proper step callbacks
            async def run_with_real_streaming():
                # Send initial progress
                await ws.send_text(json.dumps({
                    "type": "activity",
                    "activity_type": "step",
                    "title": "🚀 Task Started",
                    "content": f"Processing: {msg_content[:100]}..."
                }))
                
                await ws.send_text(json.dumps({
                    "type": "progress",
                    "content": "🔄 Agent analyzing your request..."
                }))
                
                # Queue for thread-safe communication between agent thread and async handler
                event_queue = queue.Queue()
                
                def run_agent_with_streaming():
                    """Run agent in thread and put events in queue."""
                    try:
                        # Use streaming mode for real-time updates
                        final_result = None
                        step_count = 0
                        tool_count = 0
                        
                        for event in agent.run(full_message, stream=True):
                            step_count += 1
                            event_type = type(event).__name__
                            
                            # Extract meaningful info from different event types
                            if hasattr(event, 'tool_calls') and event.tool_calls:
                                for tool_call in event.tool_calls:
                                    tool_count += 1
                                    tool_name = getattr(tool_call, 'name', str(tool_call))
                                    tool_args = getattr(tool_call, 'arguments', {})
                                    
                                    # Map tool names to activity types
                                    activity_type = "tool"
                                    icon = "🔧"
                                    
                                    # Categorize tools for better display
                                    if any(x in tool_name.lower() for x in ['scan', 'nmap', 'nikto', 'dirb', 'gobuster', 'nuclei', 'zap']):
                                        icon = "🔍"
                                        activity_msg = f"Running security scan: {tool_name}"
                                    elif any(x in tool_name.lower() for x in ['virustotal', 'shodan', 'hunter', 'dns', 'whois', 'osint']):
                                        icon = "🌐"
                                        activity_msg = f"OSINT lookup: {tool_name}"
                                    elif any(x in tool_name.lower() for x in ['browse', 'page', 'screenshot', 'playwright', 'click', 'form']):
                                        icon = "🌍"
                                        activity_msg = f"Browser automation: {tool_name}"
                                    elif any(x in tool_name.lower() for x in ['curl', 'request', 'http']):
                                        icon = "📡"
                                        activity_msg = f"HTTP request: {tool_name}"
                                    elif any(x in tool_name.lower() for x in ['report', 'finding', 'summary']):
                                        icon = "📋"
                                        activity_msg = f"Report generation: {tool_name}"
                                        activity_type = "tool-result"
                                    elif any(x in tool_name.lower() for x in ['owasp', 'classify', 'scenario']):
                                        icon = "📚"
                                        activity_msg = f"OWASP analysis: {tool_name}"
                                    else:
                                        activity_msg = f"Executing: {tool_name}"
                                    
                                    # Get target/args info
                                    target_info = ""
                                    if isinstance(tool_args, dict):
                                        for key in ['url', 'target', 'domain', 'ip_address', 'host', 'query']:
                                            if key in tool_args:
                                                target_info = f" → {tool_args[key][:60]}"
                                                break
                                    
                                    event_queue.put({
                                        "type": "activity",
                                        "activity_type": activity_type,
                                        "title": f"{icon} {activity_msg}",
                                        "content": f"Tool #{tool_count}: {tool_name}{target_info}",
                                        "tool_count": tool_count,
                                        "step_count": step_count
                                    })
                            
                            # Check for observations/results
                            if hasattr(event, 'observations') and event.observations:
                                obs = str(event.observations)[:200]
                                event_queue.put({
                                    "type": "activity",
                                    "activity_type": "tool-result",
                                    "title": "📊 Tool Result",
                                    "content": obs + ("..." if len(str(event.observations)) > 200 else ""),
                                    "tool_count": tool_count,
                                    "step_count": step_count
                                })
                            
                            # Check for planning steps
                            if hasattr(event, 'plan') and event.plan:
                                plan = str(event.plan)[:300]
                                event_queue.put({
                                    "type": "activity",
                                    "activity_type": "thinking",
                                    "title": "🧠 Agent Planning",
                                    "content": plan,
                                    "tool_count": tool_count,
                                    "step_count": step_count
                                })
                            
                            # Capture final result
                            if hasattr(event, 'output') and event.output is not None:
                                final_result = event.output
                        
                        # Signal completion
                        event_queue.put({
                            "type": "complete",
                            "result": final_result if final_result else "Task completed",
                            "tool_count": tool_count,
                            "step_count": step_count
                        })
                        
                    except Exception as e:
                        event_queue.put({
                            "type": "error",
                            "error": str(e)
                        })
                
                # Start agent in thread
                loop = asyncio.get_event_loop()
                agent_thread = threading.Thread(target=run_agent_with_streaming, daemon=True)
                agent_thread.start()
                
                # Process events from queue
                final_response = None
                last_tool_count = 0
                last_step_count = 0
                
                while True:
                    try:
                        # Non-blocking check with timeout
                        await asyncio.sleep(0.1)
                        
                        while not event_queue.empty():
                            event = event_queue.get_nowait()
                            
                            if event["type"] == "activity":
                                # Update counts from event
                                last_tool_count = event.get("tool_count", last_tool_count)
                                last_step_count = event.get("step_count", last_step_count)
                                
                                # Send activity update with counts
                                await ws.send_text(json.dumps({
                                    "type": "activity",
                                    "activity_type": event["activity_type"],
                                    "title": event["title"],
                                    "content": event["content"],
                                    "tool_count": last_tool_count,
                                    "step_count": last_step_count
                                }))
                                
                                # Also send progress update for chat
                                await ws.send_text(json.dumps({
                                    "type": "progress",
                                    "content": event["title"]
                                }))
                            
                            elif event["type"] == "complete":
                                final_response = event["result"]
                                last_tool_count = event.get("tool_count", last_tool_count)
                                last_step_count = event.get("step_count", last_step_count)
                                
                                await ws.send_text(json.dumps({
                                    "type": "activity",
                                    "activity_type": "tool-result",
                                    "title": "✅ Task Completed",
                                    "content": f"Finished with {last_step_count} steps, {last_tool_count} tool calls",
                                    "tool_count": last_tool_count,
                                    "step_count": last_step_count
                                }))
                                break
                            
                            elif event["type"] == "error":
                                await ws.send_text(json.dumps({
                                    "type": "activity",
                                    "activity_type": "error",
                                    "title": "❌ Error Occurred",
                                    "content": event["error"]
                                }))
                                await ws.send_text(json.dumps({
                                    "type": "final",
                                    "content": f"Error: {event['error']}"
                                }))
                                return
                        
                        # Check if we got final response
                        if final_response is not None:
                            break
                        
                        # Check if thread died
                        if not agent_thread.is_alive() and event_queue.empty():
                            break
                            
                    except Exception as e:
                        await ws.send_text(json.dumps({
                            "type": "activity",
                            "activity_type": "error", 
                            "title": "❌ Error",
                            "content": str(e)
                        }))
                        break
                
                # Wait for thread to finish
                agent_thread.join(timeout=5)
                
                # Handle report mode
                if final_response and report_mode_enabled and is_report_mode_enabled():
                    if '<!DOCTYPE html>' not in str(final_response) and '<html' not in str(final_response):
                        await ws.send_text(json.dumps({
                            "type": "activity",
                            "activity_type": "tool",
                            "title": "📋 Generating Report",
                            "content": "Creating professional security report..."
                        }))
                        
                        html_report = generate_html_report()
                        md_report = generate_markdown_report()
                        
                        await ws.send_text(json.dumps({
                            "type": "final",
                            "content": str(final_response)
                        }))
                        
                        await ws.send_text(json.dumps({
                            "type": "report",
                            "content": "📋 Professional security report has been generated.",
                            "html": html_report,
                            "markdown": md_report
                        }))
                        return
                
                # Send final response
                await ws.send_text(json.dumps({
                    "type": "final",
                    "content": str(final_response) if final_response else "Task completed"
                }))
            
            await run_with_real_streaming()
            
    except WebSocketDisconnect:
        return
    except Exception as e:
        try:
            await ws.send_text(json.dumps({"type": "final", "content": f"Error: {e}"}))
        except:
            pass

"""Run with: uvicorn app.main:app --reload"""
