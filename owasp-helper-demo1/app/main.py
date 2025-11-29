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
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, Any


# Task management enums and models
class TaskStatus(str, Enum):
    pending = "pending"
    waiting = "waiting"  # Waiting for dependent task to complete
    running = "running"
    paused = "paused"
    completed = "completed"
    cancelled = "cancelled"
    failed = "failed"


class Task(BaseModel):
    id: str
    name: Optional[str] = None  # Human-readable task name
    prompt: str
    status: TaskStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[str] = None
    error: Optional[str] = None
    tool_count: int = 0
    step_count: int = 0
    # Task chaining fields
    depends_on: Optional[str] = None  # Task ID this task depends on
    chain_id: Optional[str] = None  # Chain identifier for grouped tasks
    chain_order: int = 0  # Order in the chain
    use_previous_result: bool = False  # Whether to inject previous task result
    chain_name: Optional[str] = None  # Human-readable chain name


# Task chain management
class TaskChain(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    created_at: datetime
    status: TaskStatus
    tasks: list[str] = []  # Ordered list of task IDs
    current_task_index: int = 0


app = FastAPI(title="OWASP SmolAgent")
agent = None
startup_lock = asyncio.Lock()
agent_lock = threading.Lock()  # Lock for concurrent agent access
executor = ThreadPoolExecutor(max_workers=8)

# File storage for sessions
file_store: dict[str, list[dict]] = {}

# Task management
task_store: Dict[str, Task] = {}
tasks_store: Dict[str, Dict[str, Any]] = {}
task_queues: Dict[str, queue.Queue] = {}

# Task chain management
chain_store: Dict[str, TaskChain] = {}
CHAINS_FILE = os.path.join(os.path.dirname(__file__), ".task_chains.json")
chain_monitor_thread = None
chain_monitor_stop_event = threading.Event()

# API Keys storage with file persistence
API_KEYS_FILE = os.path.join(os.path.dirname(__file__), ".api_keys.json")
api_keys_store: Dict[str, str] = {}

# Chat history storage with file persistence
CHATS_FILE = os.path.join(os.path.dirname(__file__), ".chats.json")
chats_store: Dict[str, Dict[str, Any]] = {}  # chat_id -> {name, messages, created_at, updated_at}

# Scheduled tasks storage
SCHEDULED_TASKS_FILE = os.path.join(os.path.dirname(__file__), ".scheduled_tasks.json")
scheduled_tasks_store: Dict[str, Dict[str, Any]] = {}  # task_id -> {prompt, schedule_time, recurring, interval, status, etc.}
scheduler_thread = None
scheduler_stop_event = threading.Event()

# Custom context/instructions storage
CUSTOM_CONTEXT_FILE = os.path.join(os.path.dirname(__file__), ".custom_context.txt")
custom_context: str = ""

def load_chats_from_file():
    """Load chat history from file."""
    global chats_store
    if os.path.exists(CHATS_FILE):
        try:
            with open(CHATS_FILE, 'r', encoding='utf-8') as f:
                chats_store = json.load(f)
        except Exception as e:
            print(f"Error loading chats: {e}")
            chats_store = {}
    
    # Ensure default chat exists
    if not chats_store:
        chats_store["default"] = {
            "name": "Main Chat",
            "messages": [],
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }

def save_chats_to_file():
    """Save chat history to file."""
    try:
        with open(CHATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(chats_store, f, indent=2, default=str)
        return True
    except Exception as e:
        print(f"Error saving chats: {e}")
        return False

def load_scheduled_tasks_from_file():
    """Load scheduled tasks from file."""
    global scheduled_tasks_store
    if os.path.exists(SCHEDULED_TASKS_FILE):
        try:
            with open(SCHEDULED_TASKS_FILE, 'r', encoding='utf-8') as f:
                scheduled_tasks_store = json.load(f)
        except Exception as e:
            print(f"Error loading scheduled tasks: {e}")
            scheduled_tasks_store = {}

def save_scheduled_tasks_to_file():
    """Save scheduled tasks to file."""
    try:
        with open(SCHEDULED_TASKS_FILE, 'w', encoding='utf-8') as f:
            json.dump(scheduled_tasks_store, f, indent=2, default=str)
        return True
    except Exception as e:
        print(f"Error saving scheduled tasks: {e}")
        return False

def load_custom_context():
    """Load custom context from file."""
    global custom_context
    if os.path.exists(CUSTOM_CONTEXT_FILE):
        try:
            with open(CUSTOM_CONTEXT_FILE, 'r', encoding='utf-8') as f:
                custom_context = f.read()
        except Exception as e:
            print(f"Error loading custom context: {e}")
            custom_context = ""

def save_custom_context():
    """Save custom context to file."""
    try:
        with open(CUSTOM_CONTEXT_FILE, 'w', encoding='utf-8') as f:
            f.write(custom_context)
        return True
    except Exception as e:
        print(f"Error saving custom context: {e}")
        return False

def run_scheduler():
    """Background thread to check and execute scheduled tasks."""
    global scheduler_stop_event
    while not scheduler_stop_event.is_set():
        try:
            now = datetime.now()
            for task_id, task in list(scheduled_tasks_store.items()):
                if task.get("status") != "active":
                    continue
                
                # Parse schedule_time, handling both aware and naive datetimes
                schedule_time_str = task["schedule_time"]
                schedule_time = datetime.fromisoformat(schedule_time_str.replace('Z', '+00:00'))
                
                # Convert to naive datetime for comparison (remove timezone info)
                if schedule_time.tzinfo is not None:
                    # Convert to local time and make naive
                    import time
                    local_offset = time.timezone if time.localtime().tm_isdst == 0 else time.altzone
                    schedule_time = schedule_time.replace(tzinfo=None) - timedelta(seconds=-local_offset)
                
                # Check if it's time to run
                if now >= schedule_time:
                    # Mark as running immediately
                    task["status"] = "running"
                    task["last_run"] = now.isoformat()
                    save_scheduled_tasks_to_file()
                    
                    # Execute in separate thread for true concurrency
                    def execute_scheduled_task(tid, task_data):
                        try:
                            # Create dedicated agent for this task
                            task_agent = build_owasp_agent()
                            result = task_agent.run(task_data["prompt"])
                            scheduled_tasks_store[tid]["last_result"] = str(result)[:5000]
                        except Exception as e:
                            scheduled_tasks_store[tid]["last_result"] = f"Error: {str(e)}"
                        finally:
                            # Handle recurring vs one-time
                            if task_data.get("recurring") and task_data.get("interval_minutes"):
                                next_run = datetime.now() + timedelta(minutes=task_data["interval_minutes"])
                                scheduled_tasks_store[tid]["schedule_time"] = next_run.isoformat()
                                scheduled_tasks_store[tid]["status"] = "active"
                            else:
                                scheduled_tasks_store[tid]["status"] = "completed"
                            save_scheduled_tasks_to_file()
                    
                    # Start task in separate thread
                    threading.Thread(
                        target=execute_scheduled_task,
                        args=(task_id, dict(task)),
                        daemon=True
                    ).start()
                    
        except Exception as e:
            print(f"Scheduler error: {e}")
        
        # Check every 30 seconds
        scheduler_stop_event.wait(30)

def start_scheduler():
    """Start the scheduler background thread."""
    global scheduler_thread, scheduler_stop_event
    if scheduler_thread is None or not scheduler_thread.is_alive():
        scheduler_stop_event.clear()
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()


# ============================================
# Task Chain Management Functions
# ============================================

def load_chains_from_file():
    """Load task chains from file."""
    global chain_store
    if os.path.exists(CHAINS_FILE):
        try:
            with open(CHAINS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for chain_id, chain_data in data.items():
                    chain_data['created_at'] = datetime.fromisoformat(chain_data['created_at'])
                    chain_data['status'] = TaskStatus(chain_data['status'])
                    chain_store[chain_id] = TaskChain(**chain_data)
        except Exception as e:
            print(f"Error loading chains: {e}")
            chain_store = {}


def save_chains_to_file():
    """Save task chains to file."""
    try:
        data = {}
        for chain_id, chain in chain_store.items():
            chain_dict = chain.model_dump()
            chain_dict['created_at'] = chain_dict['created_at'].isoformat()
            chain_dict['status'] = chain_dict['status'].value
            data[chain_id] = chain_dict
        with open(CHAINS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error saving chains: {e}")


def run_chained_task(task_id: str, prompt: str, previous_result: str = None):
    """Run a chained task with optional previous result injection."""
    try:
        task_store[task_id].status = TaskStatus.running
        task_store[task_id].started_at = datetime.now()
        
        # Create a dedicated agent for this task
        task_agent = build_owasp_agent()
        
        # Inject previous result if available
        full_prompt = prompt
        if previous_result and task_store[task_id].use_previous_result:
            full_prompt = f"""[CONTEXT FROM PREVIOUS TASK IN CHAIN]
The previous task in this workflow has completed. Here are the results you should use:

{previous_result}

[END OF PREVIOUS TASK RESULTS]

Now, proceed with the following task:

{prompt}"""
        
        step_count = 0
        tool_count = 0
        final_result = None
        all_outputs = []
        
        for event in task_agent.run(full_prompt, stream=True):
            if task_store[task_id].status == TaskStatus.cancelled:
                return
            
            step_count += 1
            
            if hasattr(event, 'tool_calls') and event.tool_calls:
                for tc in event.tool_calls:
                    tool_count += 1
                    if hasattr(tc, 'name'):
                        all_outputs.append(f"🔧 Tool: {tc.name}")
            
            if hasattr(event, 'tool_result') and event.tool_result:
                result_str = str(event.tool_result)
                if 'SCREENSHOT_IMAGE_DATA:' in result_str or 'base64,' in result_str:
                    all_outputs.append(f"📤 Result: {result_str}")
                else:
                    all_outputs.append(f"📤 Result: {result_str[:2000]}")
            
            if hasattr(event, 'output') and event.output is not None:
                final_result = event.output
            
            task_store[task_id].step_count = step_count
            task_store[task_id].tool_count = tool_count
        
        # Build result
        result_parts = []
        screenshot_outputs = [o for o in all_outputs if 'SCREENSHOT_IMAGE_DATA:' in o or 'base64,' in o]
        
        if final_result:
            result_parts.append(str(final_result))
        
        for screenshot in screenshot_outputs:
            if screenshot not in str(final_result) if final_result else True:
                result_parts.append(screenshot)
        
        if not result_parts and all_outputs:
            result_parts.append("\\n".join(all_outputs[-10:]))
        
        task_store[task_id].status = TaskStatus.completed
        task_store[task_id].completed_at = datetime.now()
        task_store[task_id].result = "\\n\\n".join(result_parts) if result_parts else "Task completed successfully"
        
        # Trigger next task in chain if any
        check_and_start_dependent_tasks(task_id)
        
    except Exception as e:
        task_store[task_id].status = TaskStatus.failed
        task_store[task_id].error = str(e)
        task_store[task_id].completed_at = datetime.now()
        
        # Mark chain as failed if this task fails
        if task_store[task_id].chain_id:
            chain_id = task_store[task_id].chain_id
            if chain_id in chain_store:
                chain_store[chain_id].status = TaskStatus.failed
                save_chains_to_file()


def check_and_start_dependent_tasks(completed_task_id: str):
    """Check if any tasks are waiting for this task and start them."""
    completed_task = task_store.get(completed_task_id)
    if not completed_task or completed_task.status != TaskStatus.completed:
        return
    
    # Find tasks waiting for this one
    for task_id, task in task_store.items():
        if task.depends_on == completed_task_id and task.status == TaskStatus.waiting:
            print(f"Starting dependent task {task_id} after {completed_task_id} completed")
            
            # Start the dependent task with the result from completed task
            threading.Thread(
                target=run_chained_task,
                args=(task_id, task.prompt, completed_task.result),
                daemon=True
            ).start()
            
            # Update chain progress
            if task.chain_id and task.chain_id in chain_store:
                chain = chain_store[task.chain_id]
                chain.current_task_index += 1
                
                # Check if chain is complete
                if chain.current_task_index >= len(chain.tasks):
                    chain.status = TaskStatus.completed
                
                save_chains_to_file()


def run_chain_monitor():
    """Background thread to monitor task chain dependencies."""
    while not chain_monitor_stop_event.is_set():
        try:
            # Check for tasks in 'waiting' status whose dependency has completed
            for task_id, task in list(task_store.items()):
                if task.status == TaskStatus.waiting and task.depends_on:
                    dep_task = task_store.get(task.depends_on)
                    if dep_task:
                        if dep_task.status == TaskStatus.completed:
                            check_and_start_dependent_tasks(task.depends_on)
                        elif dep_task.status in [TaskStatus.failed, TaskStatus.cancelled]:
                            # Mark waiting task as failed if dependency failed
                            task_store[task_id].status = TaskStatus.failed
                            task_store[task_id].error = f"Dependency task {task.depends_on} {dep_task.status.value}"
                            task_store[task_id].completed_at = datetime.now()
        except Exception as e:
            print(f"Chain monitor error: {e}")
        
        chain_monitor_stop_event.wait(5)  # Check every 5 seconds


def start_chain_monitor():
    """Start the chain monitor background thread."""
    global chain_monitor_thread, chain_monitor_stop_event
    if chain_monitor_thread is None or not chain_monitor_thread.is_alive():
        chain_monitor_stop_event.clear()
        chain_monitor_thread = threading.Thread(target=run_chain_monitor, daemon=True)
        chain_monitor_thread.start()

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
        "TELEGRAM_BOT_TOKEN": "",
        "TELEGRAM_CHAT_ID": "",
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

class ScheduledTaskCreate(BaseModel):
    prompt: str
    schedule_time: str  # ISO format datetime
    recurring: bool = False
    interval_minutes: Optional[int] = None
    name: Optional[str] = None

class ChatCreate(BaseModel):
    name: str

class ChatMessage(BaseModel):
    chat_id: str
    type: str
    content: str
    timestamp: Optional[str] = None

@app.on_event("startup")
async def startup():
    global agent, api_keys_store
    async with startup_lock:
        if agent is None:
            # Load API keys from file/environment
            load_api_keys_from_file()
            # Load chat history
            load_chats_from_file()
            # Load scheduled tasks
            load_scheduled_tasks_from_file()
            # Load custom context
            load_custom_context()
            # Load task chains
            load_chains_from_file()
            # Start scheduler
            start_scheduler()
            # Start chain monitor
            start_chain_monitor()
            # Build agent
            agent = build_owasp_agent()


# ============================================
# Health Check Endpoint
# ============================================
@app.get("/health")
async def health_check():
    """Health check endpoint for container orchestration."""
    return JSONResponse({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "0.2.0",
        "agent_ready": agent is not None
    })


@app.get("/api/health")
async def api_health_check():
    """Detailed health check with component status."""
    components = {
        "agent": agent is not None,
        "scheduler": scheduler_thread is not None and scheduler_thread.is_alive() if 'scheduler_thread' in globals() else False,
        "executor": executor is not None,
    }
    
    # Check API key configuration
    api_configured = bool(api_keys_store.get("DEEPSEEK_API_KEY"))
    
    return JSONResponse({
        "status": "healthy" if all(components.values()) and api_configured else "degraded",
        "timestamp": datetime.now().isoformat(),
        "version": "0.2.0",
        "components": components,
        "api_configured": api_configured
    })


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

# ============== CHAT MANAGEMENT ENDPOINTS ==============

@app.get("/api/chats")
async def get_chats():
    """Get all chats with metadata (not full messages)."""
    chat_list = []
    for chat_id, chat in chats_store.items():
        chat_list.append({
            "id": chat_id,
            "name": chat.get("name", "Unnamed"),
            "message_count": len(chat.get("messages", [])),
            "created_at": chat.get("created_at"),
            "updated_at": chat.get("updated_at")
        })
    # Sort by updated_at descending
    chat_list.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
    return JSONResponse(chat_list)

@app.get("/api/chats/{chat_id}")
async def get_chat(chat_id: str):
    """Get a specific chat with all messages."""
    if chat_id not in chats_store:
        return JSONResponse({"error": "Chat not found"}, status_code=404)
    return JSONResponse(chats_store[chat_id])

@app.post("/api/chats")
async def create_chat(chat: ChatCreate):
    """Create a new chat."""
    chat_id = str(uuid.uuid4())[:8]
    chats_store[chat_id] = {
        "name": chat.name,
        "messages": [],
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
    save_chats_to_file()
    return JSONResponse({"success": True, "chat_id": chat_id, "name": chat.name})

@app.put("/api/chats/{chat_id}")
async def update_chat(chat_id: str, chat: ChatCreate):
    """Update chat name."""
    if chat_id not in chats_store:
        return JSONResponse({"error": "Chat not found"}, status_code=404)
    chats_store[chat_id]["name"] = chat.name
    chats_store[chat_id]["updated_at"] = datetime.now().isoformat()
    save_chats_to_file()
    return JSONResponse({"success": True, "chat_id": chat_id})

@app.delete("/api/chats/{chat_id}")
async def delete_chat(chat_id: str):
    """Delete a chat."""
    if chat_id == "default":
        return JSONResponse({"error": "Cannot delete default chat"}, status_code=400)
    if chat_id not in chats_store:
        return JSONResponse({"error": "Chat not found"}, status_code=404)
    del chats_store[chat_id]
    save_chats_to_file()
    return JSONResponse({"success": True, "chat_id": chat_id})

@app.post("/api/chats/{chat_id}/messages")
async def add_chat_message(chat_id: str, message: ChatMessage):
    """Add a message to a chat."""
    if chat_id not in chats_store:
        # Auto-create chat if it doesn't exist
        chats_store[chat_id] = {
            "name": f"Chat {chat_id}",
            "messages": [],
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
    
    msg_data = {
        "type": message.type,
        "content": message.content,
        "timestamp": message.timestamp or datetime.now().isoformat()
    }
    chats_store[chat_id]["messages"].append(msg_data)
    chats_store[chat_id]["updated_at"] = datetime.now().isoformat()
    
    # Keep only last 500 messages per chat to prevent file bloat
    if len(chats_store[chat_id]["messages"]) > 500:
        chats_store[chat_id]["messages"] = chats_store[chat_id]["messages"][-500:]
    
    save_chats_to_file()
    return JSONResponse({"success": True})

@app.delete("/api/chats/{chat_id}/messages")
async def clear_chat_messages(chat_id: str):
    """Clear all messages from a chat."""
    if chat_id not in chats_store:
        return JSONResponse({"error": "Chat not found"}, status_code=404)
    chats_store[chat_id]["messages"] = []
    chats_store[chat_id]["updated_at"] = datetime.now().isoformat()
    save_chats_to_file()
    return JSONResponse({"success": True})

class ChatSaveRequest(BaseModel):
    """Request to bulk save chat messages."""
    messages: list[dict]

@app.post("/api/chats/{chat_id}/save")
async def save_chat_bulk(chat_id: str, request: ChatSaveRequest):
    """Bulk save all messages for a chat (used by beforeunload)."""
    if chat_id not in chats_store:
        chats_store[chat_id] = {
            "name": f"Chat {chat_id}",
            "messages": [],
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
    
    # Replace all messages
    chats_store[chat_id]["messages"] = request.messages
    chats_store[chat_id]["updated_at"] = datetime.now().isoformat()
    
    # Keep only last 500 messages
    if len(chats_store[chat_id]["messages"]) > 500:
        chats_store[chat_id]["messages"] = chats_store[chat_id]["messages"][-500:]
    
    save_chats_to_file()
    return JSONResponse({"success": True})

# ============== SCHEDULED TASKS ENDPOINTS ==============

@app.get("/api/scheduled")
async def get_scheduled_tasks():
    """Get all scheduled tasks."""
    tasks = []
    for task_id, task in scheduled_tasks_store.items():
        tasks.append({
            "id": task_id,
            **task
        })
    # Sort by schedule_time
    tasks.sort(key=lambda x: x.get("schedule_time", ""))
    return JSONResponse(tasks)

@app.post("/api/scheduled")
async def create_scheduled_task(task: ScheduledTaskCreate):
    """Create a new scheduled task."""
    task_id = str(uuid.uuid4())[:8]
    scheduled_tasks_store[task_id] = {
        "prompt": task.prompt,
        "name": task.name or task.prompt[:50],
        "schedule_time": task.schedule_time,
        "recurring": task.recurring,
        "interval_minutes": task.interval_minutes,
        "status": "active",
        "created_at": datetime.now().isoformat(),
        "last_run": None,
        "last_result": None
    }
    save_scheduled_tasks_to_file()
    return JSONResponse({"success": True, "task_id": task_id})

@app.delete("/api/scheduled/{task_id}")
async def delete_scheduled_task(task_id: str):
    """Delete/cancel a scheduled task."""
    if task_id not in scheduled_tasks_store:
        return JSONResponse({"error": "Task not found"}, status_code=404)
    del scheduled_tasks_store[task_id]
    save_scheduled_tasks_to_file()
    return JSONResponse({"success": True})

@app.patch("/api/scheduled/{task_id}")
async def toggle_scheduled_task(task_id: str):
    """Pause/resume a scheduled task."""
    if task_id not in scheduled_tasks_store:
        return JSONResponse({"error": "Task not found"}, status_code=404)
    task = scheduled_tasks_store[task_id]
    if task["status"] == "active":
        task["status"] = "paused"
    elif task["status"] == "paused":
        task["status"] = "active"
    save_scheduled_tasks_to_file()
    return JSONResponse({"success": True, "status": task["status"]})

@app.put("/api/scheduled/{task_id}")
async def update_scheduled_task(task_id: str, update: ScheduledTaskCreate):
    """Update a scheduled task."""
    if task_id not in scheduled_tasks_store:
        return JSONResponse({"error": "Task not found"}, status_code=404)
    
    task = scheduled_tasks_store[task_id]
    task["prompt"] = update.prompt
    task["name"] = update.name or update.prompt[:50]
    task["schedule_time"] = update.schedule_time
    task["recurring"] = update.recurring
    task["interval_minutes"] = update.interval_minutes
    save_scheduled_tasks_to_file()
    return JSONResponse({"success": True, "task_id": task_id})

# ============== CUSTOM CONTEXT ENDPOINTS ==============

@app.get("/api/context")
async def get_custom_context():
    """Get custom context/instructions."""
    return JSONResponse({"context": custom_context})

@app.post("/api/context")
async def set_custom_context(data: Dict[str, str]):
    """Set custom context/instructions."""
    global custom_context
    custom_context = data.get("context", "")
    save_custom_context()
    return JSONResponse({"success": True})

# Telegram monitoring state
telegram_monitoring_active = False
telegram_monitor_thread = None
telegram_monitor_stop_event = threading.Event()

def run_telegram_monitor():
    """Background thread to monitor Telegram groups for bot mentions."""
    global telegram_monitoring_active
    from app.tools.telegram_tool import _telegram_state, _run_async, _get_telegram_bot
    
    Bot, err = _get_telegram_bot()
    if err or not _telegram_state.get("bot"):
        print(f"Telegram monitor: Bot not available - {err}")
        telegram_monitoring_active = False
        return
    
    bot_username = _telegram_state.get("bot_username", "").lower()
    if not bot_username:
        print("Telegram monitor: Bot username not set")
        telegram_monitoring_active = False
        return
    
    last_update_id = 0
    print(f"Telegram monitor: Starting to monitor for @{bot_username}")
    
    while not telegram_monitor_stop_event.is_set():
        try:
            async def get_updates():
                bot = _telegram_state["bot"]
                return await bot.get_updates(offset=last_update_id + 1, timeout=30)
            
            updates = _run_async(get_updates())
            
            for update in updates:
                last_update_id = update.update_id
                
                if not update.message or not update.message.text:
                    continue
                
                msg = update.message
                text = msg.text.lower()
                
                # Check if bot is mentioned
                bot_mention = f"@{bot_username}"
                if bot_mention not in text:
                    continue
                
                # Extract command after mention
                command = msg.text.replace(f"@{bot_username}", "").replace(f"@{bot_username.upper()}", "").strip()
                if not command:
                    continue
                
                chat_id = msg.chat.id
                user = msg.from_user.username if msg.from_user else "Unknown"
                
                print(f"Telegram command from @{user} in chat {chat_id}: {command}")
                
                # Send acknowledgment
                async def send_ack():
                    await _telegram_state["bot"].send_message(
                        chat_id=chat_id,
                        text=f"🤖 Processing your request: {command[:100]}...",
                        reply_to_message_id=msg.message_id
                    )
                _run_async(send_ack())
                
                # Execute command with agent
                def execute_command():
                    try:
                        task_agent = build_owasp_agent()
                        result = task_agent.run(command)
                        
                        # Send result back (truncate if too long)
                        result_text = str(result)
                        if len(result_text) > 4000:
                            result_text = result_text[:4000] + "\\n\\n[Result truncated]"
                        
                        async def send_result():
                            await _telegram_state["bot"].send_message(
                                chat_id=chat_id,
                                text=f"✅ Result for @{user}:\\n\\n{result_text}",
                                reply_to_message_id=msg.message_id
                            )
                        _run_async(send_result())
                    except Exception as e:
                        async def send_error():
                            await _telegram_state["bot"].send_message(
                                chat_id=chat_id,
                                text=f"❌ Error: {str(e)[:500]}",
                                reply_to_message_id=msg.message_id
                            )
                        _run_async(send_error())
                
                # Run in separate thread
                threading.Thread(target=execute_command, daemon=True).start()
                
        except Exception as e:
            if not telegram_monitor_stop_event.is_set():
                print(f"Telegram monitor error: {e}")
                time.sleep(5)
    
    print("Telegram monitor: Stopped")

@app.post("/api/telegram/monitor/start")
async def start_telegram_monitoring():
    """Start monitoring Telegram groups for bot mentions."""
    global telegram_monitoring_active, telegram_monitor_thread, telegram_monitor_stop_event
    from app.tools.telegram_tool import _telegram_state, telegram_connect
    
    # Check if bot is connected
    if not _telegram_state.get("connected"):
        # Try to connect
        bot_token = api_keys_store.get("TELEGRAM_BOT_TOKEN", "")
        if not bot_token:
            return JSONResponse({"success": False, "error": "No bot token configured"})
        
        result = telegram_connect(bot_token)
        if "❌" in result:
            return JSONResponse({"success": False, "error": "Failed to connect to Telegram"})
    
    if telegram_monitoring_active:
        return JSONResponse({"success": True, "message": "Already monitoring"})
    
    telegram_monitor_stop_event.clear()
    telegram_monitoring_active = True
    telegram_monitor_thread = threading.Thread(target=run_telegram_monitor, daemon=True)
    telegram_monitor_thread.start()
    
    return JSONResponse({
        "success": True, 
        "bot_username": _telegram_state.get("bot_username", "")
    })

@app.post("/api/telegram/monitor/stop")
async def stop_telegram_monitoring():
    """Stop monitoring Telegram groups."""
    global telegram_monitoring_active, telegram_monitor_stop_event
    
    telegram_monitor_stop_event.set()
    telegram_monitoring_active = False
    
    return JSONResponse({"success": True})

@app.get("/api/telegram/monitor/status")
async def get_telegram_monitoring_status():
    """Get Telegram monitoring status."""
    from app.tools.telegram_tool import _telegram_state
    
    return JSONResponse({
        "active": telegram_monitoring_active,
        "connected": _telegram_state.get("connected", False),
        "bot_username": _telegram_state.get("bot_username", "")
    })

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
async def cancel_or_delete_task(task_id: str, remove: bool = False):
    """Cancel a running task or remove a completed/cancelled/failed task."""
    if task_id in task_store:
        task = task_store[task_id]
        # If task is not running, or remove flag is set, delete it
        if remove or task.status in [TaskStatus.completed, TaskStatus.cancelled, TaskStatus.failed]:
            del task_store[task_id]
            return JSONResponse({"success": True, "task_id": task_id, "status": "deleted"})
        else:
            # Cancel running task
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

# =============================================
# Task Chain Management Endpoints
# =============================================

class ChainTaskInput(BaseModel):
    """Input for a task in a chain."""
    prompt: str
    name: Optional[str] = None
    use_previous_result: bool = True


class CreateChainRequest(BaseModel):
    """Request to create a new task chain."""
    name: str
    description: Optional[str] = None
    tasks: list[ChainTaskInput]  # Ordered list of tasks


class AddChainTaskRequest(BaseModel):
    """Request to add a task to an existing chain."""
    prompt: str
    name: Optional[str] = None
    use_previous_result: bool = True
    position: Optional[int] = None  # None = append to end


@app.get("/api/chains")
async def get_chains():
    """Get all task chains."""
    chains = []
    for chain_id, chain in chain_store.items():
        chain_data = chain.model_dump()
        chain_data["created_at"] = chain_data["created_at"].isoformat()
        
        # Add task details
        chain_data["task_details"] = []
        for task_id in chain.tasks:
            if task_id in task_store:
                task = task_store[task_id]
                chain_data["task_details"].append({
                    "id": task_id,
                    "name": task.name,
                    "prompt": task.prompt[:100] + "..." if len(task.prompt) > 100 else task.prompt,
                    "status": task.status.value,
                    "chain_order": task.chain_order
                })
        
        chains.append(chain_data)
    
    return JSONResponse(chains)


@app.get("/api/chains/{chain_id}")
async def get_chain(chain_id: str):
    """Get a specific chain with full task details."""
    if chain_id not in chain_store:
        return JSONResponse({"error": "Chain not found"}, status_code=404)
    
    chain = chain_store[chain_id]
    chain_data = chain.model_dump()
    chain_data["created_at"] = chain_data["created_at"].isoformat()
    
    # Add full task details
    chain_data["task_details"] = []
    for task_id in chain.tasks:
        if task_id in task_store:
            task = task_store[task_id].model_dump()
            if task.get("created_at"):
                task["created_at"] = task["created_at"].isoformat()
            if task.get("started_at"):
                task["started_at"] = task["started_at"].isoformat()
            if task.get("completed_at"):
                task["completed_at"] = task["completed_at"].isoformat()
            chain_data["task_details"].append(task)
    
    return JSONResponse(chain_data)


@app.post("/api/chains")
async def create_chain(request: CreateChainRequest):
    """Create a new task chain with multiple ordered tasks."""
    chain_id = str(uuid.uuid4())
    now = datetime.now()
    
    # Create chain object
    chain = TaskChain(
        id=chain_id,
        name=request.name,
        description=request.description,
        created_at=now,
        status=TaskStatus.pending,
        tasks=[],
        current_task_index=0
    )
    
    # Create tasks for the chain
    previous_task_id = None
    for index, task_input in enumerate(request.tasks):
        task_id = str(uuid.uuid4())
        task_name = task_input.name or f"Step {index + 1}"
        
        task = Task(
            id=task_id,
            name=task_name,
            prompt=task_input.prompt,
            status=TaskStatus.waiting if index > 0 else TaskStatus.pending,
            created_at=now,
            depends_on=previous_task_id,
            chain_id=chain_id,
            chain_order=index,
            use_previous_result=task_input.use_previous_result if index > 0 else False,
            chain_name=request.name
        )
        
        task_store[task_id] = task
        chain.tasks.append(task_id)
        previous_task_id = task_id
    
    chain_store[chain_id] = chain
    save_chains_to_file()
    
    return JSONResponse({
        "success": True,
        "chain_id": chain_id,
        "name": request.name,
        "task_count": len(request.tasks),
        "task_ids": chain.tasks
    })


@app.post("/api/chains/{chain_id}/start")
async def start_chain(chain_id: str):
    """Start executing a task chain."""
    if chain_id not in chain_store:
        return JSONResponse({"error": "Chain not found"}, status_code=404)
    
    chain = chain_store[chain_id]
    
    if chain.status == TaskStatus.running:
        return JSONResponse({"error": "Chain is already running"}, status_code=400)
    
    if not chain.tasks:
        return JSONResponse({"error": "Chain has no tasks"}, status_code=400)
    
    # Start the chain monitor if not running
    start_chain_monitor()
    
    # Get the first task
    first_task_id = chain.tasks[0]
    if first_task_id not in task_store:
        return JSONResponse({"error": "First task not found"}, status_code=500)
    
    first_task = task_store[first_task_id]
    
    # Update chain status
    chain.status = TaskStatus.running
    chain.current_task_index = 0
    save_chains_to_file()
    
    # Start the first task
    threading.Thread(
        target=run_chained_task,
        args=(first_task_id, first_task.prompt, None),
        daemon=True
    ).start()
    
    return JSONResponse({
        "success": True,
        "chain_id": chain_id,
        "started_task_id": first_task_id,
        "status": "running"
    })


@app.post("/api/chains/{chain_id}/stop")
async def stop_chain(chain_id: str):
    """Stop a running task chain."""
    if chain_id not in chain_store:
        return JSONResponse({"error": "Chain not found"}, status_code=404)
    
    chain = chain_store[chain_id]
    
    if chain.status != TaskStatus.running:
        return JSONResponse({"error": "Chain is not running"}, status_code=400)
    
    # Cancel all pending/waiting tasks in the chain
    cancelled_tasks = []
    for task_id in chain.tasks:
        if task_id in task_store:
            task = task_store[task_id]
            if task.status in [TaskStatus.pending, TaskStatus.waiting, TaskStatus.running]:
                task.status = TaskStatus.cancelled
                task.completed_at = datetime.now()
                cancelled_tasks.append(task_id)
    
    chain.status = TaskStatus.cancelled
    save_chains_to_file()
    
    return JSONResponse({
        "success": True,
        "chain_id": chain_id,
        "cancelled_tasks": cancelled_tasks,
        "status": "cancelled"
    })


@app.delete("/api/chains/{chain_id}")
async def delete_chain(chain_id: str):
    """Delete a task chain and optionally its tasks."""
    if chain_id not in chain_store:
        return JSONResponse({"error": "Chain not found"}, status_code=404)
    
    chain = chain_store[chain_id]
    
    # Can't delete running chains
    if chain.status == TaskStatus.running:
        return JSONResponse({"error": "Cannot delete a running chain. Stop it first."}, status_code=400)
    
    # Delete all tasks in the chain
    deleted_tasks = []
    for task_id in chain.tasks:
        if task_id in task_store:
            del task_store[task_id]
            deleted_tasks.append(task_id)
    
    # Delete the chain
    del chain_store[chain_id]
    save_chains_to_file()
    
    return JSONResponse({
        "success": True,
        "chain_id": chain_id,
        "deleted_tasks": deleted_tasks
    })


@app.post("/api/chains/{chain_id}/tasks")
async def add_task_to_chain(chain_id: str, request: AddChainTaskRequest):
    """Add a task to an existing chain."""
    if chain_id not in chain_store:
        return JSONResponse({"error": "Chain not found"}, status_code=404)
    
    chain = chain_store[chain_id]
    
    if chain.status == TaskStatus.running:
        return JSONResponse({"error": "Cannot add tasks to a running chain"}, status_code=400)
    
    # Determine position
    position = request.position if request.position is not None else len(chain.tasks)
    position = max(0, min(position, len(chain.tasks)))
    
    # Create the new task
    task_id = str(uuid.uuid4())
    now = datetime.now()
    
    # Determine dependency
    depends_on = None
    if position > 0:
        depends_on = chain.tasks[position - 1]
    
    task_name = request.name or f"Step {position + 1}"
    
    task = Task(
        id=task_id,
        name=task_name,
        prompt=request.prompt,
        status=TaskStatus.pending if position == 0 else TaskStatus.waiting,
        created_at=now,
        depends_on=depends_on,
        chain_id=chain_id,
        chain_order=position,
        use_previous_result=request.use_previous_result if position > 0 else False,
        chain_name=chain.name
    )
    
    task_store[task_id] = task
    
    # Insert task at position
    chain.tasks.insert(position, task_id)
    
    # Update chain_order and depends_on for subsequent tasks
    for i, tid in enumerate(chain.tasks):
        if tid in task_store:
            task_store[tid].chain_order = i
            if i > 0:
                task_store[tid].depends_on = chain.tasks[i - 1]
    
    save_chains_to_file()
    
    return JSONResponse({
        "success": True,
        "task_id": task_id,
        "chain_id": chain_id,
        "position": position
    })


@app.delete("/api/chains/{chain_id}/tasks/{task_id}")
async def remove_task_from_chain(chain_id: str, task_id: str):
    """Remove a task from a chain."""
    if chain_id not in chain_store:
        return JSONResponse({"error": "Chain not found"}, status_code=404)
    
    chain = chain_store[chain_id]
    
    if chain.status == TaskStatus.running:
        return JSONResponse({"error": "Cannot remove tasks from a running chain"}, status_code=400)
    
    if task_id not in chain.tasks:
        return JSONResponse({"error": "Task not in this chain"}, status_code=404)
    
    # Remove the task
    chain.tasks.remove(task_id)
    
    if task_id in task_store:
        del task_store[task_id]
    
    # Update chain_order and depends_on for remaining tasks
    for i, tid in enumerate(chain.tasks):
        if tid in task_store:
            task_store[tid].chain_order = i
            if i > 0:
                task_store[tid].depends_on = chain.tasks[i - 1]
            else:
                task_store[tid].depends_on = None
                task_store[tid].status = TaskStatus.pending
    
    save_chains_to_file()
    
    return JSONResponse({
        "success": True,
        "removed_task_id": task_id,
        "chain_id": chain_id,
        "remaining_tasks": len(chain.tasks)
    })


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
  --gradient-accent: linear-gradient(135deg, #0ea5e9 0%, #06b6d4 100%);
  --gradient-dark: linear-gradient(135deg, #1e293b 0%, #334155 100%);
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
  --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -2px rgba(0,0,0,0.1);
  --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -4px rgba(0,0,0,0.1);
  --shadow-xl: 0 20px 25px -5px rgba(0,0,0,0.1), 0 8px 10px -6px rgba(0,0,0,0.1);
  --bg-primary: var(--darker);
  --bg-secondary: var(--dark);
  --text-primary: var(--light);
  --text-secondary: var(--gray-300);
  --border-color: rgba(255,255,255,0.1);
  --sidebar-width: 420px;
  --sidebar-min-width: 320px;
  --sidebar-max-width: 600px;
}
/* Light Theme */
body.light-theme {
  --bg-primary: #f8fafc;
  --bg-secondary: #ffffff;
  --text-primary: #1e293b;
  --text-secondary: #475569;
  --border-color: rgba(0,0,0,0.15);
  --dark: #f1f5f9;
  --darker: #ffffff;
  --light: #1e293b;
  --gray-100: #1e293b;
  --gray-200: #334155;
  --gray-300: #475569;
  --gray-400: #64748b;
  --gray-500: #94a3b8;
  --gray-600: #e2e8f0;
  --gradient-dark: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.1);
  --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.15);
}
body.light-theme .message { color: var(--text-primary); }
body.light-theme .msg-agent { background: #e2e8f0; color: #1e293b; }
body.light-theme .msg-user { background: var(--primary); color: white; }
body.light-theme .msg-system { background: rgba(99, 102, 241, 0.15); color: #1e293b; }
body.light-theme input, body.light-theme textarea { color: #1e293b; background: #f1f5f9; border-color: #cbd5e1; }
body.light-theme input::placeholder, body.light-theme textarea::placeholder { color: #94a3b8; }
body.light-theme .sidebar { background: #ffffff; border-color: #e2e8f0; }
body.light-theme .task-item, body.light-theme .chat-item, body.light-theme .scheduled-item { background: #f1f5f9; border-color: #e2e8f0; }
body.light-theme .task-modal-content { background: #ffffff; color: #1e293b; }
body.light-theme .task-modal-body { color: #334155; }
body.light-theme .activity-item { background: rgba(0,0,0,0.03); border-color: rgba(0,0,0,0.08); color: #334155; }
body.light-theme .api-key-input { background: #f1f5f9; color: #1e293b; border-color: #cbd5e1; }
body.light-theme header { background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%); border-color: #e2e8f0; }
body.light-theme .settings-section-title { color: #1e293b; }
body.light-theme .no-tasks { color: #64748b; }
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
  border-radius: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: var(--shadow-lg), 0 0 20px rgba(99, 102, 241, 0.3);
  color: white;
}
.logo-icon svg {
  width: 26px;
  height: 26px;
  stroke: white;
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
  font-size: 0.75rem;
  color: var(--gray-400);
  font-weight: 400;
  letter-spacing: 0.3px;
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
  transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  height: 100%;
  overflow: hidden;
  position: relative;
}
#sidebar.expanded {
  width: var(--sidebar-width);
  min-width: var(--sidebar-min-width);
  max-width: var(--sidebar-max-width);
}
/* Sidebar Resize Handle */
.sidebar-resize-handle {
  position: absolute;
  top: 0;
  right: -3px;
  width: 6px;
  height: 100%;
  cursor: ew-resize;
  z-index: 100;
  background: transparent;
}
.sidebar-resize-handle:hover,
.sidebar-resize-handle.dragging {
  background: var(--primary);
}
.sidebar-resize-handle::after {
  content: '';
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 4px;
  height: 40px;
  background: var(--gray-500);
  border-radius: 2px;
  opacity: 0;
  transition: opacity 0.2s;
}
.sidebar-resize-handle:hover::after {
  opacity: 1;
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
  font-size: 1.1rem;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  gap: 0.5rem;
}
.sidebar-toggle:hover {
  color: var(--primary-light);
  background: rgba(99, 102, 241, 0.1);
}
.sidebar-toggle svg {
  width: 20px;
  height: 20px;
  stroke: currentColor;
  stroke-width: 2;
  fill: none;
}
#sidebar.expanded .sidebar-toggle {
  justify-content: flex-start;
  padding: 1rem 1.25rem;
}
#sidebar.expanded .sidebar-toggle::after {
  content: 'Collapse';
  font-size: 0.8rem;
  font-weight: 500;
  margin-left: 0.5rem;
}
/* Sidebar Tabs */
.sidebar-tabs {
  display: none;
  border-bottom: 1px solid rgba(255,255,255,0.1);
  flex-shrink: 0;
  flex-wrap: wrap;
  background: rgba(0,0,0,0.2);
}
#sidebar.expanded .sidebar-tabs {
  display: flex;
}
.sidebar-tab {
  flex: 1;
  min-width: 60px;
  padding: 0.6rem 0.5rem;
  background: transparent;
  border: none;
  color: var(--gray-400);
  cursor: pointer;
  font-size: 0.7rem;
  font-weight: 500;
  transition: all 0.2s;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.25rem;
  font-family: inherit;
  border-bottom: 2px solid transparent;
}
.sidebar-tab svg {
  width: 18px;
  height: 18px;
  stroke: currentColor;
  stroke-width: 1.75;
  fill: none;
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
.sidebar-tab .tab-label {
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.3px;
}
.sidebar-header {
  padding: 0.85rem 1rem;
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(139, 92, 246, 0.1) 100%);
  border-bottom: 1px solid rgba(255,255,255,0.08);
  font-weight: 600;
  color: var(--primary-light);
  display: none;
  font-size: 0.85rem;
  flex-shrink: 0;
  justify-content: space-between;
}
#sidebar.expanded .sidebar-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.sidebar-header .header-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.sidebar-header svg {
  width: 18px;
  height: 18px;
  stroke: currentColor;
  stroke-width: 2;
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
  padding: 0.85rem;
  margin-bottom: 0.6rem;
  border-radius: 8px;
  background: rgba(255,255,255,0.04);
  border: 1px solid rgba(255,255,255,0.08);
  animation: slideIn 0.3s ease;
  position: relative;
}
.task-delete-btn {
  position: absolute;
  top: 6px;
  right: 6px;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  border: none;
  background: rgba(239, 68, 68, 0.2);
  color: var(--danger);
  font-size: 14px;
  line-height: 1;
  cursor: pointer;
  opacity: 0.6;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  justify-content: center;
}
.task-delete-btn:hover {
  opacity: 1;
  background: var(--danger);
  color: white;
  transform: scale(1.1);
}
.task-item.running {
  border-color: var(--secondary);
  background: rgba(14, 165, 233, 0.08);
  border-left: 3px solid var(--secondary);
}
.task-item.completed {
  border-color: var(--success);
  background: rgba(16, 185, 129, 0.08);
  border-left: 3px solid var(--success);
}
.task-item.paused {
  border-color: var(--warning);
  background: rgba(245, 158, 11, 0.08);
  border-left: 3px solid var(--warning);
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

/* Collapsible Sections for Tasks/Chains */
.tasks-chains-wrapper {
  display: flex;
  flex-direction: column;
  flex: 1;
  overflow-y: auto;
  padding: 0.75rem;
  gap: 0.75rem;
}
.collapsible-section {
  background: rgba(0,0,0,0.2);
  border-radius: 10px;
  overflow: hidden;
  border: 1px solid rgba(255,255,255,0.06);
}
.section-toggle {
  width: 100%;
  padding: 0.75rem 1rem;
  background: transparent;
  border: none;
  color: var(--gray-200);
  font-size: 0.8rem;
  font-weight: 600;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  transition: all 0.2s;
  font-family: inherit;
}
.section-toggle:hover {
  background: rgba(99, 102, 241, 0.1);
  color: var(--primary-light);
}
.section-toggle svg {
  transition: transform 0.2s;
}
.section-toggle[data-expanded="false"] svg {
  transform: rotate(-90deg);
}
.section-toggle .section-count {
  margin-left: auto;
  background: rgba(99, 102, 241, 0.3);
  color: var(--primary-light);
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 0.7rem;
}
.section-content {
  padding: 0.75rem;
  max-height: 400px;
  overflow-y: auto;
  transition: max-height 0.3s ease;
}
.section-content.collapsed {
  max-height: 0;
  padding: 0 0.75rem;
  overflow: hidden;
}

/* Task Chain Styles */
.chain-item {
  padding: 0.85rem;
  margin-bottom: 0.6rem;
  border-radius: 8px;
  background: rgba(139, 92, 246, 0.08);
  border: 1px solid rgba(139, 92, 246, 0.2);
  animation: slideIn 0.3s ease;
}
.chain-item.running {
  border-color: var(--secondary);
  background: rgba(14, 165, 233, 0.1);
}
.chain-item.completed {
  border-color: var(--success);
  background: rgba(16, 185, 129, 0.1);
}
.chain-item.failed {
  border-color: var(--danger);
  background: rgba(239, 68, 68, 0.1);
}
.chain-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}
.chain-name {
  font-weight: 600;
  font-size: 0.95rem;
  color: var(--light);
}
.chain-status {
  font-size: 0.75rem;
  padding: 2px 8px;
  border-radius: 10px;
  font-weight: 500;
}
.chain-status.pending { background: rgba(100, 116, 139, 0.3); color: var(--gray-300); }
.chain-status.running { background: rgba(14, 165, 233, 0.3); color: var(--secondary); }
.chain-status.completed { background: rgba(16, 185, 129, 0.3); color: var(--success); }
.chain-status.failed { background: rgba(239, 68, 68, 0.3); color: var(--danger); }
.chain-status.cancelled { background: rgba(239, 68, 68, 0.2); color: var(--gray-400); }
.chain-progress {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.5rem;
  flex-wrap: wrap;
}
.chain-step {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.75rem;
  font-weight: 600;
  background: rgba(100, 116, 139, 0.3);
  color: var(--gray-300);
  border: 2px solid transparent;
  position: relative;
  cursor: pointer;
  transition: all 0.2s ease;
}
.chain-step::after {
  content: '';
  position: absolute;
  right: -12px;
  width: 8px;
  height: 2px;
  background: var(--gray-600);
}
.chain-step:last-child::after {
  display: none;
}
.chain-step.pending { background: rgba(100, 116, 139, 0.3); border-color: var(--gray-500); }
.chain-step.waiting { background: rgba(245, 158, 11, 0.2); border-color: var(--warning); }
.chain-step.running { background: rgba(14, 165, 233, 0.3); border-color: var(--secondary); animation: pulse 1.5s infinite; }
.chain-step.completed { background: rgba(16, 185, 129, 0.3); border-color: var(--success); color: var(--success); }
.chain-step.failed { background: rgba(239, 68, 68, 0.3); border-color: var(--danger); color: var(--danger); }
.chain-step:hover {
  transform: scale(1.1);
}
.chain-step-tooltip {
  position: absolute;
  bottom: -30px;
  left: 50%;
  transform: translateX(-50%);
  background: var(--darker);
  color: var(--light);
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.7rem;
  white-space: nowrap;
  pointer-events: none;
  opacity: 0;
  transition: opacity 0.2s;
  z-index: 10;
}
.chain-step:hover .chain-step-tooltip {
  opacity: 1;
}
.chain-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.75rem;
}
.chain-btn {
  padding: 6px 12px;
  border: none;
  border-radius: 6px;
  font-size: 0.75rem;
  cursor: pointer;
  transition: all 0.2s ease;
  font-weight: 500;
}
.chain-btn-start {
  background: rgba(16, 185, 129, 0.3);
  color: var(--success);
}
.chain-btn-start:hover {
  background: var(--success);
  color: white;
}
.chain-btn-stop {
  background: rgba(239, 68, 68, 0.3);
  color: var(--danger);
}
.chain-btn-stop:hover {
  background: var(--danger);
  color: white;
}
.chain-btn-delete {
  background: rgba(100, 116, 139, 0.3);
  color: var(--gray-300);
}
.chain-btn-delete:hover {
  background: var(--gray-500);
  color: white;
}
.create-chain-btn {
  width: 100%;
  padding: 10px;
  border: 2px dashed rgba(139, 92, 246, 0.4);
  border-radius: 8px;
  background: transparent;
  color: var(--primary-light);
  font-size: 0.85rem;
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
}
.create-chain-btn:hover {
  background: rgba(139, 92, 246, 0.1);
  border-color: var(--primary-light);
}

/* Chain Builder Modal */
.chain-builder-modal {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0,0,0,0.85);
  z-index: 1001;
  justify-content: center;
  align-items: center;
}
.chain-builder-modal.active {
  display: flex;
}
.chain-builder-content {
  background: var(--dark);
  border-radius: 16px;
  width: 90%;
  max-width: 700px;
  max-height: 85vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  border: 1px solid rgba(139, 92, 246, 0.3);
  box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5);
}
.chain-builder-header {
  padding: 1.25rem;
  border-bottom: 1px solid rgba(255,255,255,0.1);
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: rgba(139, 92, 246, 0.1);
}
.chain-builder-title {
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--primary-light);
  display: flex;
  align-items: center;
  gap: 8px;
}
.chain-builder-body {
  padding: 1.25rem;
  overflow-y: auto;
  flex: 1;
}
.chain-input-group {
  margin-bottom: 1rem;
}
.chain-input-group label {
  display: block;
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--gray-200);
  margin-bottom: 0.4rem;
}
.chain-input-group input,
.chain-input-group textarea {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid rgba(255,255,255,0.15);
  border-radius: 8px;
  background: rgba(0,0,0,0.3);
  color: var(--light);
  font-size: 0.9rem;
  font-family: inherit;
}
.chain-input-group textarea {
  min-height: 80px;
  resize: vertical;
}
.chain-input-group input:focus,
.chain-input-group textarea:focus {
  outline: none;
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
}
.chain-steps-list {
  margin-top: 1rem;
}
.chain-step-item {
  padding: 1rem;
  background: rgba(255,255,255,0.05);
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 8px;
  margin-bottom: 0.75rem;
  position: relative;
}
.chain-step-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}
.chain-step-number {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background: var(--gradient-primary);
  color: white;
  font-size: 0.8rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  justify-content: center;
}
.chain-step-remove {
  width: 24px;
  height: 24px;
  border: none;
  border-radius: 50%;
  background: rgba(239, 68, 68, 0.3);
  color: var(--danger);
  cursor: pointer;
  font-size: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
}
.chain-step-remove:hover {
  background: var(--danger);
  color: white;
}
.chain-step-input {
  width: 100%;
  padding: 0.5rem;
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 6px;
  background: rgba(0,0,0,0.2);
  color: var(--light);
  font-size: 0.85rem;
  font-family: inherit;
  margin-bottom: 0.5rem;
}
.chain-step-textarea {
  width: 100%;
  padding: 0.5rem;
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 6px;
  background: rgba(0,0,0,0.2);
  color: var(--light);
  font-size: 0.85rem;
  font-family: 'JetBrains Mono', monospace;
  min-height: 60px;
  resize: vertical;
}
.chain-step-options {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 0.5rem;
  font-size: 0.75rem;
  color: var(--gray-400);
}
.add-step-btn {
  width: 100%;
  padding: 10px;
  border: 2px dashed rgba(99, 102, 241, 0.4);
  border-radius: 8px;
  background: transparent;
  color: var(--primary-light);
  font-size: 0.85rem;
  cursor: pointer;
  transition: all 0.2s ease;
  margin-top: 0.5rem;
}
.add-step-btn:hover {
  background: rgba(99, 102, 241, 0.1);
  border-color: var(--primary);
}
.chain-builder-footer {
  padding: 1rem 1.25rem;
  border-top: 1px solid rgba(255,255,255,0.1);
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  background: rgba(0,0,0,0.2);
}
.chain-builder-btn {
  padding: 10px 20px;
  border: none;
  border-radius: 8px;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
}
.chain-builder-btn-cancel {
  background: rgba(100, 116, 139, 0.3);
  color: var(--gray-300);
}
.chain-builder-btn-cancel:hover {
  background: var(--gray-500);
  color: white;
}
.chain-builder-btn-create {
  background: var(--gradient-primary);
  color: white;
}
.chain-builder-btn-create:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 15px rgba(99, 102, 241, 0.4);
}

/* Schedule Form Styles */
.schedule-form {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.form-group {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.form-group label {
  font-size: 0.8rem;
  font-weight: 500;
  color: var(--gray-200);
}
.form-group input[type="text"],
.form-group input[type="number"],
.form-group input[type="datetime-local"],
.form-group textarea {
  padding: 8px 10px;
  background: var(--darker);
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 6px;
  color: var(--light);
  font-size: 0.85rem;
  font-family: inherit;
  transition: border-color 0.2s;
}
.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: var(--primary);
}
.form-group textarea {
  resize: vertical;
  min-height: 60px;
}
.form-row {
  display: flex;
  gap: 10px;
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
/* Chats Tab */
#chats-list {
  flex: 1;
  overflow-y: auto;
  padding: 0.5rem;
}
.chat-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.75rem;
  margin-bottom: 0.5rem;
  background: rgba(255,255,255,0.05);
  border-radius: 8px;
  border: 1px solid rgba(255,255,255,0.1);
  cursor: pointer;
  transition: all 0.2s;
}
.chat-item:hover {
  background: rgba(99, 102, 241, 0.1);
  border-color: rgba(99, 102, 241, 0.3);
}
.chat-item.active {
  background: rgba(99, 102, 241, 0.2);
  border-color: var(--primary);
}
.chat-item-info {
  flex: 1;
  min-width: 0;
}
.chat-item-name {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--light);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.chat-item-meta {
  font-size: 0.7rem;
  color: var(--gray-500);
  margin-top: 2px;
}
.chat-item-actions {
  display: flex;
  gap: 4px;
  opacity: 0;
  transition: opacity 0.2s;
}
.chat-item:hover .chat-item-actions {
  opacity: 1;
}
.chat-item-btn {
  background: none;
  border: none;
  padding: 4px;
  cursor: pointer;
  font-size: 0.9rem;
  opacity: 0.7;
  transition: opacity 0.2s;
}
.chat-item-btn:hover {
  opacity: 1;
}
.btn-new-chat {
  background: var(--primary);
  border: none;
  color: white;
  width: 24px;
  height: 24px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 0.9rem;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-left: auto;
  transition: all 0.2s;
}
.btn-new-chat:hover {
  background: var(--primary-dark);
  transform: scale(1.1);
}
/* Scheduled Tasks - Enhanced UI */
.scheduled-item {
  padding: 1rem;
  margin-bottom: 0.75rem;
  background: linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%);
  border-radius: 12px;
  border: 1px solid rgba(255,255,255,0.1);
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;
}
.scheduled-item::before {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 4px;
  background: var(--gray-600);
}
.scheduled-item:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 25px rgba(0,0,0,0.3);
}
.scheduled-item.active::before {
  background: linear-gradient(180deg, var(--success) 0%, #059669 100%);
}
.scheduled-item.active {
  border-color: rgba(16, 185, 129, 0.3);
}
.scheduled-item.paused::before {
  background: linear-gradient(180deg, var(--warning) 0%, #d97706 100%);
}
.scheduled-item.paused {
  border-color: rgba(245, 158, 11, 0.3);
  opacity: 0.85;
}
.scheduled-item.running::before {
  background: linear-gradient(180deg, var(--secondary) 0%, #0284c7 100%);
  animation: pulse 1.5s ease-in-out infinite;
}
.scheduled-item.running {
  border-color: rgba(14, 165, 233, 0.3);
}
.scheduled-item.completed::before {
  background: var(--gray-500);
}
.scheduled-item.completed {
  opacity: 0.6;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}
.scheduled-item-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 0.75rem;
  gap: 0.5rem;
}
.scheduled-item-name {
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--light);
  flex: 1;
  line-height: 1.3;
}
.scheduled-item-status {
  font-size: 0.7rem;
  padding: 4px 10px;
  border-radius: 20px;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  white-space: nowrap;
}
.scheduled-item-status.active { 
  background: rgba(16, 185, 129, 0.2); 
  color: var(--success);
  border: 1px solid rgba(16, 185, 129, 0.3);
}
.scheduled-item-status.paused { 
  background: rgba(245, 158, 11, 0.2); 
  color: var(--warning);
  border: 1px solid rgba(245, 158, 11, 0.3);
}
.scheduled-item-status.completed { 
  background: rgba(156, 163, 175, 0.2); 
  color: var(--gray-400);
  border: 1px solid rgba(156, 163, 175, 0.3);
}
.scheduled-item-status.running { 
  background: rgba(14, 165, 233, 0.2); 
  color: var(--secondary);
  border: 1px solid rgba(14, 165, 233, 0.3);
  animation: pulse 1.5s ease-in-out infinite;
}
.scheduled-item-time {
  font-size: 0.8rem;
  color: var(--gray-300);
  margin-bottom: 0.5rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.scheduled-item-meta {
  display: flex;
  gap: 1rem;
  font-size: 0.75rem;
  color: var(--gray-400);
  margin-bottom: 0.5rem;
  flex-wrap: wrap;
}
.scheduled-item-meta .status-badge {
  padding: 2px 6px;
  border-radius: 4px;
  font-weight: 500;
}
.scheduled-item-meta .status-badge.completed { background: rgba(16, 185, 129, 0.2); color: var(--success); }
.scheduled-item-meta .status-badge.failed { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
.scheduled-item-meta .status-badge.pending { background: rgba(156, 163, 175, 0.2); color: var(--gray-400); }
.scheduled-item-prompt {
  font-size: 0.8rem;
  color: var(--gray-400);
  background: rgba(0,0,0,0.2);
  padding: 0.5rem;
  border-radius: 6px;
  margin-bottom: 0.5rem;
  line-height: 1.4;
  max-height: 60px;
  overflow: hidden;
}
.scheduled-result-preview {
  margin-top: 0.5rem;
  padding: 0.5rem;
  background: rgba(0,0,0,0.2);
  border-radius: 6px;
  font-size: 0.7rem;
  color: var(--gray-300);
  max-height: 50px;
  overflow: hidden;
  cursor: pointer;
  font-family: 'JetBrains Mono', monospace;
}
.scheduled-result-preview:hover {
  background: rgba(0,0,0,0.3);
}
.scheduled-item-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.5rem;
  flex-wrap: wrap;
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
@media (max-width: 1200px) {
  :root {
    --sidebar-width: 380px;
    --sidebar-min-width: 280px;
  }
}
@media (max-width: 992px) {
  :root {
    --sidebar-width: 340px;
    --sidebar-min-width: 260px;
  }
  .sidebar-tabs {
    flex-wrap: wrap;
  }
  .sidebar-tab {
    min-width: 50px;
    padding: 0.5rem 0.4rem;
  }
  .sidebar-tab .tab-label {
    font-size: 0.6rem;
  }
}
@media (max-width: 768px) {
  header { padding: 0.75rem 1rem; }
  .header-actions { width: 100%; justify-content: center; flex-wrap: wrap; }
  .header-actions .btn { padding: 0.4rem 0.6rem; font-size: 0.75rem; }
  #sidebar.expanded { 
    width: 100% !important; 
    min-width: 100% !important; 
    position: absolute; 
    z-index: 50; 
    height: 100%; 
  }
  main { padding: 1rem; }
  .logo-icon { width: 40px; height: 40px; }
  h1 { font-size: 1.2rem; }
}
</style>
</head>
<body>
<header>
  <div class="logo-section">
    <div class="logo-icon">
      <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        <path d="M9 12l2 2 4-4" stroke-linecap="round" stroke-linejoin="round"></path>
      </svg>
    </div>
    <div>
      <h1>OWASP SmolAgent</h1>
      <div class="header-subtitle">AI-Powered Security Testing Platform</div>
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
      <span class="toggle-label"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg> Report</span>
    </div>
    <button class="btn btn-secondary" id="export-txt-btn"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg> Export</button>
    <button class="btn btn-secondary" id="clear-btn"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg> Clear</button>
    <button class="btn btn-secondary" id="theme-toggle-btn" title="Toggle Light/Dark Theme"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg></button>
  </div>
</header>
<div class="main-wrapper">
  <!-- Expandable Sidebar with Tabs -->
  <div id="sidebar">
    <div class="sidebar-resize-handle" id="sidebar-resize"></div>
    <button class="sidebar-toggle" id="sidebar-toggle" title="Toggle Sidebar">
      <svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="9" y1="3" x2="9" y2="21"></line></svg>
    </button>
    
    <!-- Sidebar Tabs -->
    <div class="sidebar-tabs">
      <button class="sidebar-tab" data-tab="chats">
        <svg viewBox="0 0 24 24"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
        <span class="tab-label">Chats</span>
      </button>
      <button class="sidebar-tab active" data-tab="activity">
        <svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
        <span class="tab-label">Activity</span>
      </button>
      <button class="sidebar-tab" data-tab="tasks">
        <svg viewBox="0 0 24 24"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path><rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect></svg>
        <span class="tab-label">Tasks</span>
      </button>
      <button class="sidebar-tab" data-tab="scheduled">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
        <span class="tab-label">Schedule</span>
      </button>
      <button class="sidebar-tab" data-tab="settings">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
        <span class="tab-label">Settings</span>
      </button>
    </div>
    
    <!-- Chats Tab Content -->
    <div class="tab-content" id="tab-chats">
      <div class="sidebar-header">
        <span class="header-title"><svg viewBox="0 0 24 24"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg> Conversations</span>
        <button class="btn-new-chat" onclick="createNewChat()" title="New Chat"><svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg></button>
      </div>
      <div id="chats-list">
        <div class="chat-loading">Loading chats...</div>
      </div>
    </div>
    
    <!-- Activity Tab Content -->
    <div class="tab-content active" id="tab-activity">
      <div class="sidebar-header"><span class="header-title"><svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg> Activity Monitor</span></div>
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
      <div class="sidebar-header"><span class="header-title"><svg viewBox="0 0 24 24"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path><rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect></svg> Tasks & Chains</span></div>
      <div class="tasks-chains-wrapper">
        <div class="collapsible-section">
          <button class="section-toggle" onclick="toggleSection(this)" data-expanded="true">
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><polyline points="6 9 12 15 18 9"></polyline></svg>
            <span>Background Tasks</span>
            <span class="section-count" id="tasks-count">0</span>
          </button>
          <div class="section-content" id="tasks-list">
            <div class="no-tasks">No active tasks</div>
          </div>
        </div>
        
        <div class="collapsible-section">
          <button class="section-toggle" onclick="toggleSection(this)" data-expanded="true">
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><polyline points="6 9 12 15 18 9"></polyline></svg>
            <span>Task Chains</span>
            <span class="section-count" id="chains-count">0</span>
          </button>
          <div class="section-content">
            <button class="create-chain-btn" onclick="openChainBuilder()">
              <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
              Create Task Chain
            </button>
            <div id="chains-list" style="margin-top: 0.75rem;">
              <!-- Chains will be rendered here -->
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Chain Builder Modal -->
    <div class="chain-builder-modal" id="chain-builder-modal">
      <div class="chain-builder-content">
        <div class="chain-builder-header">
          <span class="chain-builder-title">🔗 Create Task Chain</span>
          <button class="task-modal-close" onclick="closeChainBuilder()">&times;</button>
        </div>
        <div class="chain-builder-body">
          <div class="chain-input-group">
            <label>Chain Name</label>
            <input type="text" id="chain-name-input" placeholder="e.g., Full OSINT + Pentest Workflow">
          </div>
          <div class="chain-input-group">
            <label>Description (optional)</label>
            <textarea id="chain-desc-input" placeholder="Describe what this chain does..."></textarea>
          </div>
          <div class="chain-steps-list" id="chain-steps-list">
            <!-- Steps will be added here -->
          </div>
          <button class="add-step-btn" onclick="addChainStep()">
            ➕ Add Step
          </button>
        </div>
        <div class="chain-builder-footer">
          <button class="chain-builder-btn chain-builder-btn-cancel" onclick="closeChainBuilder()">Cancel</button>
          <button class="chain-builder-btn chain-builder-btn-create" onclick="createChain()">Create Chain</button>
        </div>
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
        
        <div class="settings-section">
          <div class="settings-section-title">📱 Telegram Integration</div>
          <div class="api-key-item">
            <span class="api-key-label">Bot Token</span>
            <input type="password" class="api-key-input" id="api-key-telegram_bot" placeholder="Enter Telegram bot token...">
            <button class="api-key-btn api-key-btn-save" onclick="saveApiKey('telegram_bot')">💾</button>
            <button class="api-key-btn api-key-btn-delete" onclick="deleteApiKey('telegram_bot')">🗑️</button>
          </div>
          <div class="api-key-item">
            <span class="api-key-label">Chat ID</span>
            <input type="text" class="api-key-input" id="api-key-telegram_chat" placeholder="Enter chat/group ID...">
            <button class="api-key-btn api-key-btn-save" onclick="saveApiKey('telegram_chat')">💾</button>
            <button class="api-key-btn api-key-btn-delete" onclick="deleteApiKey('telegram_chat')">🗑️</button>
          </div>
          <p style="font-size: 0.75rem; color: var(--gray-500); margin-top: 8px;">
            Create a bot via @BotFather on Telegram. Use the agent's telegram_connect tool to link.
          </p>
          <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(255,255,255,0.1);">
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
              <span style="font-size: 0.85rem; font-weight: 500;">🎧 Group Monitoring</span>
              <label class="checkbox-wrapper" style="margin: 0;">
                <input type="checkbox" id="telegram-monitoring-toggle">
                <span class="checkmark"></span>
                <span class="checkbox-label">Enable</span>
              </label>
            </div>
            <p style="font-size: 0.75rem; color: var(--gray-500); line-height: 1.4;">
              When enabled, the agent monitors Telegram group chats for commands.<br>
              Mention the bot to execute commands: <code style="background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px;">@bot_name scan example.com</code>
            </p>
            <div id="telegram-monitoring-status" style="margin-top: 8px; font-size: 0.8rem; color: var(--gray-400);">Status: Not monitoring</div>
          </div>
        </div>
        
        <div class="settings-section">
          <div class="settings-section-title">📋 Custom Context / Instructions</div>
          <textarea id="custom-context-input" placeholder="Add custom instructions for the agent (e.g., preferred reporting format, specific rules)..." 
            style="width: 100%; height: 120px; background: var(--dark); border: 1px solid rgba(255,255,255,0.2); border-radius: 8px; padding: 10px; color: var(--light); font-family: inherit; font-size: 0.85rem; resize: vertical;"></textarea>
          <div style="display: flex; gap: 10px; margin-top: 10px;">
            <button class="api-key-btn" style="padding: 8px 16px; font-size: 0.85rem;" onclick="saveCustomContext()">💾 Save Context</button>
            <button class="api-key-btn" style="padding: 8px 16px; font-size: 0.85rem;" onclick="clearCustomContext()">🗑️ Clear</button>
          </div>
          <p style="font-size: 0.75rem; color: var(--gray-500); margin-top: 8px;">
            These instructions will be included with every request to the agent.
          </p>
        </div>
      </div>
    </div>
    
    <!-- Scheduled Tasks Tab Content -->
    <div class="tab-content" id="tab-scheduled">
      <div class="sidebar-header">
        <span class="header-icon">⏰</span> Scheduled Tasks
        <button class="btn-new-chat" onclick="showScheduleModal()" title="New Scheduled Task">➕</button>
      </div>
      <div id="scheduled-list">
        <div class="no-tasks">No scheduled tasks</div>
      </div>
    </div>
  </div>
  
  <!-- Schedule Task Modal -->
  <div class="task-modal" id="schedule-modal">
    <div class="task-modal-content" style="max-width: 480px;">
      <div class="task-modal-header">
        <span class="task-modal-title">⏰ Schedule New Task</span>
        <button class="task-modal-close" onclick="closeScheduleModal()">&times;</button>
      </div>
      <div class="task-modal-body" style="padding: 1rem;">
        <div class="schedule-form">
          <div class="form-group">
            <label>Task Name</label>
            <input type="text" id="schedule-name" placeholder="e.g., Daily security scan">
          </div>
          <div class="form-group">
            <label>Task Prompt</label>
            <textarea id="schedule-prompt" placeholder="e.g., Run a quick nmap scan on target.com..." rows="3"></textarea>
          </div>
          <div class="form-row">
            <div class="form-group" style="flex: 1;">
              <label>📅 Schedule Time</label>
              <input type="datetime-local" id="schedule-time">
            </div>
          </div>
          <div class="form-group" style="margin-bottom: 8px;">
            <label class="checkbox-wrapper" style="margin: 0;">
              <input type="checkbox" id="schedule-recurring">
              <span class="checkmark"></span>
              <span class="checkbox-label">🔄 Recurring Task</span>
            </label>
          </div>
          <div id="recurring-options" class="form-group" style="display: none;">
            <label>Repeat Every (minutes)</label>
            <input type="number" id="schedule-interval" value="60" min="5">
          </div>
          <button class="btn btn-primary" style="width: 100%; margin-top: 8px;" onclick="createScheduledTask()">📅 Schedule Task</button>
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
const sidebarResize = document.getElementById('sidebar-resize');
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
};

// Sidebar resize functionality
let isResizing = false;
let startX = 0;
let startWidth = 0;

sidebarResize.addEventListener('mousedown', (e) => {
  if (!sidebar.classList.contains('expanded')) return;
  isResizing = true;
  startX = e.clientX;
  startWidth = parseInt(getComputedStyle(sidebar).width, 10);
  sidebarResize.classList.add('dragging');
  document.body.style.cursor = 'ew-resize';
  document.body.style.userSelect = 'none';
});

document.addEventListener('mousemove', (e) => {
  if (!isResizing) return;
  const newWidth = startWidth + (e.clientX - startX);
  const minWidth = parseInt(getComputedStyle(document.documentElement).getPropertyValue('--sidebar-min-width'), 10) || 320;
  const maxWidth = parseInt(getComputedStyle(document.documentElement).getPropertyValue('--sidebar-max-width'), 10) || 600;
  
  if (newWidth >= minWidth && newWidth <= maxWidth) {
    document.documentElement.style.setProperty('--sidebar-width', newWidth + 'px');
  }
});

document.addEventListener('mouseup', () => {
  if (isResizing) {
    isResizing = false;
    sidebarResize.classList.remove('dragging');
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  }
});

// Section toggle for collapsible sections
function toggleSection(btn) {
  const isExpanded = btn.getAttribute('data-expanded') === 'true';
  const content = btn.nextElementSibling;
  
  if (isExpanded) {
    content.classList.add('collapsed');
    btn.setAttribute('data-expanded', 'false');
  } else {
    content.classList.remove('collapsed');
    btn.setAttribute('data-expanded', 'true');
  }
}

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
  const tasksCount = document.getElementById('tasks-count');
  const tasks = Object.values(taskStore).filter(t => !t.chain_id); // Only show non-chain tasks
  
  // Update count
  if (tasksCount) tasksCount.textContent = tasks.length;
  
  if (tasks.length === 0) {
    tasksList.innerHTML = '<div class="no-tasks">No active tasks</div>';
    return;
  }
  
  // Sort by created_at descending
  tasks.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  
  tasksList.innerHTML = tasks.map(task => {
    const isActive = ['pending', 'running', 'paused'].includes(task.status);
    const isFinished = ['completed', 'cancelled', 'failed'].includes(task.status);
    const createdAt = new Date(task.created_at).toLocaleTimeString();
    const truncatedPrompt = task.prompt.length > 50 ? task.prompt.substring(0, 50) + '...' : task.prompt;
    
    return `
      <div class="task-item ${task.status}" style="position: relative;">
        ${isFinished ? `<button class="task-delete-btn" onclick="deleteTask('${task.id}')" title="Remove task">×</button>` : ''}
        <div class="task-header">
          <span class="task-title">${escapeHtml(truncatedPrompt)}</span>
          <span class="task-status ${task.status}">${task.status}</span>
        </div>
        <div class="task-meta">
          Created: ${createdAt} | Steps: ${task.step_count} | Tools: ${task.tool_count}
        </div>
        ${isActive ? `
        <div class="task-actions">
          <button class="task-btn task-btn-pause" onclick="pauseTask('${task.id}')">
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

async function deleteTask(taskId) {
  try {
    await fetch(`/api/tasks/${taskId}?remove=true`, { method: 'DELETE' });
    delete taskStore[taskId];
    renderTasks();
  } catch (err) {
    addMessage('system', `⚠️ Failed to delete task: ${err.message}`);
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
    
    // Handle SCREENSHOT_IMAGE_DATA format first
    const screenshotRegex = /SCREENSHOT_IMAGE_DATA:([A-Za-z0-9+\\/=]+):END_IMAGE_DATA/g;
    resultHtml = resultHtml.replace(screenshotRegex, (match, base64Data) => {
      return `<div style="margin: 15px 0;">
        <div style="font-weight: bold; margin-bottom: 8px;">📸 Screenshot:</div>
        <img src="data:image/png;base64,${base64Data}" 
             onclick="showImageModal(this.src)" 
             style="max-width: 100%; max-height: 500px; border-radius: 8px; cursor: pointer; border: 1px solid rgba(255,255,255,0.2);">
        <div style="font-size: 0.75rem; color: var(--gray-400); margin-top: 5px;">Click to view full size</div>
      </div>`;
    });
    
    // Check for regular base64 images and render them
    const base64Pattern = /data:image\\/(png|jpg|jpeg|gif|webp);base64,([A-Za-z0-9+\\/=]+)/g;
    resultHtml = resultHtml.replace(base64Pattern, '<img src="$&" style="max-width: 100%; margin: 10px 0; border-radius: 8px; cursor: pointer;" onclick="showImageModal(this.src)">');
    
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

// ======================================
// Task Chain Management Functions
// ======================================

let chainStore = {};
let chainSteps = [];

async function loadChains() {
  try {
    const response = await fetch('/api/chains');
    const chains = await response.json();
    chainStore = {};
    chains.forEach(c => chainStore[c.id] = c);
    renderChains();
  } catch (err) {
    console.error('Failed to load chains:', err);
  }
}

function renderChains() {
  const chainsList = document.getElementById('chains-list');
  const chainsCount = document.getElementById('chains-count');
  const chains = Object.values(chainStore);
  
  // Update count
  if (chainsCount) chainsCount.textContent = chains.length;
  
  if (chains.length === 0) {
    chainsList.innerHTML = '<div class="no-tasks" style="text-align: center; padding: 1rem; color: var(--gray-500);">No chains created</div>';
    return;
  }
  
  // Sort by created_at descending
  chains.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  
  chainsList.innerHTML = chains.map(chain => {
    const statusClass = chain.status || 'pending';
    const taskCount = chain.tasks?.length || 0;
    const currentIndex = chain.current_task_index || 0;
    
    // Create progress steps
    const stepsHtml = (chain.task_details || []).map((task, i) => {
      const stepStatus = task.status || 'pending';
      const stepName = task.name || `Step ${i + 1}`;
      return `
        <div class="chain-step ${stepStatus}" title="${stepName}">
          ${i + 1}
          <div class="chain-step-tooltip">${stepName}: ${stepStatus}</div>
        </div>
      `;
    }).join('');
    
    return `
      <div class="chain-item ${statusClass}">
        <div class="chain-header">
          <span class="chain-name">🔗 ${escapeHtml(chain.name)}</span>
          <span class="chain-status ${statusClass}">${statusClass}</span>
        </div>
        ${chain.description ? `<div style="font-size: 0.75rem; color: var(--gray-400); margin-bottom: 0.5rem;">${escapeHtml(chain.description)}</div>` : ''}
        <div style="font-size: 0.75rem; color: var(--gray-400);">
          ${taskCount} tasks | Progress: ${currentIndex}/${taskCount}
        </div>
        <div class="chain-progress">
          ${stepsHtml || '<div style="color: var(--gray-500); font-size: 0.75rem;">No steps</div>'}
        </div>
        <div class="chain-actions">
          ${statusClass === 'pending' || statusClass === 'cancelled' || statusClass === 'failed' ? `
            <button class="chain-btn chain-btn-start" onclick="startChain('${chain.id}')">▶️ Start</button>
          ` : ''}
          ${statusClass === 'running' ? `
            <button class="chain-btn chain-btn-stop" onclick="stopChain('${chain.id}')">⏹️ Stop</button>
          ` : ''}
          ${statusClass !== 'running' ? `
            <button class="chain-btn chain-btn-delete" onclick="deleteChain('${chain.id}')">🗑️ Delete</button>
          ` : ''}
        </div>
      </div>
    `;
  }).join('');
}

function openChainBuilder() {
  chainSteps = [];
  document.getElementById('chain-name-input').value = '';
  document.getElementById('chain-desc-input').value = '';
  document.getElementById('chain-steps-list').innerHTML = '';
  addChainStep(); // Start with one step
  document.getElementById('chain-builder-modal').classList.add('active');
}

function closeChainBuilder() {
  document.getElementById('chain-builder-modal').classList.remove('active');
}

function addChainStep() {
  const stepNum = chainSteps.length + 1;
  const stepId = 'step-' + Date.now();
  
  chainSteps.push({ id: stepId, name: '', prompt: '', usePrevious: true });
  
  const stepHtml = `
    <div class="chain-step-item" id="${stepId}">
      <div class="chain-step-header">
        <div class="chain-step-number">${stepNum}</div>
        <button class="chain-step-remove" onclick="removeChainStep('${stepId}')">&times;</button>
      </div>
      <input type="text" class="chain-step-input" placeholder="Step name (e.g., OSINT Discovery)" 
             onchange="updateChainStep('${stepId}', 'name', this.value)">
      <textarea class="chain-step-textarea" placeholder="Prompt for this step (e.g., Perform OSINT on target.com and enumerate subdomains)"
                onchange="updateChainStep('${stepId}', 'prompt', this.value)"></textarea>
      ${stepNum > 1 ? `
        <div class="chain-step-options">
          <label style="display: flex; align-items: center; gap: 4px; cursor: pointer;">
            <input type="checkbox" checked onchange="updateChainStep('${stepId}', 'usePrevious', this.checked)">
            Use results from previous step
          </label>
        </div>
      ` : ''}
    </div>
  `;
  
  document.getElementById('chain-steps-list').insertAdjacentHTML('beforeend', stepHtml);
}

function removeChainStep(stepId) {
  if (chainSteps.length <= 1) {
    addMessage('system', '⚠️ Chain must have at least one step');
    return;
  }
  
  const index = chainSteps.findIndex(s => s.id === stepId);
  if (index > -1) {
    chainSteps.splice(index, 1);
    document.getElementById(stepId).remove();
    
    // Renumber steps
    document.querySelectorAll('.chain-step-item').forEach((el, i) => {
      el.querySelector('.chain-step-number').textContent = i + 1;
    });
  }
}

function updateChainStep(stepId, field, value) {
  const step = chainSteps.find(s => s.id === stepId);
  if (step) {
    step[field] = value;
  }
}

async function createChain() {
  const name = document.getElementById('chain-name-input').value.trim();
  const description = document.getElementById('chain-desc-input').value.trim();
  
  if (!name) {
    addMessage('system', '⚠️ Please enter a chain name');
    return;
  }
  
  // Collect step data from DOM
  const steps = [];
  document.querySelectorAll('.chain-step-item').forEach((el, i) => {
    const inputs = el.querySelectorAll('input, textarea');
    const stepName = inputs[0]?.value?.trim() || `Step ${i + 1}`;
    const prompt = inputs[1]?.value?.trim();
    const usePrevious = i > 0 ? (inputs[2]?.checked ?? true) : false;
    
    if (prompt) {
      steps.push({
        name: stepName,
        prompt: prompt,
        use_previous_result: usePrevious
      });
    }
  });
  
  if (steps.length === 0) {
    addMessage('system', '⚠️ Please add at least one step with a prompt');
    return;
  }
  
  try {
    const response = await fetch('/api/chains', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: name,
        description: description,
        tasks: steps
      })
    });
    
    const result = await response.json();
    
    if (result.success) {
      addMessage('system', `✅ Chain "${name}" created with ${result.task_count} tasks`);
      closeChainBuilder();
      loadChains();
    } else {
      addMessage('system', `⚠️ Failed to create chain: ${result.error || 'Unknown error'}`);
    }
  } catch (err) {
    addMessage('system', `⚠️ Failed to create chain: ${err.message}`);
  }
}

async function startChain(chainId) {
  try {
    const response = await fetch(`/api/chains/${chainId}/start`, {
      method: 'POST'
    });
    
    const result = await response.json();
    
    if (result.success) {
      addMessage('system', `✅ Chain started! First task is running.`);
      loadChains();
    } else {
      addMessage('system', `⚠️ Failed to start chain: ${result.error || 'Unknown error'}`);
    }
  } catch (err) {
    addMessage('system', `⚠️ Failed to start chain: ${err.message}`);
  }
}

async function stopChain(chainId) {
  if (!confirm('Are you sure you want to stop this chain? All pending tasks will be cancelled.')) return;
  
  try {
    const response = await fetch(`/api/chains/${chainId}/stop`, {
      method: 'POST'
    });
    
    const result = await response.json();
    
    if (result.success) {
      addMessage('system', `✅ Chain stopped. ${result.cancelled_tasks?.length || 0} tasks cancelled.`);
      loadChains();
    } else {
      addMessage('system', `⚠️ Failed to stop chain: ${result.error || 'Unknown error'}`);
    }
  } catch (err) {
    addMessage('system', `⚠️ Failed to stop chain: ${err.message}`);
  }
}

async function deleteChain(chainId) {
  if (!confirm('Are you sure you want to delete this chain? All tasks will be removed.')) return;
  
  try {
    const response = await fetch(`/api/chains/${chainId}`, {
      method: 'DELETE'
    });
    
    const result = await response.json();
    
    if (result.success) {
      addMessage('system', `✅ Chain deleted. ${result.deleted_tasks?.length || 0} tasks removed.`);
      delete chainStore[chainId];
      renderChains();
    } else {
      addMessage('system', `⚠️ Failed to delete chain: ${result.error || 'Unknown error'}`);
    }
  } catch (err) {
    addMessage('system', `⚠️ Failed to delete chain: ${err.message}`);
  }
}

// Refresh chains along with tasks
const originalRefreshTasks = refreshTasks;
refreshTasks = async function() {
  await originalRefreshTasks();
  await loadChains();
};

// Close modal on escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeTaskModal();
    closeChainBuilder();
    document.getElementById('image-modal').classList.remove('active');
  }
});

// Close modal on clicking outside
document.getElementById('task-modal').addEventListener('click', (e) => {
  if (e.target.id === 'task-modal') closeTaskModal();
});

document.getElementById('chain-builder-modal').addEventListener('click', (e) => {
  if (e.target.id === 'chain-builder-modal') closeChainBuilder();
});

// API Key management functions
const API_KEY_MAP = {
  'shodan': 'SHODAN_API_KEY',
  'virustotal': 'VIRUSTOTAL_API_KEY',
  'hunter': 'HUNTER_API_KEY',
  'securitytrails': 'SECURITYTRAILS_API_KEY',
  'hibp': 'HIBP_API_KEY',
  'censys': 'CENSYS_API_KEY',
  'alienvault': 'ALIENVAULT_API_KEY',
  'telegram_bot': 'TELEGRAM_BOT_TOKEN',
  'telegram_chat': 'TELEGRAM_CHAT_ID'
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
  
  // Add to chat history
  const msgData = { type, content, timestamp: new Date().toISOString() };
  chatHistory.push(msgData);
  
  // Auto-save message to backend (unless skipSave is set)
  if (!meta.skipSave && type !== 'progress') {
    saveMessageToBackend(msgData);
  }
}

// Debounced save to prevent too many API calls
let saveMessageTimeout = null;
let pendingMessages = [];

async function saveMessageToBackend(msgData) {
  pendingMessages.push(msgData);
  
  // Debounce: wait 500ms before saving
  if (saveMessageTimeout) clearTimeout(saveMessageTimeout);
  saveMessageTimeout = setTimeout(async () => {
    const messagesToSave = [...pendingMessages];
    pendingMessages = [];
    
    for (const msg of messagesToSave) {
      try {
        await fetch(`/api/chats/${currentChatId}/messages`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: msg.type,
            content: msg.content,
            timestamp: msg.timestamp
          })
        });
      } catch (err) {
        console.error('Failed to save message:', err);
      }
    }
  }, 500);
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
  
  // Check if message belongs to different chat - store for later
  const msgChatId = data.chat_id;
  if (msgChatId && msgChatId !== currentChatId) {
    // Queue message for the correct chat (will be loaded when chat is switched)
    // For now, skip showing in current chat
    console.log(`Message for chat ${msgChatId} received while in chat ${currentChatId}`);
    // Still process activity and stats updates
    if (data.type === 'activity') {
      if (typeof data.tool_count === 'number') {
        toolCount = data.tool_count;
        document.getElementById('stat-tools').textContent = toolCount;
      }
      if (typeof data.step_count === 'number') {
        stepCount = data.step_count;
        document.getElementById('stat-steps').textContent = stepCount;
      }
    }
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
    chat_id: currentChatId,
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

// ============== THEME TOGGLE ==============
const themeToggleBtn = document.getElementById('theme-toggle-btn');

// Load saved theme
const savedTheme = localStorage.getItem('owasp-theme');
if (savedTheme === 'light') {
  document.body.classList.add('light-theme');
  themeToggleBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>';
}

const moonIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>';
const sunIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>';

themeToggleBtn.onclick = () => {
  document.body.classList.toggle('light-theme');
  const isLight = document.body.classList.contains('light-theme');
  localStorage.setItem('owasp-theme', isLight ? 'light' : 'dark');
  themeToggleBtn.innerHTML = isLight ? sunIcon : moonIcon;
};

// ============== CHAT MANAGEMENT ==============
let currentChatId = 'default';
let chatsStore = {};

async function loadChats() {
  try {
    const response = await fetch('/api/chats');
    const chats = await response.json();
    chatsStore = {};
    chats.forEach(c => chatsStore[c.id] = c);
    renderChats();
  } catch (err) {
    console.error('Failed to load chats:', err);
  }
}

function renderChats() {
  const chatsList = document.getElementById('chats-list');
  const chats = Object.values(chatsStore);
  
  if (chats.length === 0) {
    chatsList.innerHTML = '<div class="no-tasks">No chats yet. Create one!</div>';
    return;
  }
  
  chatsList.innerHTML = chats.map(chat => `
    <div class="chat-item ${chat.id === currentChatId ? 'active' : ''}" onclick="switchChat('${chat.id}')">
      <div class="chat-item-info">
        <div class="chat-item-name">${escapeHtml(chat.name)}</div>
        <div class="chat-item-meta">${chat.message_count || 0} messages</div>
      </div>
      <div class="chat-item-actions">
        <button class="chat-item-btn" onclick="event.stopPropagation(); renameChat('${chat.id}')" title="Rename">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
        </button>
        ${chat.id !== 'default' ? `<button class="chat-item-btn" onclick="event.stopPropagation(); deleteChat('${chat.id}')" title="Delete">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
        </button>` : ''}
      </div>
    </div>
  `).join('');
}

async function createNewChat() {
  const name = prompt('Enter chat name:', 'New Chat');
  if (!name) return;
  
  try {
    const response = await fetch('/api/chats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name })
    });
    const result = await response.json();
    if (result.success) {
      await loadChats();
      switchChat(result.chat_id);
    }
  } catch (err) {
    addMessage('system', `⚠️ Failed to create chat: ${err.message}`);
  }
}

async function switchChat(chatId) {
  // Flush any pending message saves
  if (saveMessageTimeout) {
    clearTimeout(saveMessageTimeout);
    saveMessageTimeout = null;
  }
  
  // Save any remaining pending messages immediately
  if (pendingMessages.length > 0) {
    for (const msg of pendingMessages) {
      try {
        await fetch(`/api/chats/${currentChatId}/messages`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: msg.type,
            content: msg.content,
            timestamp: msg.timestamp
          })
        });
      } catch (err) {
        console.error('Failed to save pending message:', err);
      }
    }
    pendingMessages = [];
  }
  
  currentChatId = chatId;
  sessionId = chatId;  // Update session ID to match chat
  
  // Clear current messages
  messagesDiv.innerHTML = '';
  chatHistory = [];
  
  // Load messages for this chat
  try {
    const response = await fetch(`/api/chats/${chatId}`);
    const chat = await response.json();
    
    if (chat.messages && chat.messages.length > 0) {
      chat.messages.forEach(msg => {
        addMessage(msg.type, msg.content, { skipSave: true });
      });
      chatHistory = [...chat.messages];
    }
  } catch (err) {
    console.error('Failed to load chat:', err);
  }
  
  renderChats();
  
  if (chatHistory.length === 0) {
    addMessage('system', `💬 Switched to: ${chatsStore[chatId]?.name || 'Chat'}`, { skipSave: true });
  }
}

async function saveChatMessages() {
  // This is now handled by auto-save in addMessage
  // Keeping for backward compatibility with page unload
  if (pendingMessages.length > 0) {
    for (const msg of pendingMessages) {
      try {
        await fetch(`/api/chats/${currentChatId}/messages`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: msg.type,
            content: msg.content,
            timestamp: msg.timestamp
          })
        });
      } catch (err) {
        console.error('Failed to save message:', err);
      }
    }
    pendingMessages = [];
  }
}

async function renameChat(chatId) {
  const chat = chatsStore[chatId];
  const newName = prompt('Enter new name:', chat?.name || 'Chat');
  if (!newName || newName === chat?.name) return;
  
  try {
    await fetch(`/api/chats/${chatId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: newName })
    });
    await loadChats();
  } catch (err) {
    addMessage('system', `⚠️ Failed to rename chat: ${err.message}`);
  }
}

async function deleteChat(chatId) {
  if (!confirm('Delete this chat and all its messages?')) return;
  
  try {
    await fetch(`/api/chats/${chatId}`, { method: 'DELETE' });
    if (currentChatId === chatId) {
      currentChatId = 'default';
      sessionId = 'default';
    }
    await loadChats();
    if (currentChatId === 'default') {
      switchChat('default');
    }
  } catch (err) {
    addMessage('system', `⚠️ Failed to delete chat: ${err.message}`);
  }
}

// Auto-save chat when page unloads
window.addEventListener('beforeunload', () => {
  // Use sendBeacon for reliable save on page close
  if (chatHistory.length > 0) {
    navigator.sendBeacon('/api/chats/' + currentChatId + '/save', JSON.stringify({
      messages: chatHistory
    }));
  }
});

// ============== SCHEDULED TASKS ==============
let scheduledTasksStore = {};
let scheduledRefreshInterval = null;

async function loadScheduledTasks() {
  try {
    const response = await fetch('/api/scheduled');
    const tasks = await response.json();
    scheduledTasksStore = {};
    tasks.forEach(t => scheduledTasksStore[t.id] = t);
    renderScheduledTasks();
  } catch (err) {
    console.error('Failed to load scheduled tasks:', err);
  }
}

function renderScheduledTasks() {
  const list = document.getElementById('scheduled-list');
  const tasks = Object.values(scheduledTasksStore);
  
  if (tasks.length === 0) {
    list.innerHTML = '<div class="no-tasks">No scheduled tasks. Click + to create one.</div>';
    return;
  }
  
  list.innerHTML = tasks.map(task => {
    const scheduleDate = new Date(task.schedule_time);
    const now = new Date();
    const isRecurring = task.recurring;
    const isPast = scheduleDate < now && task.status !== 'completed';
    const isUpcoming = scheduleDate > now && (scheduleDate - now) < 3600000; // within 1 hour
    
    // Determine execution status
    let execStatus = 'Not Run';
    let execStatusIcon = '⏳';
    let execStatusClass = 'pending';
    if (task.last_run) {
      if (task.last_result && task.last_result.startsWith('Error:')) {
        execStatus = 'Failed';
        execStatusIcon = '❌';
        execStatusClass = 'failed';
      } else if (task.last_result) {
        execStatus = 'Success';
        execStatusIcon = '✅';
        execStatusClass = 'completed';
      }
    }
    
    // Format times
    const lastRunTime = task.last_run ? new Date(task.last_run).toLocaleString() : 'Never';
    const nextRunFormatted = task.status === 'completed' ? 'Completed' : scheduleDate.toLocaleString();
    
    // Time remaining
    let timeRemaining = '';
    if (task.status === 'active' && scheduleDate > now) {
      const diff = scheduleDate - now;
      const hours = Math.floor(diff / 3600000);
      const mins = Math.floor((diff % 3600000) / 60000);
      if (hours > 0) {
        timeRemaining = `in ${hours}h ${mins}m`;
      } else if (mins > 0) {
        timeRemaining = `in ${mins}m`;
      } else {
        timeRemaining = 'imminent';
      }
    } else if (task.status === 'active' && scheduleDate <= now) {
      timeRemaining = 'pending execution';
    }
    
    return `
      <div class="scheduled-item ${task.status}">
        <div class="scheduled-item-header">
          <span class="scheduled-item-name">${escapeHtml(task.name || task.prompt.substring(0, 40) + '...')}</span>
          <span class="scheduled-item-status ${task.status}">
            ${task.status === 'running' ? '⚡ Running' : task.status === 'active' ? '✓ Active' : task.status === 'paused' ? '⏸ Paused' : '✓ Done'}
            ${isRecurring ? ' 🔁' : ''}
          </span>
        </div>
        
        <div class="scheduled-item-time">
          📅 ${nextRunFormatted}
          ${timeRemaining ? `<span style="color: ${isUpcoming ? 'var(--warning)' : 'var(--gray-400)'}; font-weight: 500;">(${timeRemaining})</span>` : ''}
          ${isRecurring ? `<span style="color: var(--secondary);">• Repeats every ${task.interval_minutes}m</span>` : ''}
        </div>
        
        <div class="scheduled-item-meta">
          <span><span class="status-badge ${execStatusClass}">${execStatusIcon} ${execStatus}</span></span>
          <span>🕐 Last: ${lastRunTime}</span>
        </div>
        
        <div class="scheduled-item-prompt">${escapeHtml(task.prompt)}</div>
        
        ${task.last_result ? `
        <div class="scheduled-result-preview" onclick="viewScheduledTaskResult('${task.id}')">
          📋 ${escapeHtml(task.last_result.substring(0, 120))}${task.last_result.length > 120 ? '...' : ''}
        </div>
        ` : ''}
        
        <div class="scheduled-item-actions">
          ${task.last_result ? `
          <button class="task-btn task-btn-view" onclick="viewScheduledTaskResult('${task.id}')">
            👁️ Results
          </button>
          ` : ''}
          <button class="task-btn" onclick="editScheduledTask('${task.id}')" ${task.status === 'completed' ? 'disabled' : ''}>
            ✏️ Edit
          </button>
          <button class="task-btn" onclick="toggleScheduledTask('${task.id}')" ${task.status === 'completed' ? 'disabled' : ''}>
            ${task.status === 'paused' ? '▶️ Resume' : '⏸️ Pause'}
          </button>
          <button class="task-btn task-btn-cancel" onclick="deleteScheduledTask('${task.id}')">🗑️</button>
        </div>
      </div>
    `;
  }).join('');
}

let editingScheduledTaskId = null;

function showScheduleModal(taskId = null) {
  const modal = document.getElementById('schedule-modal');
  const title = modal.querySelector('.task-modal-title');
  const submitBtn = modal.querySelector('button.btn-primary');
  
  editingScheduledTaskId = taskId;
  
  if (taskId && scheduledTasksStore[taskId]) {
    // Editing existing task
    const task = scheduledTasksStore[taskId];
    title.textContent = '✏️ Edit Scheduled Task';
    submitBtn.textContent = '💾 Save Changes';
    
    document.getElementById('schedule-name').value = task.name || '';
    document.getElementById('schedule-prompt').value = task.prompt || '';
    
    // Parse ISO date to local datetime-local format
    const scheduleDate = new Date(task.schedule_time);
    const localDateTime = new Date(scheduleDate.getTime() - scheduleDate.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    document.getElementById('schedule-time').value = localDateTime;
    
    document.getElementById('schedule-recurring').checked = task.recurring || false;
    document.getElementById('recurring-options').style.display = task.recurring ? 'block' : 'none';
    document.getElementById('schedule-interval').value = task.interval_minutes || 60;
  } else {
    // New task
    title.textContent = '⏰ Schedule New Task';
    submitBtn.textContent = '📅 Schedule Task';
    
    document.getElementById('schedule-name').value = '';
    document.getElementById('schedule-prompt').value = '';
    document.getElementById('schedule-recurring').checked = false;
    document.getElementById('recurring-options').style.display = 'none';
    document.getElementById('schedule-interval').value = 60;
    
    // Set default time to now + 1 hour
    const now = new Date();
    now.setHours(now.getHours() + 1);
    now.setMinutes(0);
    const dateStr = now.toISOString().slice(0, 16);
    document.getElementById('schedule-time').value = dateStr;
  }
  
  modal.classList.add('active');
}

function editScheduledTask(taskId) {
  showScheduleModal(taskId);
}

function viewScheduledTaskResult(taskId) {
  const task = scheduledTasksStore[taskId];
  if (!task || !task.last_result) {
    alert('No results available for this task');
    return;
  }
  
  const modal = document.getElementById('task-modal');
  const title = document.getElementById('task-modal-title');
  const body = document.getElementById('task-modal-body');
  
  title.textContent = `📊 Scheduled Task Result: ${task.name || task.prompt.substring(0, 30)}`;
  
  let resultHtml = task.last_result;
  
  // Convert SCREENSHOT_IMAGE_DATA to actual images
  resultHtml = resultHtml.replace(/SCREENSHOT_IMAGE_DATA:([A-Za-z0-9+\\/=]+):END_IMAGE_DATA/g, 
    '<img src="data:image/png;base64,$1" style="max-width:100%; margin: 10px 0; border-radius: 8px; border: 1px solid var(--gray-600);" />');
  
  // Escape remaining HTML but preserve our img tags
  const tempDiv = document.createElement('div');
  tempDiv.textContent = resultHtml;
  let safeHtml = tempDiv.innerHTML;
  
  // Restore img tags (they were escaped)
  safeHtml = safeHtml.replace(/&lt;img src="data:image\\/png;base64,([A-Za-z0-9+\\/=]+)" style="([^"]*)" \\/&gt;/g,
    '<img src="data:image/png;base64,$1" style="$2" />');
  
  body.innerHTML = `
    <div style="margin-bottom: 10px; padding: 10px; background: rgba(0,0,0,0.2); border-radius: 8px;">
      <strong>Task:</strong> ${escapeHtml(task.prompt)}<br>
      <strong>Last Run:</strong> ${task.last_run ? new Date(task.last_run).toLocaleString() : 'Never'}<br>
      <strong>Status:</strong> ${task.status}${task.recurring ? ' (Recurring)' : ''}
    </div>
    <div style="white-space: pre-wrap; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">${safeHtml}</div>
  `;
  
  modal.classList.add('active');
}

function closeScheduleModal() {
  document.getElementById('schedule-modal').classList.remove('active');
  editingScheduledTaskId = null;
  document.getElementById('schedule-name').value = '';
  document.getElementById('schedule-prompt').value = '';
  document.getElementById('schedule-recurring').checked = false;
  document.getElementById('recurring-options').style.display = 'none';
}

// Toggle recurring options visibility
document.getElementById('schedule-recurring')?.addEventListener('change', (e) => {
  document.getElementById('recurring-options').style.display = e.target.checked ? 'block' : 'none';
});

async function createScheduledTask() {
  const name = document.getElementById('schedule-name').value.trim();
  const prompt = document.getElementById('schedule-prompt').value.trim();
  const time = document.getElementById('schedule-time').value;
  const recurring = document.getElementById('schedule-recurring').checked;
  const interval = parseInt(document.getElementById('schedule-interval').value) || 60;
  
  if (!prompt) {
    alert('Please enter a task prompt');
    return;
  }
  if (!time) {
    alert('Please select a schedule time');
    return;
  }
  
  try {
    const isEditing = editingScheduledTaskId !== null;
    const url = isEditing ? `/api/scheduled/${editingScheduledTaskId}` : '/api/scheduled';
    const method = isEditing ? 'PUT' : 'POST';
    
    const response = await fetch(url, {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: name || prompt.substring(0, 50),
        prompt,
        schedule_time: new Date(time).toISOString(),
        recurring,
        interval_minutes: recurring ? interval : null
      })
    });
    
    if (response.ok) {
      closeScheduleModal();
      await loadScheduledTasks();
      const action = isEditing ? 'updated' : 'scheduled';
      addMessage('system', `⏰ Task ${action} for ${new Date(time).toLocaleString()}${recurring ? ` (repeating every ${interval}m)` : ''}`);
    }
  } catch (err) {
    addMessage('system', `⚠️ Failed to schedule task: ${err.message}`);
  }
}

async function toggleScheduledTask(taskId) {
  try {
    await fetch(`/api/scheduled/${taskId}`, { method: 'PATCH' });
    await loadScheduledTasks();
  } catch (err) {
    addMessage('system', `⚠️ Failed to update task: ${err.message}`);
  }
}

async function deleteScheduledTask(taskId) {
  if (!confirm('Delete this scheduled task?')) return;
  try {
    await fetch(`/api/scheduled/${taskId}`, { method: 'DELETE' });
    await loadScheduledTasks();
  } catch (err) {
    addMessage('system', `⚠️ Failed to delete task: ${err.message}`);
  }
}

// ============== CUSTOM CONTEXT ==============
async function loadCustomContext() {
  try {
    const response = await fetch('/api/context');
    const data = await response.json();
    const textarea = document.getElementById('custom-context-input');
    if (textarea && data.context) {
      textarea.value = data.context;
    }
  } catch (err) {
    console.error('Failed to load custom context:', err);
  }
}

async function saveCustomContext() {
  const context = document.getElementById('custom-context-input').value;
  try {
    await fetch('/api/context', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ context })
    });
    addMessage('system', '✅ Custom context saved');
  } catch (err) {
    addMessage('system', `⚠️ Failed to save context: ${err.message}`);
  }
}

async function clearCustomContext() {
  if (!confirm('Clear custom context?')) return;
  document.getElementById('custom-context-input').value = '';
  await saveCustomContext();
}

// ============== TELEGRAM GROUP MONITORING ==============
let telegramMonitoringActive = false;

async function toggleTelegramMonitoring() {
  const toggle = document.getElementById('telegram-monitoring-toggle');
  const statusDiv = document.getElementById('telegram-monitoring-status');
  
  if (toggle.checked) {
    // Start monitoring
    try {
      const response = await fetch('/api/telegram/monitor/start', { method: 'POST' });
      const result = await response.json();
      if (result.success) {
        telegramMonitoringActive = true;
        statusDiv.innerHTML = '<span style="color: var(--success);">✅ Monitoring active - listening for @mentions</span>';
        addMessage('system', '📱 Telegram group monitoring started');
      } else {
        toggle.checked = false;
        statusDiv.innerHTML = `<span style="color: var(--danger);">❌ ${result.error}</span>`;
      }
    } catch (err) {
      toggle.checked = false;
      statusDiv.innerHTML = `<span style="color: var(--danger);">❌ Failed to start: ${err.message}</span>`;
    }
  } else {
    // Stop monitoring
    try {
      await fetch('/api/telegram/monitor/stop', { method: 'POST' });
      telegramMonitoringActive = false;
      statusDiv.innerHTML = 'Status: Not monitoring';
      addMessage('system', '📱 Telegram group monitoring stopped');
    } catch (err) {
      statusDiv.innerHTML = `<span style="color: var(--warning);">⚠️ ${err.message}</span>`;
    }
  }
}

// Add event listener for telegram monitoring toggle
document.addEventListener('DOMContentLoaded', () => {
  const telegramToggle = document.getElementById('telegram-monitoring-toggle');
  if (telegramToggle) {
    telegramToggle.addEventListener('change', toggleTelegramMonitoring);
  }
});

// Check telegram monitoring status on settings load
async function checkTelegramMonitoringStatus() {
  try {
    const response = await fetch('/api/telegram/monitor/status');
    const result = await response.json();
    const toggle = document.getElementById('telegram-monitoring-toggle');
    const statusDiv = document.getElementById('telegram-monitoring-status');
    
    if (toggle && statusDiv) {
      toggle.checked = result.active;
      telegramMonitoringActive = result.active;
      if (result.active) {
        statusDiv.innerHTML = `<span style="color: var(--success);">✅ Monitoring active - @${result.bot_username || 'bot'}</span>`;
      } else {
        statusDiv.innerHTML = 'Status: Not monitoring';
      }
    }
  } catch (err) {
    console.error('Failed to check telegram status:', err);
  }
}

// ============== TAB SWITCHING UPDATES ==============
// Update sidebar tab handling
document.querySelectorAll('.sidebar-tab').forEach(tab => {
  tab.onclick = () => {
    document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    tab.classList.add('active');
    const tabId = tab.getAttribute('data-tab');
    document.getElementById('tab-' + tabId).classList.add('active');
    
    // Load data based on tab
    if (tabId === 'tasks') startTaskPolling();
    else stopTaskPolling();
    
    if (tabId === 'settings') {
      loadApiKeys();
      loadCustomContext();
      checkTelegramMonitoringStatus();
    }
    
    if (tabId === 'chats') loadChats();
    
    if (tabId === 'scheduled') {
      loadScheduledTasks();
      // Start auto-refresh every 15 seconds when on scheduled tab
      if (scheduledRefreshInterval) clearInterval(scheduledRefreshInterval);
      scheduledRefreshInterval = setInterval(loadScheduledTasks, 15000);
    } else {
      // Stop auto-refresh when leaving scheduled tab
      if (scheduledRefreshInterval) {
        clearInterval(scheduledRefreshInterval);
        scheduledRefreshInterval = null;
      }
    }
  };
});

// ============== INITIALIZATION ==============
// Load chats on startup
loadChats();
// Load chains on startup
loadChains();

// Update addMessage to support skipSave option
const originalAddMessage = addMessage;
addMessage = function(type, content, meta = {}) {
  originalAddMessage(type, content, meta);
  if (!meta.skipSave && type !== 'progress') {
    // Messages are saved when switching chats or on page unload
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
window.createNewChat = createNewChat;
window.switchChat = switchChat;
window.renameChat = renameChat;
window.deleteChat = deleteChat;
window.showScheduleModal = showScheduleModal;
window.closeScheduleModal = closeScheduleModal;
window.createScheduledTask = createScheduledTask;
window.toggleScheduledTask = toggleScheduledTask;
window.deleteScheduledTask = deleteScheduledTask;
window.editScheduledTask = editScheduledTask;
window.viewScheduledTaskResult = viewScheduledTaskResult;
window.deleteTask = deleteTask;
window.saveCustomContext = saveCustomContext;
window.clearCustomContext = clearCustomContext;
// Chain functions
window.openChainBuilder = openChainBuilder;
window.closeChainBuilder = closeChainBuilder;
window.addChainStep = addChainStep;
window.removeChainStep = removeChainStep;
window.updateChainStep = updateChainStep;
window.createChain = createChain;
window.startChain = startChain;
window.stopChain = stopChain;
window.deleteChain = deleteChain;
window.toggleSection = toggleSection;
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
            chat_id = msg_data.get("chat_id", "default")
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
            
            # Add custom context if defined
            if custom_context and custom_context.strip():
                full_message = f"""[CUSTOM INSTRUCTIONS FROM USER]
{custom_context}
[END CUSTOM INSTRUCTIONS]

{full_message}"""
            
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
                
                # Run task in background thread with captured task_id and separate agent
                def run_background_task(tid, prompt):
                    try:
                        task_store[tid].status = TaskStatus.running
                        task_store[tid].started_at = datetime.now()
                        
                        # Create a dedicated agent for this background task (enables true concurrency)
                        task_agent = build_owasp_agent()
                        
                        step_count = 0
                        tool_count = 0
                        final_result = None
                        all_outputs = []  # Collect all meaningful outputs
                        
                        for event in task_agent.run(prompt, stream=True):
                            # Check for cancellation
                            if task_store[tid].status == TaskStatus.cancelled:
                                return
                            
                            step_count += 1
                            event_type = type(event).__name__
                            
                            # Collect tool calls and their results
                            if hasattr(event, 'tool_calls') and event.tool_calls:
                                for tc in event.tool_calls:
                                    tool_count += 1
                                    if hasattr(tc, 'name'):
                                        all_outputs.append(f"🔧 Tool: {tc.name}")
                            
                            # Collect tool results - preserve full base64 image data
                            if hasattr(event, 'tool_result') and event.tool_result:
                                result_str = str(event.tool_result)
                                # Keep full data for screenshots, truncate others
                                if 'SCREENSHOT_IMAGE_DATA:' in result_str or 'base64,' in result_str:
                                    all_outputs.append(f"📤 Result: {result_str}")
                                else:
                                    all_outputs.append(f"📤 Result: {result_str[:2000]}")
                            
                            # Collect final output
                            if hasattr(event, 'output') and event.output is not None:
                                final_result = event.output
                            
                            # Update task counts
                            task_store[tid].step_count = step_count
                            task_store[tid].tool_count = tool_count
                        
                        # Build comprehensive result - prioritize screenshots
                        result_parts = []
                        screenshot_outputs = [o for o in all_outputs if 'SCREENSHOT_IMAGE_DATA:' in o or 'base64,' in o]
                        
                        if final_result:
                            result_parts.append(str(final_result))
                        
                        # Always include screenshots even if we have final_result
                        for screenshot in screenshot_outputs:
                            if screenshot not in str(final_result) if final_result else True:
                                result_parts.append(screenshot)
                        
                        if not result_parts and all_outputs:
                            result_parts.append("\\n".join(all_outputs[-10:]))  # Last 10 outputs
                        
                        task_store[tid].status = TaskStatus.completed
                        task_store[tid].completed_at = datetime.now()
                        task_store[tid].result = "\\n\\n".join(result_parts) if result_parts else "Task completed successfully"
                        
                    except Exception as e:
                        task_store[tid].status = TaskStatus.failed
                        task_store[tid].error = str(e)
                        task_store[tid].completed_at = datetime.now()
                
                # Pass task_id and prompt as arguments to prevent closure issues
                threading.Thread(target=run_background_task, args=(task_id, full_message), daemon=True).start()
                continue  # Don't block, move to next message
            
            # Stream real agent execution with proper step callbacks
            async def run_with_real_streaming():
                # Capture chat_id for this request
                request_chat_id = chat_id
                
                # Send initial progress
                await ws.send_text(json.dumps({
                    "type": "activity",
                    "activity_type": "step",
                    "title": "🚀 Task Started",
                    "content": f"Processing: {msg_content[:100]}...",
                    "chat_id": request_chat_id
                }))
                
                await ws.send_text(json.dumps({
                    "type": "progress",
                    "content": "🔄 Agent analyzing your request...",
                    "chat_id": request_chat_id
                }))
                
                # Queue for thread-safe communication between agent thread and async handler
                event_queue = queue.Queue()
                
                def run_agent_with_streaming():
                    """Run agent in thread and put events in queue."""
                    try:
                        # Acquire lock for concurrent access
                        with agent_lock:
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
                                
                                # Send activity update with counts and chat_id
                                await ws.send_text(json.dumps({
                                    "type": "activity",
                                    "activity_type": event["activity_type"],
                                    "title": event["title"],
                                    "content": event["content"],
                                    "tool_count": last_tool_count,
                                    "step_count": last_step_count,
                                    "chat_id": request_chat_id
                                }))
                                
                                # Also send progress update for chat
                                await ws.send_text(json.dumps({
                                    "type": "progress",
                                    "content": event["title"],
                                    "chat_id": request_chat_id
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
                                    "step_count": last_step_count,
                                    "chat_id": request_chat_id
                                }))
                                break
                            
                            elif event["type"] == "error":
                                await ws.send_text(json.dumps({
                                    "type": "activity",
                                    "activity_type": "error",
                                    "title": "❌ Error Occurred",
                                    "content": event["error"],
                                    "chat_id": request_chat_id
                                }))
                                await ws.send_text(json.dumps({
                                    "type": "final",
                                    "content": f"Error: {event['error']}",
                                    "chat_id": request_chat_id
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
                            "content": str(e),
                            "chat_id": request_chat_id
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
                            "content": "Creating professional security report...",
                            "chat_id": request_chat_id
                        }))
                        
                        html_report = generate_html_report()
                        md_report = generate_markdown_report()
                        
                        await ws.send_text(json.dumps({
                            "type": "final",
                            "content": str(final_response),
                            "chat_id": request_chat_id
                        }))
                        
                        await ws.send_text(json.dumps({
                            "type": "report",
                            "content": "📋 Professional security report has been generated.",
                            "html": html_report,
                            "markdown": md_report,
                            "chat_id": request_chat_id
                        }))
                        return
                
                # Send final response
                await ws.send_text(json.dumps({
                    "type": "final",
                    "content": str(final_response) if final_response else "Task completed",
                    "chat_id": request_chat_id
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
