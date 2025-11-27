from __future__ import annotations
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from app.agents.owasp_agent import build_owasp_agent
from app.tools.report_tools import enable_report_mode, disable_report_mode, get_report_status
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor

app = FastAPI(title="OWASP SmolAgent")
agent = None
startup_lock = asyncio.Lock()
executor = ThreadPoolExecutor(max_workers=4)

@app.on_event("startup")
async def startup():
    global agent
    async with startup_lock:
        if agent is None:
            agent = build_owasp_agent()

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OWASP SmolAgent - Security Testing Assistant</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  color: #333;
}
header {
  background: rgba(255,255,255,0.95);
  padding: 1.5rem 2rem;
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 1rem;
  z-index: 10;
}
h1 {
  font-size: 1.75rem;
  color: #667eea;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
h1::before { content: '🛡️'; }
.header-actions {
  display: flex;
  gap: 0.75rem;
  align-items: center;
}
.btn {
  padding: 0.6rem 1.2rem;
  border: none;
  border-radius: 6px;
  font-size: 0.9rem;
  cursor: pointer;
  transition: all 0.2s;
  font-weight: 500;
}
.btn-primary {
  background: #667eea;
  color: white;
}
.btn-primary:hover {
  background: #5568d3;
  transform: translateY(-1px);
  box-shadow: 0 4px 8px rgba(102,126,234,0.3);
}
.btn-secondary {
  background: #f0f0f0;
  color: #333;
}
.btn-secondary:hover {
  background: #e0e0e0;
}

/* Report Mode Toggle */
.report-toggle {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: #f8f9fa;
  border-radius: 8px;
  border: 2px solid #e0e0e0;
}
.report-toggle.active {
  background: #d4edda;
  border-color: #28a745;
}
.report-toggle label {
  cursor: pointer;
  font-weight: 500;
  color: #333;
}
.report-toggle input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

/* Main layout with sidebar */
.main-wrapper {
  flex: 1;
  display: flex;
  max-width: 100%;
  overflow: hidden;
}

/* Sidebar */
#sidebar {
  width: 60px;
  min-width: 60px;
  background: rgba(255,255,255,0.98);
  border-right: 1px solid #e0e0e0;
  display: flex;
  flex-direction: column;
  transition: all 0.3s ease;
  box-shadow: 2px 0 8px rgba(0,0,0,0.05);
}
#sidebar.expanded {
  width: 380px;
  min-width: 380px;
}
.sidebar-toggle {
  padding: 1rem;
  background: #667eea;
  color: white;
  border: none;
  cursor: pointer;
  font-size: 1.2rem;
  transition: background 0.2s;
}
.sidebar-toggle:hover {
  background: #5568d3;
}
.sidebar-header {
  padding: 1rem;
  background: #f8f9fa;
  border-bottom: 1px solid #e0e0e0;
  font-weight: 600;
  color: #667eea;
  display: none;
}
#sidebar.expanded .sidebar-header {
  display: block;
}
#activity-log {
  flex: 1;
  overflow-y: auto;
  padding: 0;
  display: none;
}
#sidebar.expanded #activity-log {
  display: block;
  padding: 1rem;
}
.activity-item {
  padding: 0.75rem;
  margin-bottom: 0.5rem;
  border-radius: 6px;
  font-size: 0.85rem;
  animation: slideIn 0.3s ease;
}
@keyframes slideIn {
  from { opacity: 0; transform: translateX(-10px); }
  to { opacity: 1; transform: translateX(0); }
}
.activity-thinking {
  background: #fff3cd;
  border-left: 3px solid #ffc107;
}
.activity-tool {
  background: #d1ecf1;
  border-left: 3px solid #17a2b8;
}
.activity-tool-result {
  background: #d4edda;
  border-left: 3px solid #28a745;
}
.activity-error {
  background: #f8d7da;
  border-left: 3px solid #dc3545;
}
.activity-step {
  background: #e2e3e5;
  border-left: 3px solid #6c757d;
}
.activity-time {
  font-size: 0.75rem;
  color: #666;
  margin-bottom: 0.25rem;
}
.activity-content {
  word-break: break-word;
}
.activity-content pre {
  background: #282c34;
  color: #abb2bf;
  padding: 0.5rem;
  border-radius: 4px;
  font-size: 0.8rem;
  overflow-x: auto;
  margin-top: 0.5rem;
}

/* Main content area */
main {
  flex: 1;
  display: flex;
  flex-direction: column;
  padding: 2rem;
  gap: 1.5rem;
  overflow: hidden;
}
#chat-container {
  background: white;
  border-radius: 12px;
  box-shadow: 0 4px 16px rgba(0,0,0,0.1);
  display: flex;
  flex-direction: column;
  flex: 1;
  overflow: hidden;
}
#messages {
  flex: 1;
  padding: 1.5rem;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.message {
  padding: 1rem 1.25rem;
  border-radius: 8px;
  max-width: 85%;
  word-wrap: break-word;
  animation: fadeIn 0.3s;
}
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}
.msg-user {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  align-self: flex-end;
  border-bottom-right-radius: 4px;
}
.msg-agent {
  background: #f5f7fa;
  color: #333;
  align-self: flex-start;
  border-bottom-left-radius: 4px;
  border-left: 4px solid #667eea;
}
.msg-system {
  background: #fff3cd;
  color: #856404;
  align-self: center;
  max-width: 100%;
  text-align: center;
  font-size: 0.9rem;
  border-left: 4px solid #ffc107;
}
.msg-progress {
  background: #d1ecf1;
  color: #0c5460;
  align-self: flex-start;
  max-width: 100%;
  font-family: 'Courier New', monospace;
  font-size: 0.85rem;
  border-left: 4px solid #17a2b8;
}
.html-preview-btn {
  display: inline-block;
  margin-top: 0.5rem;
  padding: 0.4rem 0.8rem;
  background: #28a745;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85rem;
}
.html-preview-btn:hover {
  background: #218838;
}
#input-area {
  padding: 1.5rem;
  background: #f8f9fa;
  border-top: 1px solid #dee2e6;
  display: flex;
  gap: 1rem;
}
#message-input {
  flex: 1;
  padding: 1rem;
  border: 2px solid #e0e0e0;
  border-radius: 8px;
  font-size: 1rem;
  transition: border-color 0.2s;
}
#message-input:focus {
  outline: none;
  border-color: #667eea;
}
#send-btn {
  padding: 1rem 2rem;
}
.status-indicator {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  margin-left: 0.5rem;
}
.status-connected { background: #28a745; }
.status-disconnected { background: #dc3545; }
pre { 
  background: #282c34;
  color: #abb2bf;
  padding: 1rem;
  border-radius: 6px;
  overflow-x: auto;
  margin: 0.5rem 0;
}
code {
  font-family: 'Courier New', monospace;
}

/* Stats bar at bottom of sidebar */
.sidebar-stats {
  padding: 1rem;
  background: #f8f9fa;
  border-top: 1px solid #e0e0e0;
  display: none;
  font-size: 0.85rem;
}
#sidebar.expanded .sidebar-stats {
  display: block;
}
.stat-row {
  display: flex;
  justify-content: space-between;
  margin-bottom: 0.5rem;
}
.stat-label { color: #666; }
.stat-value { font-weight: 600; color: #333; }

/* Tool badges */
.tool-badge {
  display: inline-block;
  background: #667eea;
  color: white;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  margin-right: 0.25rem;
}
</style>
</head>
<body>
<header>
  <h1>OWASP SmolAgent<span class="status-indicator status-disconnected" id="status"></span></h1>
  <div class="header-actions">
    <div class="report-toggle" id="report-toggle">
      <input type="checkbox" id="report-mode-checkbox">
      <label for="report-mode-checkbox">📋 Report Mode</label>
    </div>
    <button class="btn btn-secondary" id="export-txt-btn">📥 Export Chat</button>
    <button class="btn btn-secondary" id="clear-btn">🗑️ Clear</button>
  </div>
</header>
<div class="main-wrapper">
  <!-- Expandable Sidebar for Agent Activity -->
  <div id="sidebar">
    <button class="sidebar-toggle" id="sidebar-toggle" title="Toggle Activity Log">📊</button>
    <div class="sidebar-header">🔍 Agent Activity</div>
    <div id="activity-log"></div>
    <div class="sidebar-stats">
      <div class="stat-row">
        <span class="stat-label">Steps:</span>
        <span class="stat-value" id="stat-steps">0</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Tools Used:</span>
        <span class="stat-value" id="stat-tools">0</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Duration:</span>
        <span class="stat-value" id="stat-duration">0s</span>
      </div>
    </div>
  </div>
  
  <main>
    <div id="chat-container">
      <div id="messages"></div>
      <div id="input-area">
        <input type="text" id="message-input" placeholder="Ask about OWASP standards, run pentests, classify vulnerabilities..." autocomplete="off">
        <button class="btn btn-primary" id="send-btn">Send</button>
      </div>
    </div>
  </main>
</div>
<script>
const messagesDiv = document.getElementById('messages');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const statusIndicator = document.getElementById('status');
const exportTxtBtn = document.getElementById('export-txt-btn');
const clearBtn = document.getElementById('clear-btn');
const sidebar = document.getElementById('sidebar');
const sidebarToggle = document.getElementById('sidebar-toggle');
const activityLog = document.getElementById('activity-log');
const reportToggle = document.getElementById('report-toggle');
const reportCheckbox = document.getElementById('report-mode-checkbox');

// Stats
let stepCount = 0;
let toolCount = 0;
let startTime = null;
let durationInterval = null;

let chatHistory = [];
const ws = new WebSocket(`ws://${location.host}/ws`);

// Sidebar toggle
sidebarToggle.onclick = () => {
  sidebar.classList.toggle('expanded');
  sidebarToggle.textContent = sidebar.classList.contains('expanded') ? '◀' : '📊';
};

// Report mode toggle
reportCheckbox.onchange = () => {
  const enabled = reportCheckbox.checked;
  reportToggle.classList.toggle('active', enabled);
  
  // Send command to enable/disable report mode
  if (enabled) {
    ws.send('__REPORT_MODE_ON__');
  } else {
    ws.send('__REPORT_MODE_OFF__');
  }
};

function addActivity(type, content, details = null) {
  const item = document.createElement('div');
  item.className = `activity-item activity-${type}`;
  
  const time = new Date().toLocaleTimeString();
  item.innerHTML = `
    <div class="activity-time">${time}</div>
    <div class="activity-content">${content}${details ? '<pre>' + escapeHtml(details) + '</pre>' : ''}</div>
  `;
  
  activityLog.appendChild(item);
  activityLog.scrollTop = activityLog.scrollHeight;
  
  // Update stats
  if (type === 'step') stepCount++;
  if (type === 'tool') toolCount++;
  document.getElementById('stat-steps').textContent = stepCount;
  document.getElementById('stat-tools').textContent = toolCount;
}

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text.substring(0, 500);
  return div.innerHTML + (text.length > 500 ? '... (truncated)' : '');
}

function startTimer() {
  startTime = Date.now();
  stepCount = 0;
  toolCount = 0;
  activityLog.innerHTML = '';
  
  if (durationInterval) clearInterval(durationInterval);
  durationInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    document.getElementById('stat-duration').textContent = elapsed + 's';
  }, 1000);
}

function stopTimer() {
  if (durationInterval) clearInterval(durationInterval);
}

function addMessage(type, content, meta) {
  const msgDiv = document.createElement('div');
  msgDiv.className = `message msg-${type}`;
  
  // Detect HTML content (full HTML document)
  if (type === 'agent' && content.includes('<!DOCTYPE html>')) {
    const htmlCode = content;
    msgDiv.innerHTML = '<strong>📋 HTML Report Generated</strong><br><small>Click button to preview</small>';
    
    const previewBtn = document.createElement('button');
    previewBtn.className = 'html-preview-btn';
    previewBtn.textContent = '👁️ Preview HTML Report';
    previewBtn.onclick = () => {
      const newWindow = window.open();
      newWindow.document.write(htmlCode);
      newWindow.document.close();
    };
    msgDiv.appendChild(previewBtn);
  }
  // Detect HTML code blocks
  else if (type === 'agent' && content.match(/```html\\n([\\s\\S]*?)\\n```/)) {
    const htmlMatch = content.match(/```html\\n([\\s\\S]*?)\\n```/);
    const htmlCode = htmlMatch[1];
    msgDiv.textContent = content;
    
    const previewBtn = document.createElement('button');
    previewBtn.className = 'html-preview-btn';
    previewBtn.textContent = '👁️ Preview HTML Report';
    previewBtn.onclick = () => {
      const newWindow = window.open();
      newWindow.document.write(htmlCode);
      newWindow.document.close();
    };
    msgDiv.appendChild(previewBtn);
  } else {
    msgDiv.textContent = content;
  }
  
  messagesDiv.appendChild(msgDiv);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
  
  chatHistory.push({ type, content, timestamp: new Date().toISOString(), ...meta });
}

ws.onopen = () => {
  statusIndicator.className = 'status-indicator status-connected';
  addMessage('system', '🟢 Connected to OWASP SmolAgent');
};

ws.onclose = () => {
  statusIndicator.className = 'status-indicator status-disconnected';
  addMessage('system', '🔴 Disconnected from server');
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  if (data.type === 'progress') {
    addMessage('progress', data.content);
  } else if (data.type === 'activity') {
    // Activity log update from agent steps
    addActivity(data.activity_type, data.content, data.details);
  } else if (data.type === 'final') {
    stopTimer();
    addMessage('agent', data.content);
    addActivity('step', '✅ Task completed');
  } else if (data.type === 'report_mode') {
    addMessage('system', data.content);
  } else {
    addMessage('agent', event.data);
  }
};

function sendMessage() {
  const content = messageInput.value.trim();
  if (!content) return;
  
  addMessage('user', content);
  startTimer();
  addActivity('step', '🚀 Starting task: ' + content.substring(0, 50) + '...');
  ws.send(content);
  messageInput.value = '';
  
  // Auto-expand sidebar when task starts
  if (!sidebar.classList.contains('expanded')) {
    sidebar.classList.add('expanded');
    sidebarToggle.textContent = '◀';
  }
}

sendBtn.onclick = sendMessage;
messageInput.onkeypress = (e) => {
  if (e.key === 'Enter') sendMessage();
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
  if (confirm('Clear all chat history?')) {
    messagesDiv.innerHTML = '';
    chatHistory = [];
    activityLog.innerHTML = '';
    stepCount = 0;
    toolCount = 0;
    document.getElementById('stat-steps').textContent = '0';
    document.getElementById('stat-tools').textContent = '0';
    document.getElementById('stat-duration').textContent = '0s';
    addMessage('system', 'Chat cleared');
  }
};
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
            msg = await ws.receive_text()
            
            # Handle report mode toggle commands
            if msg == "__REPORT_MODE_ON__":
                result = enable_report_mode(
                    title="Security Assessment Report",
                    target="Target to be specified",
                    author="OWASP SmolAgent"
                )
                await ws.send_text(json.dumps({
                    "type": "report_mode",
                    "content": "📋 Report Mode ENABLED - Findings will be collected for professional report generation."
                }))
                continue
            
            if msg == "__REPORT_MODE_OFF__":
                result = disable_report_mode()
                await ws.send_text(json.dumps({
                    "type": "report_mode", 
                    "content": "📋 Report Mode DISABLED - Report data cleared."
                }))
                continue
            
            # Stream progress updates
            async def run_with_progress():
                # Send initial progress
                await ws.send_text(json.dumps({
                    "type": "progress",
                    "content": "🔄 Agent processing your request..."
                }))
                
                await ws.send_text(json.dumps({
                    "type": "activity",
                    "activity_type": "thinking",
                    "content": "🧠 Analyzing request..."
                }))
                
                # Run agent in executor to avoid blocking
                loop = asyncio.get_event_loop()
                
                step_counter = [0]
                
                # Custom step callback to stream activity
                async def send_activity(activity_type, content, details=None):
                    await ws.send_text(json.dumps({
                        "type": "activity",
                        "activity_type": activity_type,
                        "content": content,
                        "details": details
                    }))
                
                def agent_run_wrapper(user_msg):
                    # Run the agent
                    return agent.run(user_msg)
                
                try:
                    response = await loop.run_in_executor(executor, agent_run_wrapper, msg)
                    
                    # Send final response
                    await ws.send_text(json.dumps({
                        "type": "final",
                        "content": response
                    }))
                except Exception as e:
                    await ws.send_text(json.dumps({
                        "type": "activity",
                        "activity_type": "error",
                        "content": f"❌ Error: {str(e)}"
                    }))
                    await ws.send_text(json.dumps({
                        "type": "final",
                        "content": f"Error: {e}"
                    }))
            
            await run_with_progress()
            
    except WebSocketDisconnect:
        return
    except Exception as e:
        await ws.send_text(json.dumps({"type": "final", "content": f"Error: {e}"}))
"""Run with: uvicorn app.main:app --reload"""
