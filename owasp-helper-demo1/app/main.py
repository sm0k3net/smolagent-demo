from __future__ import annotations
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from app.agents.owasp_agent import build_owasp_agent
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
main {
  flex: 1;
  display: flex;
  flex-direction: column;
  max-width: 1400px;
  width: 100%;
  margin: 0 auto;
  padding: 2rem;
  gap: 1.5rem;
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
</style>
</head>
<body>
<header>
  <h1>OWASP SmolAgent<span class="status-indicator status-disconnected" id="status"></span></h1>
  <div class="header-actions">
    <button class="btn btn-secondary" id="export-txt-btn">📥 Export Chat (TXT)</button>
    <button class="btn btn-secondary" id="clear-btn">🗑️ Clear Chat</button>
  </div>
</header>
<main>
  <div id="chat-container">
    <div id="messages"></div>
    <div id="input-area">
      <input type="text" id="message-input" placeholder="Ask about OWASP standards, run pentests, classify vulnerabilities..." autocomplete="off">
      <button class="btn btn-primary" id="send-btn">Send</button>
    </div>
  </div>
</main>
<script>
const messagesDiv = document.getElementById('messages');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const statusIndicator = document.getElementById('status');
const exportTxtBtn = document.getElementById('export-txt-btn');
const clearBtn = document.getElementById('clear-btn');

let chatHistory = [];
const ws = new WebSocket(`ws://${location.host}/ws`);

function addMessage(type, content, meta) {
  const msgDiv = document.createElement('div');
  msgDiv.className = `message msg-${type}`;
  
  // Detect HTML code blocks and add preview button
  const htmlMatch = content.match(/```html\\n([\\s\\S]*?)\\n```/);
  if (htmlMatch && type === 'agent') {
    const htmlCode = htmlMatch[1];
    const textNode = document.createTextNode(content);
    msgDiv.appendChild(textNode);
    
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
  } else if (data.type === 'final') {
    addMessage('agent', data.content);
  } else {
    addMessage('agent', event.data);
  }
};

function sendMessage() {
  const content = messageInput.value.trim();
  if (!content) return;
  
  addMessage('user', content);
  ws.send(content);
  messageInput.value = '';
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
            
            # Stream progress updates
            async def run_with_progress():
                # Send initial progress
                await ws.send_text(json.dumps({
                    "type": "progress",
                    "content": "🔄 Agent processing your request..."
                }))
                
                # Run agent in executor to avoid blocking
                loop = asyncio.get_event_loop()
                
                # Wrap agent run to capture intermediate steps
                def agent_run_wrapper(user_msg):
                    # Here we'd ideally hook into agent's step callback if available
                    # For now, we'll send the final response
                    return agent.run(user_msg)
                
                response = await loop.run_in_executor(executor, agent_run_wrapper, msg)
                
                # Send final response
                await ws.send_text(json.dumps({
                    "type": "final",
                    "content": response
                }))
            
            await run_with_progress()
            
    except WebSocketDisconnect:
        return
    except Exception as e:
        await ws.send_text(json.dumps({"type": "final", "content": f"Error: {e}"}))
"""Run with: uvicorn app.main:app --reload"""
