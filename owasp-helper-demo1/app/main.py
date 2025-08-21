from __future__ import annotations
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from app.agents.owasp_agent import build_owasp_agent, format_owasp_query
import asyncio

app = FastAPI(title="OWASP SmolAgent")
agent = None
startup_lock = asyncio.Lock()

@app.on_event("startup")
async def startup():
    global agent
    async with startup_lock:
        if agent is None:
            agent = build_owasp_agent()

HTML = """
<!DOCTYPE html>
<html>
<head><title>OWASP SmolAgent Chat</title>
<style>
body { font-family: system-ui, sans-serif; margin: 1rem; }
#log { border: 1px solid #ccc; padding: .5rem; height: 60vh; overflow: auto; white-space: pre-wrap; }
.msg-user { color: #036; }
.msg-agent { color: #060; }
</style>
</head>
<body>
<h1>OWASP SmolAgent</h1>
<div id=log></div>
<form id=f>
<input id=inp style="width:80%" autocomplete=off placeholder="Ask about OWASP, security testing, classification..." />
<button>Send</button>
</form>
<script>
const ws = new WebSocket(`ws://${location.host}/ws`);
const log = document.getElementById('log');
function add(cls, text){const d=document.createElement('div');d.className=cls;d.textContent=text;log.appendChild(d);log.scrollTop=log.scrollHeight;}
ws.onmessage = (ev)=> add('msg-agent', ev.data);
ws.onopen = ()=> add('msg-agent', 'Connected.');
ws.onclose = ()=> add('msg-agent', 'Disconnected.');

const form=document.getElementById('f');
form.onsubmit = (e)=>{e.preventDefault(); const v=inp.value; if(!v) return; add('msg-user', v); ws.send(v); inp.value='';};
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
        await ws.send_text("Agent not ready")
        await ws.close()
        return
    try:
        while True:
            msg = await ws.receive_text()
            # run agent synchronously in thread to avoid blocking
            loop = asyncio.get_event_loop()
            prompt = format_owasp_query(msg)
            response = await loop.run_in_executor(None, agent.run, prompt)
            await ws.send_text(response)
    except WebSocketDisconnect:
        return
    except Exception as e:
        await ws.send_text(f"Error: {e}")
"""Run with: uvicorn app.main:app --reload"""
