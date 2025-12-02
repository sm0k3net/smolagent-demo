"""Slack integration tools for OWASP Agent.

Uses Slack Incoming Webhooks for sending messages and optionally
Slack Events API for receiving messages.

Setup:
1. Create a Slack app at https://api.slack.com/apps
2. Enable Incoming Webhooks
3. Add webhook to a channel
4. Copy the webhook URL
5. Optionally enable Events API for receiving messages
"""
from __future__ import annotations
import os
import json
import asyncio
import threading
from typing import Optional, Dict, Any, Callable, List
from smolagents import tool
from datetime import datetime


# Slack integration state
_slack_state = {
    "webhook_url": None,
    "connected": False,
    "channel": None,
    "bot_token": None,  # For advanced features like file upload
    "app_token": None,  # For Socket Mode
    "socket_client": None,
    "listening": False,
    "event_loop": None,
    "loop_thread": None,
    "message_callback": None,
    "received_messages": [],
}


def _get_or_create_event_loop():
    """Get or create a persistent event loop for Slack operations."""
    global _slack_state
    
    if _slack_state["event_loop"] is not None:
        try:
            if not _slack_state["event_loop"].is_closed():
                return _slack_state["event_loop"]
        except:
            pass
    
    # Create a new event loop in a background thread
    loop = asyncio.new_event_loop()
    _slack_state["event_loop"] = loop
    
    def run_loop():
        asyncio.set_event_loop(loop)
        loop.run_forever()
    
    thread = threading.Thread(target=run_loop, daemon=True)
    thread.start()
    _slack_state["loop_thread"] = thread
    
    return loop


def _run_async(coro):
    """Run an async coroutine in the persistent event loop."""
    loop = _get_or_create_event_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result(timeout=60)  # 60 second timeout


def _ensure_requests():
    """Ensure requests library is available."""
    try:
        import requests
        return requests, None
    except ImportError:
        import subprocess
        try:
            subprocess.run(
                ["pip", "install", "requests"],
                check=True,
                capture_output=True,
                text=True
            )
            import requests
            return requests, None
        except Exception as e:
            return None, f"Failed to install requests: {e}"


def _ensure_slack_sdk():
    """Ensure Slack SDK is available (for advanced features)."""
    try:
        from slack_sdk import WebClient
        from slack_sdk.socket_mode import SocketModeClient
        from slack_sdk.socket_mode.response import SocketModeResponse
        from slack_sdk.socket_mode.request import SocketModeRequest
        return True, None
    except ImportError:
        return False, "slack_sdk not installed"


@tool
def slack_connect(webhook_url: Optional[str] = None, bot_token: Optional[str] = None) -> str:
    """Connect to Slack using a webhook URL or bot token.
    
    For simple message sending, only webhook_url is needed.
    For advanced features (file uploads, receiving messages), provide bot_token.
    
    Args:
        webhook_url: Slack Incoming Webhook URL (or use SLACK_WEBHOOK_URL env var)
        bot_token: Slack Bot Token starting with xoxb- (or use SLACK_BOT_TOKEN env var)
    
    Returns:
        Connection status message
    """
    global _slack_state
    
    # Get credentials from arguments or environment
    webhook = webhook_url or os.environ.get("SLACK_WEBHOOK_URL", "")
    token = bot_token or os.environ.get("SLACK_BOT_TOKEN", "")
    
    if not webhook and not token:
        return """❌ No Slack credentials found!

Please provide either:

**Option 1: Webhook URL (simplest, for sending messages only)**
1. Go to https://api.slack.com/apps
2. Create a new app or select existing
3. Go to "Incoming Webhooks" and enable it
4. Click "Add New Webhook to Workspace"
5. Select a channel and authorize
6. Copy the webhook URL

Then connect:
- slack_connect(webhook_url="https://hooks.slack.com/services/...")
- Or set SLACK_WEBHOOK_URL environment variable

**Option 2: Bot Token (for advanced features)**
1. Go to https://api.slack.com/apps
2. Create/select app and go to "OAuth & Permissions"
3. Add scopes: chat:write, files:write, channels:history (as needed)
4. Install to workspace and copy Bot Token (xoxb-...)

Then connect:
- slack_connect(bot_token="xoxb-...")
- Or set SLACK_BOT_TOKEN environment variable"""

    _slack_state["webhook_url"] = webhook
    _slack_state["bot_token"] = token
    
    # Test webhook connection
    if webhook:
        requests, err = _ensure_requests()
        if err:
            return err
        
        try:
            # Send a test connection (we won't actually post anything)
            # Just verify the URL format
            if not webhook.startswith("https://hooks.slack.com/"):
                return "❌ Invalid webhook URL format. Should start with https://hooks.slack.com/"
            
            _slack_state["connected"] = True
            
            result_parts = ["✅ Connected to Slack via Webhook!"]
            
            if token:
                result_parts.append("Bot token also configured for advanced features.")
            
            result_parts.append("""
You can now use:
- slack_send_message() to send messages
- slack_send_formatted() for rich formatted messages
- slack_send_alert() for security alerts""")
            
            return "\n".join(result_parts)
            
        except Exception as e:
            return f"❌ Failed to connect to Slack: {str(e)}"
    
    elif token:
        # Bot token only mode
        has_sdk, sdk_err = _ensure_slack_sdk()
        
        if has_sdk:
            try:
                from slack_sdk import WebClient
                client = WebClient(token=token)
                auth_response = client.auth_test()
                
                _slack_state["connected"] = True
                _slack_state["bot_username"] = auth_response.get("user")
                _slack_state["team"] = auth_response.get("team")
                
                return f"""✅ Connected to Slack via Bot Token!

**Bot Info:**
- User: {auth_response.get('user')}
- Team: {auth_response.get('team')}

You can now use:
- slack_send_message() to send messages
- slack_send_file() to upload files
- slack_start_listening() to receive messages (requires Socket Mode)"""
                
            except Exception as e:
                return f"❌ Failed to authenticate with Slack: {str(e)}"
        else:
            _slack_state["connected"] = True
            return """✅ Bot token configured!

Note: slack_sdk not installed. Install for advanced features:
pip install slack_sdk

Webhook-based messaging will still work."""
    
    return "❌ Unexpected error during connection"


@tool
def slack_send_message(message: str, channel: Optional[str] = None) -> str:
    """Send a simple text message to Slack.
    
    Args:
        message: The message text to send
        channel: Target channel (optional, uses webhook default or SLACK_CHANNEL env var)
    
    Returns:
        Status message confirming delivery or error
    """
    global _slack_state
    
    if not _slack_state["connected"]:
        return "❌ Not connected to Slack. Use slack_connect() first."
    
    webhook = _slack_state["webhook_url"]
    token = _slack_state["bot_token"]
    target_channel = channel or os.environ.get("SLACK_CHANNEL")
    
    requests, err = _ensure_requests()
    if err:
        return err
    
    try:
        if webhook:
            # Use webhook (channel is determined by webhook config)
            payload = {"text": message}
            if target_channel:
                payload["channel"] = target_channel
            
            response = requests.post(
                webhook,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200 and response.text == "ok":
                return f"✅ Message sent to Slack"
            else:
                return f"❌ Failed to send message: {response.text}"
        
        elif token:
            # Use Web API
            has_sdk, _ = _ensure_slack_sdk()
            if has_sdk:
                from slack_sdk import WebClient
                client = WebClient(token=token)
                
                if not target_channel:
                    return "❌ No channel specified. Use channel parameter or set SLACK_CHANNEL env var."
                
                result = client.chat_postMessage(
                    channel=target_channel,
                    text=message
                )
                
                if result["ok"]:
                    return f"✅ Message sent to {target_channel}"
                else:
                    return f"❌ Failed: {result.get('error', 'Unknown error')}"
            else:
                return "❌ slack_sdk required for bot token messaging. Use webhook instead."
        
        return "❌ No valid connection method available"
        
    except Exception as e:
        return f"❌ Failed to send message: {str(e)}"


@tool
def slack_send_formatted(
    title: str,
    text: str,
    color: str = "#36a64f",
    fields: Optional[str] = None,
    channel: Optional[str] = None
) -> str:
    """Send a formatted message with attachments to Slack.
    
    Args:
        title: Bold title for the message
        text: Main message text
        color: Sidebar color in hex (default: green #36a64f)
        fields: JSON string of fields [{"title": "Field", "value": "Value", "short": true}]
        channel: Target channel (optional)
    
    Returns:
        Status message confirming delivery or error
    """
    global _slack_state
    
    if not _slack_state["connected"]:
        return "❌ Not connected to Slack. Use slack_connect() first."
    
    webhook = _slack_state["webhook_url"]
    
    requests, err = _ensure_requests()
    if err:
        return err
    
    try:
        # Parse fields if provided
        field_list = []
        if fields:
            try:
                field_list = json.loads(fields)
            except json.JSONDecodeError:
                pass
        
        # Build Block Kit message for modern formatting
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": title,
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": text
                }
            }
        ]
        
        # Add fields if provided
        if field_list:
            field_elements = []
            for field in field_list:
                field_elements.append({
                    "type": "mrkdwn",
                    "text": f"*{field.get('title', '')}*\n{field.get('value', '')}"
                })
            
            # Group fields into sections of 2
            for i in range(0, len(field_elements), 2):
                blocks.append({
                    "type": "section",
                    "fields": field_elements[i:i+2]
                })
        
        # Also include attachment for color support
        attachment = {
            "color": color,
            "blocks": blocks
        }
        
        payload = {
            "attachments": [attachment]
        }
        
        if channel:
            payload["channel"] = channel
        
        if webhook:
            response = requests.post(
                webhook,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200 and response.text == "ok":
                return f"✅ Formatted message sent to Slack"
            else:
                return f"❌ Failed to send: {response.text}"
        
        return "❌ No webhook URL configured"
        
    except Exception as e:
        return f"❌ Failed to send formatted message: {str(e)}"


@tool
def slack_send_alert(
    alert_type: str,
    title: str,
    description: str,
    severity: str = "medium",
    target: Optional[str] = None,
    details: Optional[str] = None,
    channel: Optional[str] = None
) -> str:
    """Send a security alert to Slack with proper formatting.
    
    Args:
        alert_type: Type of alert (vulnerability, scan_complete, finding, warning, etc.)
        title: Alert title
        description: Alert description
        severity: Severity level (critical, high, medium, low, info)
        target: Target URL/IP/system (optional)
        details: Additional details or findings (optional)
        channel: Target channel (optional)
    
    Returns:
        Status message confirming delivery or error
    """
    global _slack_state
    
    if not _slack_state["connected"]:
        return "❌ Not connected to Slack. Use slack_connect() first."
    
    # Color mapping for severity
    severity_colors = {
        "critical": "#FF0000",  # Red
        "high": "#FF6B00",      # Orange
        "medium": "#FFB800",    # Yellow/Orange
        "low": "#00C853",       # Green
        "info": "#2196F3"       # Blue
    }
    
    # Emoji mapping
    severity_emoji = {
        "critical": "🚨",
        "high": "⚠️",
        "medium": "🔶",
        "low": "🔵",
        "info": "ℹ️"
    }
    
    color = severity_colors.get(severity.lower(), "#808080")
    emoji = severity_emoji.get(severity.lower(), "📋")
    
    webhook = _slack_state["webhook_url"]
    
    requests, err = _ensure_requests()
    if err:
        return err
    
    try:
        # Build blocks for the alert
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {alert_type.upper()}: {title}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": description
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{severity.upper()}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Time:*\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    }
                ]
            }
        ]
        
        # Add target if provided
        if target:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Target:* `{target}`"
                }
            })
        
        # Add details if provided
        if details:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Details:*\n```{details[:2000]}```"
                }
            })
        
        # Add divider
        blocks.append({"type": "divider"})
        
        # Context footer
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🔒 *OWASP Security Agent* | Automated Security Alert"
                }
            ]
        })
        
        payload = {
            "attachments": [{
                "color": color,
                "blocks": blocks
            }]
        }
        
        if channel:
            payload["channel"] = channel
        
        if webhook:
            response = requests.post(
                webhook,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200 and response.text == "ok":
                return f"✅ Security alert sent to Slack: {title}"
            else:
                return f"❌ Failed to send alert: {response.text}"
        
        return "❌ No webhook URL configured"
        
    except Exception as e:
        return f"❌ Failed to send alert: {str(e)}"


@tool
def slack_send_report_summary(
    report_title: str,
    total_findings: int,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    target: Optional[str] = None,
    report_url: Optional[str] = None,
    channel: Optional[str] = None
) -> str:
    """Send a security report summary to Slack.
    
    Args:
        report_title: Title of the report
        total_findings: Total number of findings
        critical: Number of critical findings
        high: Number of high severity findings
        medium: Number of medium severity findings
        low: Number of low severity findings
        target: Target of the assessment
        report_url: URL to full report (optional)
        channel: Target channel (optional)
    
    Returns:
        Status message confirming delivery or error
    """
    global _slack_state
    
    if not _slack_state["connected"]:
        return "❌ Not connected to Slack. Use slack_connect() first."
    
    webhook = _slack_state["webhook_url"]
    
    requests, err = _ensure_requests()
    if err:
        return err
    
    # Determine overall color based on highest severity
    if critical > 0:
        color = "#FF0000"
        status_emoji = "🚨"
    elif high > 0:
        color = "#FF6B00"
        status_emoji = "⚠️"
    elif medium > 0:
        color = "#FFB800"
        status_emoji = "🔶"
    elif low > 0:
        color = "#00C853"
        status_emoji = "✅"
    else:
        color = "#2196F3"
        status_emoji = "🎉"
    
    try:
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"📊 Security Report: {report_title}",
                    "emoji": True
                }
            }
        ]
        
        # Target info
        if target:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Target:* `{target}`"
                }
            })
        
        # Findings summary
        findings_text = f"""
*Total Findings:* {total_findings}

🚨 *Critical:* {critical}
⚠️ *High:* {high}
🔶 *Medium:* {medium}
🔵 *Low:* {low}
"""
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": findings_text
            }
        })
        
        # Visual progress bar
        if total_findings > 0:
            bar_parts = []
            if critical > 0:
                bar_parts.extend(["🟥"] * min(critical, 5))
            if high > 0:
                bar_parts.extend(["🟧"] * min(high, 5))
            if medium > 0:
                bar_parts.extend(["🟨"] * min(medium, 5))
            if low > 0:
                bar_parts.extend(["🟩"] * min(low, 5))
            
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": " ".join(bar_parts[:20])  # Max 20 squares
                    }
                ]
            })
        
        # Report link if available
        if report_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "📄 View Full Report",
                            "emoji": True
                        },
                        "url": report_url,
                        "action_id": "view_report"
                    }
                ]
            })
        
        blocks.append({"type": "divider"})
        
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"🔒 *OWASP Security Agent* | Report generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                }
            ]
        })
        
        payload = {
            "attachments": [{
                "color": color,
                "blocks": blocks
            }]
        }
        
        if channel:
            payload["channel"] = channel
        
        if webhook:
            response = requests.post(
                webhook,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200 and response.text == "ok":
                return f"✅ Report summary sent to Slack: {report_title}"
            else:
                return f"❌ Failed to send report: {response.text}"
        
        return "❌ No webhook URL configured"
        
    except Exception as e:
        return f"❌ Failed to send report summary: {str(e)}"


@tool
def slack_send_file(file_path: str, title: Optional[str] = None, comment: Optional[str] = None, channel: Optional[str] = None) -> str:
    """Upload a file to Slack.
    
    Requires bot token with files:write scope.
    
    Args:
        file_path: Path to the file to upload
        title: Title for the file (optional)
        comment: Initial comment (optional)
        channel: Target channel (required for upload)
    
    Returns:
        Status message confirming upload or error
    """
    global _slack_state
    
    if not _slack_state["connected"]:
        return "❌ Not connected to Slack. Use slack_connect() first."
    
    token = _slack_state["bot_token"]
    target_channel = channel or os.environ.get("SLACK_CHANNEL")
    
    if not token:
        return "❌ File upload requires bot token. Use slack_connect(bot_token='xoxb-...') first."
    
    if not target_channel:
        return "❌ No channel specified. Use channel parameter or set SLACK_CHANNEL env var."
    
    if not os.path.exists(file_path):
        return f"❌ File not found: {file_path}"
    
    has_sdk, err = _ensure_slack_sdk()
    if not has_sdk:
        return f"❌ slack_sdk required for file upload. Run: pip install slack_sdk"
    
    try:
        from slack_sdk import WebClient
        client = WebClient(token=token)
        
        result = client.files_upload_v2(
            channels=target_channel,
            file=file_path,
            title=title or os.path.basename(file_path),
            initial_comment=comment
        )
        
        if result["ok"]:
            return f"✅ File uploaded to {target_channel}: {os.path.basename(file_path)}"
        else:
            return f"❌ Upload failed: {result.get('error', 'Unknown error')}"
            
    except Exception as e:
        return f"❌ Failed to upload file: {str(e)}"


@tool
def slack_start_listening(app_token: Optional[str] = None, channel: Optional[str] = None) -> str:
    """Start listening for incoming Slack messages using Socket Mode.
    
    Requires Slack app with Socket Mode enabled and app-level token.
    
    Args:
        app_token: App-level token starting with xapp- (or use SLACK_APP_TOKEN env var)
        channel: Channel ID to monitor (or use SLACK_CHANNEL env var)
    
    Returns:
        Status message about listening setup
    """
    global _slack_state
    
    if not _slack_state["connected"]:
        return "❌ Not connected to Slack. Use slack_connect() first."
    
    token = app_token or os.environ.get("SLACK_APP_TOKEN")
    bot_token = _slack_state["bot_token"]
    
    if not token:
        return """❌ Socket Mode requires an app-level token.

To enable Socket Mode:
1. Go to your app at https://api.slack.com/apps
2. Click "Socket Mode" in the sidebar
3. Enable Socket Mode
4. Generate an app-level token with connections:write scope
5. Copy the token (starts with xapp-)

Then:
- slack_start_listening(app_token="xapp-...")
- Or set SLACK_APP_TOKEN environment variable"""
    
    if not bot_token:
        return "❌ Bot token required for Socket Mode. Use slack_connect(bot_token='xoxb-...') first."
    
    has_sdk, err = _ensure_slack_sdk()
    if not has_sdk:
        return f"""❌ slack_sdk required for Socket Mode.

Run: pip install slack_sdk"""
    
    try:
        from slack_sdk.socket_mode import SocketModeClient
        from slack_sdk.socket_mode.response import SocketModeResponse
        from slack_sdk.socket_mode.request import SocketModeRequest
        from slack_sdk import WebClient
        
        # Create socket mode client
        client = SocketModeClient(
            app_token=token,
            web_client=WebClient(token=bot_token)
        )
        
        def process_event(client: SocketModeClient, req: SocketModeRequest):
            if req.type == "events_api":
                # Acknowledge the event
                response = SocketModeResponse(envelope_id=req.envelope_id)
                client.send_socket_mode_response(response)
                
                # Process the event
                event = req.payload.get("event", {})
                if event.get("type") == "message" and "subtype" not in event:
                    message_data = {
                        "channel": event.get("channel"),
                        "user": event.get("user"),
                        "text": event.get("text"),
                        "ts": event.get("ts"),
                        "time": datetime.now().isoformat()
                    }
                    _slack_state["received_messages"].append(message_data)
                    
                    # Limit stored messages
                    if len(_slack_state["received_messages"]) > 100:
                        _slack_state["received_messages"] = _slack_state["received_messages"][-50:]
                    
                    # Call callback if registered
                    if _slack_state["message_callback"]:
                        try:
                            _slack_state["message_callback"](message_data)
                        except Exception as e:
                            print(f"Slack callback error: {e}")
        
        client.socket_mode_request_listeners.append(process_event)
        
        # Start in background thread
        def run_socket():
            client.connect()
            _slack_state["socket_client"] = client
        
        thread = threading.Thread(target=run_socket, daemon=True)
        thread.start()
        
        _slack_state["listening"] = True
        
        return f"""✅ Started listening for Slack messages!

Messages will be collected and can be retrieved with slack_get_messages().

To stop listening, use slack_stop_listening()."""
        
    except Exception as e:
        return f"❌ Failed to start listening: {str(e)}"


@tool
def slack_stop_listening() -> str:
    """Stop listening for Slack messages.
    
    Returns:
        Status message
    """
    global _slack_state
    
    if _slack_state["socket_client"]:
        try:
            _slack_state["socket_client"].close()
        except:
            pass
    
    _slack_state["socket_client"] = None
    _slack_state["listening"] = False
    
    return "✅ Stopped listening for Slack messages"


@tool
def slack_get_messages(limit: int = 10) -> str:
    """Get recently received Slack messages.
    
    Only works if slack_start_listening() was called.
    
    Args:
        limit: Maximum number of messages to return (default: 10)
    
    Returns:
        Recent messages in JSON format
    """
    global _slack_state
    
    if not _slack_state["listening"]:
        return "❌ Not listening for messages. Use slack_start_listening() first."
    
    messages = _slack_state["received_messages"][-limit:]
    
    if not messages:
        return "No messages received yet."
    
    return f"Recent Slack messages:\n```json\n{json.dumps(messages, indent=2)}\n```"


@tool
def slack_status() -> str:
    """Get the current Slack connection status.
    
    Returns:
        Current connection status and configuration
    """
    global _slack_state
    
    if not _slack_state["connected"]:
        has_webhook = bool(os.environ.get("SLACK_WEBHOOK_URL"))
        has_token = bool(os.environ.get("SLACK_BOT_TOKEN"))
        has_app_token = bool(os.environ.get("SLACK_APP_TOKEN"))
        
        return f"""📱 Slack Status: Not Connected

**Environment Variables:**
- SLACK_WEBHOOK_URL: {'✅ Set' if has_webhook else '❌ Not set'}
- SLACK_BOT_TOKEN: {'✅ Set' if has_token else '❌ Not set'}
- SLACK_APP_TOKEN: {'✅ Set' if has_app_token else '❌ Not set'}
- SLACK_CHANNEL: {os.environ.get('SLACK_CHANNEL', '❌ Not set')}

Use slack_connect() to connect."""
    
    listening_status = "✅ Active" if _slack_state.get("listening") else "❌ Not active"
    msg_count = len(_slack_state.get("received_messages", []))
    
    return f"""📱 Slack Status: Connected ✅

**Configuration:**
- Webhook: {'✅ Configured' if _slack_state.get('webhook_url') else '❌ Not configured'}
- Bot Token: {'✅ Configured' if _slack_state.get('bot_token') else '❌ Not configured'}
- Listening: {listening_status}
- Messages Received: {msg_count}

**Available Features:**
- Send Messages: ✅
- Send Alerts: ✅
- Send Reports: ✅
- File Upload: {'✅' if _slack_state.get('bot_token') else '❌ (needs bot token)'}
- Receive Messages: {'✅' if _slack_state.get('listening') else '❌ (needs socket mode)'}"""


@tool
def slack_disconnect() -> str:
    """Disconnect from Slack.
    
    Returns:
        Disconnection status
    """
    global _slack_state
    
    if _slack_state["socket_client"]:
        try:
            _slack_state["socket_client"].close()
        except:
            pass
    
    _slack_state["webhook_url"] = None
    _slack_state["connected"] = False
    _slack_state["bot_token"] = None
    _slack_state["app_token"] = None
    _slack_state["socket_client"] = None
    _slack_state["listening"] = False
    _slack_state["received_messages"] = []
    
    return "✅ Disconnected from Slack"


# Callback registration for external handlers
def register_slack_message_callback(callback: Callable):
    """Register a callback function to handle incoming Slack messages.
    
    The callback will receive a dict with: channel, user, text, ts, time
    """
    global _slack_state
    _slack_state["message_callback"] = callback


def get_slack_state():
    """Get the current Slack state for external access."""
    return _slack_state.copy()
