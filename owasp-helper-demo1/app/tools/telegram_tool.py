"""Telegram Bot integration tools for OWASP Agent."""
from __future__ import annotations
import os
import json
import asyncio
import threading
from typing import Optional, Dict, Any, Callable
from smolagents import tool


# Telegram bot state
_telegram_state = {
    "bot": None,
    "connected": False,
    "chat_id": None,
    "group_id": None,
    "bot_username": None,
    "command_callback": None,
    "polling_thread": None,
    "stop_polling": False,
}


def _get_telegram_bot():
    """Get or create Telegram bot instance with auto-install."""
    try:
        from telegram import Bot
        return Bot, None
    except ImportError:
        # Auto-install python-telegram-bot
        import subprocess
        try:
            subprocess.run(
                ["pip", "install", "python-telegram-bot>=20.0"],
                check=True,
                capture_output=True,
                text=True
            )
            from telegram import Bot
            return Bot, None
        except Exception as e:
            return None, f"Failed to install python-telegram-bot: {e}"


@tool
def telegram_connect(bot_token: Optional[str] = None, chat_id: Optional[str] = None) -> str:
    """Connect to Telegram using a bot token. Auto-detects from environment if not provided.
    
    Args:
        bot_token: Telegram Bot API token (optional, uses TELEGRAM_BOT_TOKEN env var if not provided)
        chat_id: Default chat/group ID to send messages to (optional, uses TELEGRAM_CHAT_ID env var)
    
    Returns:
        Connection status message
    """
    global _telegram_state
    
    # Get token from argument or environment
    token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
    
    if not token:
        return """❌ No Telegram bot token found!

Please provide a bot token either:
1. As an argument: telegram_connect(bot_token="YOUR_TOKEN")
2. Set environment variable: TELEGRAM_BOT_TOKEN
3. Add via Settings tab: Add a new API key with name 'TELEGRAM_BOT_TOKEN'

To create a Telegram bot:
1. Open Telegram and search for @BotFather
2. Send /newbot command
3. Follow instructions to create your bot
4. Copy the API token provided"""

    Bot, err = _get_telegram_bot()
    if err:
        return err
    
    try:
        import asyncio
        
        async def verify_bot():
            bot = Bot(token=token)
            me = await bot.get_me()
            return bot, me
        
        # Run async in new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            bot, me = loop.run_until_complete(verify_bot())
        finally:
            loop.close()
        
        _telegram_state["bot"] = bot
        _telegram_state["connected"] = True
        _telegram_state["bot_username"] = me.username
        
        # Set chat ID if provided
        if chat_id:
            _telegram_state["chat_id"] = chat_id
        elif os.environ.get("TELEGRAM_CHAT_ID"):
            _telegram_state["chat_id"] = os.environ.get("TELEGRAM_CHAT_ID")
        
        chat_info = f" Default chat: {_telegram_state['chat_id']}" if _telegram_state['chat_id'] else ""
        
        return f"""✅ Connected to Telegram!

**Bot Info:**
- Username: @{me.username}
- Name: {me.first_name}
- ID: {me.id}{chat_info}

You can now use:
- telegram_send_message() to send messages
- telegram_set_chat() to set default chat/group
- telegram_start_listening() to receive commands"""
        
    except Exception as e:
        return f"❌ Failed to connect to Telegram: {str(e)}"


@tool
def telegram_set_chat(chat_id: str) -> str:
    """Set the default chat/group ID for sending messages.
    
    Args:
        chat_id: The Telegram chat or group ID (can be negative for groups)
    
    Returns:
        Confirmation message
    """
    global _telegram_state
    
    if not _telegram_state["connected"]:
        return "❌ Not connected to Telegram. Use telegram_connect() first."
    
    _telegram_state["chat_id"] = chat_id
    os.environ["TELEGRAM_CHAT_ID"] = str(chat_id)
    
    return f"✅ Default chat ID set to: {chat_id}"


@tool
def telegram_send_message(message: str, chat_id: Optional[str] = None, parse_mode: str = "HTML") -> str:
    """Send a message to a Telegram chat or group.
    
    Args:
        message: The message text to send (supports HTML formatting)
        chat_id: Target chat/group ID (optional, uses default if not provided)
        parse_mode: Message format - 'HTML', 'Markdown', or 'MarkdownV2' (default: HTML)
    
    Returns:
        Status message confirming delivery or error
    """
    global _telegram_state
    
    if not _telegram_state["connected"]:
        return "❌ Not connected to Telegram. Use telegram_connect() first."
    
    target_chat = chat_id or _telegram_state.get("chat_id")
    if not target_chat:
        return "❌ No chat ID specified. Use telegram_set_chat() or provide chat_id parameter."
    
    try:
        import asyncio
        
        async def send():
            bot = _telegram_state["bot"]
            result = await bot.send_message(
                chat_id=target_chat,
                text=message,
                parse_mode=parse_mode
            )
            return result
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(send())
        finally:
            loop.close()
        
        return f"✅ Message sent to chat {target_chat} (message_id: {result.message_id})"
        
    except Exception as e:
        return f"❌ Failed to send message: {str(e)}"


@tool
def telegram_send_file(file_path: str, caption: Optional[str] = None, chat_id: Optional[str] = None) -> str:
    """Send a file (document, image, etc.) to a Telegram chat.
    
    Args:
        file_path: Path to the file to send
        caption: Optional caption for the file
        chat_id: Target chat/group ID (optional, uses default if not provided)
    
    Returns:
        Status message confirming delivery or error
    """
    global _telegram_state
    
    if not _telegram_state["connected"]:
        return "❌ Not connected to Telegram. Use telegram_connect() first."
    
    target_chat = chat_id or _telegram_state.get("chat_id")
    if not target_chat:
        return "❌ No chat ID specified."
    
    if not os.path.exists(file_path):
        return f"❌ File not found: {file_path}"
    
    try:
        import asyncio
        
        async def send_doc():
            bot = _telegram_state["bot"]
            with open(file_path, 'rb') as f:
                # Determine if it's an image
                ext = file_path.lower().split('.')[-1]
                if ext in ['jpg', 'jpeg', 'png', 'gif', 'webp']:
                    result = await bot.send_photo(
                        chat_id=target_chat,
                        photo=f,
                        caption=caption
                    )
                else:
                    result = await bot.send_document(
                        chat_id=target_chat,
                        document=f,
                        caption=caption
                    )
                return result
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(send_doc())
        finally:
            loop.close()
        
        return f"✅ File sent to chat {target_chat}"
        
    except Exception as e:
        return f"❌ Failed to send file: {str(e)}"


@tool
def telegram_get_updates(limit: int = 10) -> str:
    """Get recent messages/updates from connected chats (for debugging).
    
    Args:
        limit: Maximum number of updates to retrieve (default: 10)
    
    Returns:
        Recent updates in JSON format
    """
    global _telegram_state
    
    if not _telegram_state["connected"]:
        return "❌ Not connected to Telegram. Use telegram_connect() first."
    
    try:
        import asyncio
        
        async def get_updates():
            bot = _telegram_state["bot"]
            updates = await bot.get_updates(limit=limit)
            return updates
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            updates = loop.run_until_complete(get_updates())
        finally:
            loop.close()
        
        if not updates:
            return "No recent updates found."
        
        results = []
        for update in updates:
            if update.message:
                msg = update.message
                results.append({
                    "update_id": update.update_id,
                    "chat_id": msg.chat.id,
                    "chat_type": msg.chat.type,
                    "from_user": msg.from_user.username if msg.from_user else None,
                    "text": msg.text,
                    "date": str(msg.date)
                })
        
        return f"Recent updates:\n```json\n{json.dumps(results, indent=2)}\n```"
        
    except Exception as e:
        return f"❌ Failed to get updates: {str(e)}"


@tool
def telegram_status() -> str:
    """Get the current Telegram connection status.
    
    Returns:
        Current connection status and configuration
    """
    global _telegram_state
    
    if not _telegram_state["connected"]:
        # Check if token is available in environment
        has_token = bool(os.environ.get("TELEGRAM_BOT_TOKEN"))
        return f"""📱 Telegram Status: Not Connected

**Environment:**
- TELEGRAM_BOT_TOKEN: {'✅ Set' if has_token else '❌ Not set'}
- TELEGRAM_CHAT_ID: {os.environ.get('TELEGRAM_CHAT_ID', '❌ Not set')}

Use telegram_connect() to connect."""
    
    return f"""📱 Telegram Status: Connected ✅

**Bot Info:**
- Username: @{_telegram_state.get('bot_username', 'Unknown')}
- Default Chat ID: {_telegram_state.get('chat_id', 'Not set')}
- Listening for commands: {_telegram_state.get('polling_thread') is not None}"""


@tool 
def telegram_disconnect() -> str:
    """Disconnect from Telegram and stop listening for commands.
    
    Returns:
        Disconnection status
    """
    global _telegram_state
    
    _telegram_state["stop_polling"] = True
    _telegram_state["connected"] = False
    _telegram_state["bot"] = None
    _telegram_state["bot_username"] = None
    
    if _telegram_state["polling_thread"]:
        _telegram_state["polling_thread"] = None
    
    return "✅ Disconnected from Telegram"


# Store for command handlers that can be registered
_command_handlers: Dict[str, Callable] = {}

def register_telegram_command_callback(callback: Callable):
    """Register a callback function to handle incoming Telegram commands.
    
    The callback will receive (chat_id, username, command, args) when a message
    mentioning the bot is received.
    """
    global _telegram_state
    _telegram_state["command_callback"] = callback


def get_telegram_state():
    """Get the current Telegram state for external access."""
    return _telegram_state.copy()
