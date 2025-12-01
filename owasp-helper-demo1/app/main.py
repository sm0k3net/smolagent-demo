from __future__ import annotations
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
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
from app.config import (
    get_settings, update_runtime_settings, get_runtime_settings,
    PROVIDER_CONFIGS
)
import asyncio
import json
import base64
import queue
import threading
import uuid
import os
import time
import subprocess
import re
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, Any, Literal
import socket

# Database storage support (optional)
try:
    import psycopg2
    from psycopg2 import sql
    from psycopg2.extras import RealDictCursor
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False
    psycopg2 = None
    # Try to install psycopg2-binary automatically
    try:
        import subprocess
        import sys
        print("[Database] psycopg2 not found, attempting to install psycopg2-binary...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psycopg2-binary", "-q"])
        import psycopg2
        from psycopg2 import sql
        from psycopg2.extras import RealDictCursor
        HAS_PSYCOPG2 = True
        print("[Database] psycopg2-binary installed successfully!")
    except Exception as install_error:
        print(f"[Database] Could not auto-install psycopg2-binary: {install_error}")
        print("[Database] To enable database features, run: pip install psycopg2-binary")


class DatabaseStorage:
    """PostgreSQL/Supabase storage backend for command history and agent memory."""
    
    def __init__(self):
        self.connection = None
        self.config = {}
        self.enabled = False
        self.tables_initialized = False
    
    def configure(self, config: Dict[str, Any]) -> bool:
        """Configure database connection settings."""
        # Check if a connection URI was provided
        connection_uri = config.get("connection_uri", "")
        if connection_uri and connection_uri.startswith("postgresql://"):
            # Parse the URI
            try:
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(connection_uri)
                self.config = {
                    "host": parsed.hostname or "localhost",
                    "port": parsed.port or 5432,
                    "database": parsed.path.lstrip('/') or "postgres",
                    "user": parsed.username or "postgres",
                    "password": parsed.password or "",
                    "ssl_mode": parse_qs(parsed.query).get("sslmode", ["require"])[0],
                    "connection_type": "supabase" if "supabase" in (parsed.hostname or "") else "local",
                    "connection_uri": connection_uri,
                }
                return True
            except Exception as e:
                print(f"[Database] Failed to parse connection URI: {e}")
        
        self.config = {
            "host": config.get("host", "localhost"),
            "port": config.get("port", 5432),
            "database": config.get("database", "owasp_agent"),
            "user": config.get("user", "postgres"),
            "password": config.get("password", ""),
            "ssl_mode": config.get("ssl_mode", "prefer"),
            "connection_type": config.get("connection_type", "local"),  # local, supabase
        }
        return True
    
    def get_connection_string(self) -> str:
        """Generate PostgreSQL connection string."""
        ssl_param = ""
        if self.config.get("ssl_mode") and self.config["ssl_mode"] != "disable":
            ssl_param = f"?sslmode={self.config['ssl_mode']}"
        
        return f"postgresql://{self.config['user']}:{self.config['password']}@{self.config['host']}:{self.config['port']}/{self.config['database']}{ssl_param}"
    
    def connect(self) -> tuple[bool, str]:
        """Establish database connection."""
        if not HAS_PSYCOPG2:
            return False, "psycopg2 not installed. Run: pip install psycopg2-binary"
        
        try:
            ssl_mode = self.config.get("ssl_mode", "prefer")
            original_host = self.config["host"]
            
            # For Supabase/remote hosts, try to force IPv4 connection
            # libpq will use hostaddr if provided, bypassing DNS resolution
            connect_params = {
                "port": self.config["port"],
                "dbname": self.config["database"],
                "user": self.config["user"],
                "password": self.config["password"],
                "sslmode": ssl_mode,
                "connect_timeout": 15,
            }
            
            # Try to resolve to IPv4 and use hostaddr parameter
            resolved_ip = None
            try:
                resolved_ip = socket.gethostbyname(original_host)
                # Use hostaddr to force IPv4, but keep host for SSL certificate verification
                connect_params["hostaddr"] = resolved_ip
                connect_params["host"] = original_host
                print(f"[Database] Connecting via IPv4 address {resolved_ip} for {original_host}")
            except socket.gaierror as dns_err:
                print(f"[Database] IPv4 resolution failed, using hostname directly: {dns_err}")
                connect_params["host"] = original_host
            
            self.connection = psycopg2.connect(**connect_params)
            self.connection.autocommit = True
            self.enabled = True
            return True, f"Connected successfully{' via ' + resolved_ip if resolved_ip else ''}"
        except Exception as e:
            self.enabled = False
            return False, str(e)
    
    def disconnect(self):
        """Close database connection."""
        if self.connection:
            try:
                self.connection.close()
            except:
                pass
            self.connection = None
        self.enabled = False
    
    def test_connection(self) -> tuple[bool, str]:
        """Test database connection without persisting."""
        if not HAS_PSYCOPG2:
            return False, "psycopg2 not installed. Run: pip install psycopg2-binary"
        
        try:
            ssl_mode = self.config.get("ssl_mode", "prefer")
            original_host = self.config["host"]
            
            # For Supabase/remote hosts, try to force IPv4 connection
            # libpq will use hostaddr if provided, bypassing DNS resolution
            connect_params = {
                "port": self.config["port"],
                "dbname": self.config["database"],
                "user": self.config["user"],
                "password": self.config["password"],
                "sslmode": ssl_mode,
                "connect_timeout": 15,
            }
            
            # Try to resolve to IPv4 and use hostaddr parameter
            resolved_ip = None
            try:
                resolved_ip = socket.gethostbyname(original_host)
                # Use hostaddr to force IPv4, but keep host for SSL certificate verification
                connect_params["hostaddr"] = resolved_ip
                connect_params["host"] = original_host
                print(f"[Database] Using IPv4 address {resolved_ip} for {original_host}")
            except socket.gaierror as dns_err:
                print(f"[Database] IPv4 resolution failed, using hostname directly: {dns_err}")
                connect_params["host"] = original_host
            
            conn = psycopg2.connect(**connect_params)
            
            # Test with a simple query
            with conn.cursor() as cur:
                cur.execute("SELECT version();")
                version = cur.fetchone()[0]
            
            conn.close()
            return True, f"Connected! PostgreSQL {version.split(',')[0].replace('PostgreSQL ', '')}"
        except Exception as e:
            return False, str(e)
    
    def initialize_tables(self) -> tuple[bool, str]:
        """Create necessary tables if they don't exist."""
        if not self.connection or not self.enabled:
            return False, "Not connected to database"
        
        try:
            with self.connection.cursor() as cur:
                # Command history table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS command_history (
                        id SERIAL PRIMARY KEY,
                        session_id VARCHAR(50),
                        task_id VARCHAR(50),
                        command TEXT NOT NULL,
                        command_type VARCHAR(50),
                        tool_name VARCHAR(100),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                
                # Command outputs table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS command_outputs (
                        id SERIAL PRIMARY KEY,
                        command_id INTEGER REFERENCES command_history(id) ON DELETE CASCADE,
                        output TEXT,
                        output_type VARCHAR(50),
                        status VARCHAR(20),
                        execution_time_ms INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                
                # Agent memory/context table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS agent_memory (
                        id SERIAL PRIMARY KEY,
                        session_id VARCHAR(50),
                        key VARCHAR(255) NOT NULL,
                        value TEXT,
                        memory_type VARCHAR(50),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(session_id, key)
                    );
                """)
                
                # Task history table  
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS task_history (
                        id SERIAL PRIMARY KEY,
                        task_id VARCHAR(50) UNIQUE NOT NULL,
                        prompt TEXT NOT NULL,
                        result TEXT,
                        status VARCHAR(20),
                        tool_count INTEGER DEFAULT 0,
                        step_count INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        started_at TIMESTAMP,
                        completed_at TIMESTAMP,
                        error TEXT
                    );
                """)
                
                # Chat history table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS chat_history (
                        id SERIAL PRIMARY KEY,
                        chat_id VARCHAR(50) NOT NULL,
                        message_role VARCHAR(20) NOT NULL,
                        message_content TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                
                # Create indexes
                cur.execute("CREATE INDEX IF NOT EXISTS idx_command_history_session ON command_history(session_id);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_command_history_task ON command_history(task_id);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_agent_memory_session ON agent_memory(session_id);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_task_history_status ON task_history(status);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_history_chat ON chat_history(chat_id);")
                
            self.tables_initialized = True
            return True, "Tables initialized successfully"
        except Exception as e:
            return False, str(e)
    
    def log_command(self, session_id: str, task_id: str, command: str, 
                    command_type: str = "prompt", tool_name: str = None) -> Optional[int]:
        """Log a command to the database."""
        if not self.enabled or not self.connection:
            return None
        
        try:
            with self.connection.cursor() as cur:
                cur.execute("""
                    INSERT INTO command_history (session_id, task_id, command, command_type, tool_name)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id;
                """, (session_id, task_id, command, command_type, tool_name))
                return cur.fetchone()[0]
        except Exception as e:
            print(f"Error logging command: {e}")
            return None
    
    def save_chat_message(self, chat_id: str, role: str, content: str) -> bool:
        """Save a chat message to the database."""
        if not self.enabled or not self.connection:
            return False
        
        try:
            with self.connection.cursor() as cur:
                cur.execute("""
                    INSERT INTO chat_history (chat_id, message_role, message_content)
                    VALUES (%s, %s, %s);
                """, (chat_id, role, content))
            return True
        except Exception as e:
            print(f"Error saving chat message: {e}")
            return False
    
    def log_output(self, command_id: int, output: str, output_type: str = "text",
                   status: str = "success", execution_time_ms: int = None) -> bool:
        """Log command output to the database."""
        if not self.enabled or not self.connection or not command_id:
            return False
        
        try:
            with self.connection.cursor() as cur:
                cur.execute("""
                    INSERT INTO command_outputs (command_id, output, output_type, status, execution_time_ms)
                    VALUES (%s, %s, %s, %s, %s);
                """, (command_id, output, output_type, status, execution_time_ms))
            return True
        except Exception as e:
            print(f"Error logging output: {e}")
            return False
    
    def save_memory(self, session_id: str, key: str, value: str, memory_type: str = "context") -> bool:
        """Save or update agent memory."""
        if not self.enabled or not self.connection:
            return False
        
        try:
            with self.connection.cursor() as cur:
                cur.execute("""
                    INSERT INTO agent_memory (session_id, key, value, memory_type, updated_at)
                    VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (session_id, key) 
                    DO UPDATE SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP;
                """, (session_id, key, value, memory_type))
            return True
        except Exception as e:
            print(f"Error saving memory: {e}")
            return False
    
    def get_memory(self, session_id: str, key: str = None) -> Optional[Dict]:
        """Retrieve agent memory."""
        if not self.enabled or not self.connection:
            return None
        
        try:
            with self.connection.cursor(cursor_factory=RealDictCursor) as cur:
                if key:
                    cur.execute("""
                        SELECT * FROM agent_memory WHERE session_id = %s AND key = %s;
                    """, (session_id, key))
                    return cur.fetchone()
                else:
                    cur.execute("""
                        SELECT * FROM agent_memory WHERE session_id = %s;
                    """, (session_id,))
                    return cur.fetchall()
        except Exception as e:
            print(f"Error getting memory: {e}")
            return None
    
    def get_command_history(self, session_id: str = None, task_id: str = None, 
                            limit: int = 100) -> list:
        """Retrieve command history."""
        if not self.enabled or not self.connection:
            return []
        
        try:
            with self.connection.cursor(cursor_factory=RealDictCursor) as cur:
                query = "SELECT * FROM command_history"
                params = []
                conditions = []
                
                if session_id:
                    conditions.append("session_id = %s")
                    params.append(session_id)
                if task_id:
                    conditions.append("task_id = %s")
                    params.append(task_id)
                
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
                
                query += " ORDER BY created_at DESC LIMIT %s"
                params.append(limit)
                
                cur.execute(query, params)
                return cur.fetchall()
        except Exception as e:
            print(f"Error getting command history: {e}")
            return []
    
    def save_task(self, task_data: Dict) -> bool:
        """Save task to database."""
        if not self.enabled or not self.connection:
            return False
        
        try:
            with self.connection.cursor() as cur:
                cur.execute("""
                    INSERT INTO task_history (task_id, prompt, result, status, tool_count, step_count, 
                                            created_at, started_at, completed_at, error)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (task_id) 
                    DO UPDATE SET 
                        result = EXCLUDED.result,
                        status = EXCLUDED.status,
                        tool_count = EXCLUDED.tool_count,
                        step_count = EXCLUDED.step_count,
                        started_at = EXCLUDED.started_at,
                        completed_at = EXCLUDED.completed_at,
                        error = EXCLUDED.error;
                """, (
                    task_data.get("id"),
                    task_data.get("prompt"),
                    task_data.get("result"),
                    task_data.get("status"),
                    task_data.get("tool_count", 0),
                    task_data.get("step_count", 0),
                    task_data.get("created_at"),
                    task_data.get("started_at"),
                    task_data.get("completed_at"),
                    task_data.get("error")
                ))
            return True
        except Exception as e:
            print(f"Error saving task: {e}")
            return False
    
    def get_stats(self) -> Dict:
        """Get database statistics."""
        if not self.enabled or not self.connection:
            return {"enabled": False}
        
        try:
            with self.connection.cursor() as cur:
                stats = {"enabled": True}
                
                cur.execute("SELECT COUNT(*) FROM command_history;")
                stats["total_commands"] = cur.fetchone()[0]
                
                cur.execute("SELECT COUNT(*) FROM task_history;")
                stats["total_tasks"] = cur.fetchone()[0]
                
                cur.execute("SELECT COUNT(*) FROM agent_memory;")
                stats["total_memories"] = cur.fetchone()[0]
                
                cur.execute("SELECT COUNT(*) FROM chat_history;")
                stats["total_messages"] = cur.fetchone()[0]
                
                return stats
        except Exception as e:
            return {"enabled": True, "error": str(e)}
    
    def export_to_local(self, export_path: str = ".db_export") -> tuple[bool, str, Dict]:
        """Export all database data to local JSON files for backup/migration."""
        if not self.enabled or not self.connection:
            return False, "Not connected to database", {}
        
        import json
        from pathlib import Path
        
        try:
            export_dir = Path(export_path)
            export_dir.mkdir(exist_ok=True)
            
            exported = {}
            
            with self.connection.cursor(cursor_factory=RealDictCursor) as cur:
                # Export command_history
                cur.execute("SELECT * FROM command_history ORDER BY created_at;")
                commands = cur.fetchall()
                commands_data = []
                for row in commands:
                    row_dict = dict(row)
                    for k, v in row_dict.items():
                        if hasattr(v, 'isoformat'):
                            row_dict[k] = v.isoformat()
                    commands_data.append(row_dict)
                with open(export_dir / "command_history.json", "w") as f:
                    json.dump(commands_data, f, indent=2, default=str)
                exported["commands"] = len(commands_data)
                
                # Export command_outputs
                cur.execute("SELECT * FROM command_outputs ORDER BY created_at;")
                outputs = cur.fetchall()
                outputs_data = []
                for row in outputs:
                    row_dict = dict(row)
                    for k, v in row_dict.items():
                        if hasattr(v, 'isoformat'):
                            row_dict[k] = v.isoformat()
                    outputs_data.append(row_dict)
                with open(export_dir / "command_outputs.json", "w") as f:
                    json.dump(outputs_data, f, indent=2, default=str)
                exported["outputs"] = len(outputs_data)
                
                # Export agent_memory
                cur.execute("SELECT * FROM agent_memory ORDER BY created_at;")
                memories = cur.fetchall()
                memories_data = []
                for row in memories:
                    row_dict = dict(row)
                    for k, v in row_dict.items():
                        if hasattr(v, 'isoformat'):
                            row_dict[k] = v.isoformat()
                    memories_data.append(row_dict)
                with open(export_dir / "agent_memory.json", "w") as f:
                    json.dump(memories_data, f, indent=2, default=str)
                exported["memories"] = len(memories_data)
                
                # Export task_history
                cur.execute("SELECT * FROM task_history ORDER BY created_at;")
                tasks = cur.fetchall()
                tasks_data = []
                for row in tasks:
                    row_dict = dict(row)
                    for k, v in row_dict.items():
                        if hasattr(v, 'isoformat'):
                            row_dict[k] = v.isoformat()
                    tasks_data.append(row_dict)
                with open(export_dir / "task_history.json", "w") as f:
                    json.dump(tasks_data, f, indent=2, default=str)
                exported["tasks"] = len(tasks_data)
                
                # Export chat_history
                cur.execute("SELECT * FROM chat_history ORDER BY created_at;")
                chats = cur.fetchall()
                chats_data = []
                for row in chats:
                    row_dict = dict(row)
                    for k, v in row_dict.items():
                        if hasattr(v, 'isoformat'):
                            row_dict[k] = v.isoformat()
                    chats_data.append(row_dict)
                with open(export_dir / "chat_history.json", "w") as f:
                    json.dump(chats_data, f, indent=2, default=str)
                exported["messages"] = len(chats_data)
            
            # Save export metadata
            metadata = {
                "exported_at": datetime.now().isoformat(),
                "source": self.config.get("host", "unknown"),
                "counts": exported
            }
            with open(export_dir / "export_metadata.json", "w") as f:
                json.dump(metadata, f, indent=2)
            
            total = sum(exported.values())
            return True, f"Exported {total} records to {export_path}/", exported
            
        except Exception as e:
            return False, f"Export failed: {str(e)}", {}
    
    def import_from_local(self, import_path: str = ".db_export") -> tuple[bool, str, Dict]:
        """Import data from local JSON files back to database."""
        if not self.enabled or not self.connection:
            return False, "Not connected to database", {}
        
        import json
        from pathlib import Path
        
        try:
            import_dir = Path(import_path)
            if not import_dir.exists():
                return False, f"Import directory {import_path} not found", {}
            
            imported = {}
            
            with self.connection.cursor() as cur:
                # Import command_history
                cmd_file = import_dir / "command_history.json"
                if cmd_file.exists():
                    with open(cmd_file) as f:
                        commands = json.load(f)
                    for cmd in commands:
                        cur.execute("""
                            INSERT INTO command_history (session_id, task_id, command, command_type, tool_name, created_at)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT DO NOTHING;
                        """, (cmd.get("session_id"), cmd.get("task_id"), cmd.get("command"),
                              cmd.get("command_type"), cmd.get("tool_name"), cmd.get("created_at")))
                    imported["commands"] = len(commands)
                
                # Import agent_memory
                mem_file = import_dir / "agent_memory.json"
                if mem_file.exists():
                    with open(mem_file) as f:
                        memories = json.load(f)
                    for mem in memories:
                        cur.execute("""
                            INSERT INTO agent_memory (session_id, memory_type, key, value, metadata, created_at)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT DO NOTHING;
                        """, (mem.get("session_id"), mem.get("memory_type"), mem.get("key"),
                              mem.get("value"), json.dumps(mem.get("metadata")) if mem.get("metadata") else None,
                              mem.get("created_at")))
                    imported["memories"] = len(memories)
                
                # Import task_history
                task_file = import_dir / "task_history.json"
                if task_file.exists():
                    with open(task_file) as f:
                        tasks = json.load(f)
                    for task in tasks:
                        cur.execute("""
                            INSERT INTO task_history (task_id, session_id, prompt, status, result, error, 
                                                      step_count, tool_count, created_at, completed_at)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT DO NOTHING;
                        """, (task.get("task_id"), task.get("session_id"), task.get("prompt"),
                              task.get("status"), task.get("result"), task.get("error"),
                              task.get("step_count", 0), task.get("tool_count", 0),
                              task.get("created_at"), task.get("completed_at")))
                    imported["tasks"] = len(tasks)
                
                # Import chat_history
                chat_file = import_dir / "chat_history.json"
                if chat_file.exists():
                    with open(chat_file) as f:
                        chats = json.load(f)
                    for chat in chats:
                        # Support both DB export format and legacy format
                        chat_id = chat.get("chat_id") or chat.get("session_id") or "default"
                        role = chat.get("message_role") or chat.get("role") or "user"
                        content = chat.get("message_content") or chat.get("content") or ""
                        created_at = chat.get("created_at")
                        
                        if content:  # Only import if there's content
                            cur.execute("""
                                INSERT INTO chat_history (chat_id, message_role, message_content, created_at)
                                VALUES (%s, %s, %s, %s)
                                ON CONFLICT DO NOTHING;
                            """, (chat_id, role, content, created_at))
                    imported["messages"] = len(chats)
                
                self.connection.commit()
            
            total = sum(imported.values())
            return True, f"Imported {total} records from {import_path}/", imported
            
        except Exception as e:
            return False, f"Import failed: {str(e)}", {}


# Global database storage instance
db_storage = DatabaseStorage()

# Cloudflare Tunnel management
cloudflare_tunnel_process = None
cloudflare_tunnel_url = None

# Proxy configuration for agent tools
proxy_config = {
    "enabled": False,
    "type": "http",  # http, https, socks5
    "host": "",
    "port": "",
    "username": "",
    "password": "",
}

# Tools state management - enabled/disabled status for agent tools
# Defines all available tools with their metadata
TOOLS_REGISTRY = {
    # Reconnaissance Tools
    "nmap": {"name": "Nmap", "category": "recon", "description": "Network scanner for port/service discovery", "install_cmd": "apt install nmap", "binary": "nmap"},
    "dnsrecon": {"name": "DNSRecon", "category": "recon", "description": "DNS enumeration and reconnaissance", "install_cmd": "pip install dnsrecon", "binary": "dnsrecon"},
    "subfinder": {"name": "Subfinder", "category": "recon", "description": "Fast subdomain discovery", "install_cmd": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "binary": "subfinder"},
    "amass": {"name": "Amass", "category": "recon", "description": "In-depth attack surface mapping", "install_cmd": "go install github.com/owasp-amass/amass/v4/...@master", "binary": "amass"},
    "httpx": {"name": "HTTPX", "category": "recon", "description": "HTTP toolkit for probing web servers", "install_cmd": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", "binary": "httpx"},
    "whatweb": {"name": "WhatWeb", "category": "recon", "description": "Web technology fingerprinting", "install_cmd": "apt install whatweb", "binary": "whatweb"},
    
    # Vulnerability Scanning
    "nuclei": {"name": "Nuclei", "category": "vuln", "description": "Template-based vulnerability scanner", "install_cmd": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "binary": "nuclei"},
    "nikto": {"name": "Nikto", "category": "vuln", "description": "Web server vulnerability scanner", "install_cmd": "apt install nikto", "binary": "nikto"},
    "sqlmap": {"name": "SQLMap", "category": "vuln", "description": "Automated SQL injection tool", "install_cmd": "apt install sqlmap", "binary": "sqlmap"},
    "xsser": {"name": "XSSer", "category": "vuln", "description": "XSS vulnerability scanner", "install_cmd": "pip install xsser", "binary": "xsser"},
    "sslyze": {"name": "SSLyze", "category": "vuln", "description": "SSL/TLS configuration analyzer", "install_cmd": "pip install sslyze", "binary": "sslyze"},
    "testssl": {"name": "testssl.sh", "category": "vuln", "description": "TLS/SSL testing tool", "install_cmd": "git clone https://github.com/drwetter/testssl.sh.git", "binary": "testssl.sh"},
    
    # Content Discovery
    "gobuster": {"name": "Gobuster", "category": "discovery", "description": "Directory/DNS/vhost bruteforcing", "install_cmd": "go install github.com/OJ/gobuster/v3@latest", "binary": "gobuster"},
    "ffuf": {"name": "FFUF", "category": "discovery", "description": "Fast web fuzzer", "install_cmd": "go install github.com/ffuf/ffuf/v2@latest", "binary": "ffuf"},
    "dirb": {"name": "Dirb", "category": "discovery", "description": "Web content scanner", "install_cmd": "apt install dirb", "binary": "dirb"},
    
    # Web Application
    "wpscan": {"name": "WPScan", "category": "webapp", "description": "WordPress vulnerability scanner", "install_cmd": "gem install wpscan", "binary": "wpscan"},
    "curl": {"name": "cURL", "category": "webapp", "description": "HTTP request tool", "install_cmd": "apt install curl", "binary": "curl"},
    
    # Brute Force
    "hydra": {"name": "Hydra", "category": "bruteforce", "description": "Network login cracker", "install_cmd": "apt install hydra", "binary": "hydra"},
    "ncrack": {"name": "Ncrack", "category": "bruteforce", "description": "High-speed network authentication cracker", "install_cmd": "apt install ncrack", "binary": "ncrack"},
    
    # Exploitation
    "searchsploit": {"name": "SearchSploit", "category": "exploit", "description": "ExploitDB CLI search", "install_cmd": "apt install exploitdb", "binary": "searchsploit"},
    
    # Browser Automation  
    "playwright": {"name": "Playwright", "category": "browser", "description": "Browser automation for testing", "install_cmd": "pip install playwright && playwright install", "binary": None},
    
    # Infrastructure
    "cloudflared": {"name": "Cloudflared", "category": "infra", "description": "Cloudflare Tunnel client", "install_cmd": "See cloudflare docs", "binary": "cloudflared"},
}

# Tool enabled state (persisted in memory, could be saved to file/db)
tools_enabled_state = {tool: True for tool in TOOLS_REGISTRY}


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
    # Report fields
    report_html: Optional[str] = None  # Generated HTML report
    report_markdown: Optional[str] = None  # Generated Markdown report
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


app = FastAPI(title="Pentest.Systems Assistant")
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

# Provider settings storage with file persistence
PROVIDER_SETTINGS_FILE = os.path.join(os.path.dirname(__file__), ".provider_settings.json")
provider_settings_store: Dict[str, Any] = {
    "provider": "deepseek",
    "model": "deepseek-chat",
}

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

# Database storage settings with file persistence
DATABASE_SETTINGS_FILE = os.path.join(os.path.dirname(__file__), ".database_settings.json")
database_settings_store: Dict[str, Any] = {
    "enabled": False,
    "connection_type": "local",  # local, supabase
    "host": "localhost",
    "port": 5432,
    "database": "owasp_agent",
    "user": "postgres",
    "password": "",
    "ssl_mode": "prefer",
    "auto_connect": False,
}

def load_database_settings_from_file():
    """Load database settings from file."""
    global database_settings_store
    if os.path.exists(DATABASE_SETTINGS_FILE):
        try:
            with open(DATABASE_SETTINGS_FILE, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                database_settings_store.update(loaded)
        except Exception as e:
            print(f"Error loading database settings: {e}")

def save_database_settings_to_file():
    """Save database settings to file."""
    try:
        with open(DATABASE_SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(database_settings_store, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving database settings: {e}")
        return False

def initialize_database_connection():
    """Initialize database connection from saved settings if auto-connect is enabled."""
    global db_storage
    if database_settings_store.get("auto_connect") and database_settings_store.get("enabled"):
        db_storage.configure(database_settings_store)
        success, msg = db_storage.connect()
        if success:
            db_storage.initialize_tables()
            print(f"Database connected: {msg}")
        else:
            print(f"Database connection failed: {msg}")

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

def import_export_to_local_chats():
    """Import chat history from .db_export to local chats_store."""
    global chats_store
    from pathlib import Path
    
    export_dir = Path(".db_export")
    chat_file = export_dir / "chat_history.json"
    
    if not chat_file.exists():
        return False, "No exported chat history found in .db_export/", {}
    
    try:
        with open(chat_file) as f:
            exported_chats = json.load(f)
        
        if not exported_chats or len(exported_chats) == 0:
            # Check if there's command history we can import instead
            cmd_file = export_dir / "command_history.json"
            if cmd_file.exists():
                with open(cmd_file) as f:
                    commands = json.load(f)
                if commands:
                    # Convert command history to chat messages
                    imported = {"messages": 0, "chats": 0}
                    for cmd in commands:
                        chat_id = cmd.get("session_id", "default")
                        if chat_id.startswith("session_"):
                            chat_id = "default"
                        
                        if chat_id not in chats_store:
                            chats_store[chat_id] = {
                                "name": "Main Chat" if chat_id == "default" else f"Chat {chat_id[:8]}",
                                "messages": [],
                                "created_at": datetime.now().isoformat(),
                                "updated_at": datetime.now().isoformat()
                            }
                            imported["chats"] += 1
                        
                        # Add command as user message
                        content = cmd.get("command", "")
                        if content:
                            existing = {m.get("content") for m in chats_store[chat_id].get("messages", [])}
                            if content not in existing:
                                chats_store[chat_id]["messages"].append({
                                    "type": "user",
                                    "content": content,
                                    "timestamp": cmd.get("created_at", datetime.now().isoformat())
                                })
                                imported["messages"] += 1
                    
                    save_chats_to_file()
                    return True, f"Imported {imported['messages']} commands as messages", imported
            
            return False, "No chat messages found in export (chat_history.json is empty). Command history was exported but not chat messages.", {}
        
        imported = {"messages": 0, "chats": 0}
        
        # Group messages by chat_id
        chat_messages = {}
        for msg in exported_chats:
            # Handle different field names from different export sources:
            # DB export uses: chat_id, message_role, message_content
            # Old format might use: session_id, role, content
            chat_id = msg.get("chat_id") or msg.get("session_id", "default")
            
            # Normalize session IDs that look like timestamps to 'default'
            if chat_id and chat_id.startswith("session_"):
                chat_id = "default"
            if not chat_id:
                chat_id = "default"
            
            if chat_id not in chat_messages:
                chat_messages[chat_id] = []
            
            # Handle different field names for message type/role
            msg_type = msg.get("message_role") or msg.get("role") or msg.get("type", "user")
            # Normalize role names: 'assistant' stays, 'agent' -> 'assistant', 'user' stays
            if msg_type == "agent":
                msg_type = "assistant"
            
            # Handle different field names for content
            content = msg.get("message_content") or msg.get("content", "")
            
            chat_messages[chat_id].append({
                "type": msg_type,
                "content": content,
                "timestamp": msg.get("created_at") or msg.get("timestamp", datetime.now().isoformat())
            })
            imported["messages"] += 1
        
        # Merge into chats_store
        for chat_id, messages in chat_messages.items():
            if chat_id not in chats_store:
                chats_store[chat_id] = {
                    "name": f"Imported Chat {chat_id[:8]}" if chat_id != "default" else "Main Chat",
                    "messages": [],
                    "created_at": datetime.now().isoformat(),
                    "updated_at": datetime.now().isoformat()
                }
                imported["chats"] += 1
            
            # Add messages (avoid duplicates by checking content)
            existing_content = {m.get("content") for m in chats_store[chat_id].get("messages", [])}
            added = 0
            for msg in messages:
                content = msg.get("content", "")
                if content and content not in existing_content:
                    chats_store[chat_id]["messages"].append(msg)
                    existing_content.add(content)
                    added += 1
            
            if added > 0:
                chats_store[chat_id]["updated_at"] = datetime.now().isoformat()
        
        save_chats_to_file()
        total_msgs = sum(len(msgs) for msgs in chat_messages.values())
        return True, f"Imported {total_msgs} messages to {len(chat_messages)} chats", imported
        
    except Exception as e:
        import traceback
        print(f"Import error: {traceback.format_exc()}")
        return False, f"Import failed: {str(e)}", {}

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
        
        # Check if a report was generated and store it
        if is_report_mode_enabled():
            try:
                html_report = generate_html_report()
                md_report = generate_markdown_report()
                if html_report and '<!DOCTYPE html>' in html_report:
                    task_store[task_id].report_html = html_report
                    task_store[task_id].report_markdown = md_report
            except Exception as report_err:
                pass  # Report generation failed, but task still completed
        
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
        "DEEPSEEK_API_KEY": "",
        "OPENROUTER_API_KEY": "",
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


def load_provider_settings_from_file():
    """Load provider settings from file."""
    global provider_settings_store
    
    if os.path.exists(PROVIDER_SETTINGS_FILE):
        try:
            with open(PROVIDER_SETTINGS_FILE, 'r') as f:
                saved_settings = json.load(f)
                provider_settings_store.update(saved_settings)
        except Exception as e:
            print(f"Error loading provider settings: {e}")
    
    # Check environment variables (override file)
    if os.getenv("LLM_PROVIDER"):
        provider_settings_store["provider"] = os.getenv("LLM_PROVIDER")
    if os.getenv("LLM_MODEL"):
        provider_settings_store["model"] = os.getenv("LLM_MODEL")
    if os.getenv("DEEPSEEK_API_KEY"):
        provider_settings_store["deepseek_api_key"] = os.getenv("DEEPSEEK_API_KEY")
    if os.getenv("OPENROUTER_API_KEY"):
        provider_settings_store["openrouter_api_key"] = os.getenv("OPENROUTER_API_KEY")
    
    # Apply to runtime settings
    update_runtime_settings(
        llm_provider=provider_settings_store.get("provider", "deepseek"),
        selected_model=provider_settings_store.get("model"),
        deepseek_api_key=provider_settings_store.get("deepseek_api_key"),
        openrouter_api_key=provider_settings_store.get("openrouter_api_key"),
    )
    
    print(f"[Provider] Loaded settings: provider={provider_settings_store.get('provider')}, model={provider_settings_store.get('model')}")


def save_provider_settings_to_file():
    """Save provider settings to file."""
    try:
        # Don't save API keys to this file (they should be in .api_keys.json or env)
        settings_to_save = {
            "provider": provider_settings_store.get("provider", "deepseek"),
            "model": provider_settings_store.get("model", "deepseek-chat"),
        }
        with open(PROVIDER_SETTINGS_FILE, 'w') as f:
            json.dump(settings_to_save, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving provider settings: {e}")
        return False


class FileUpload(BaseModel):
    session_id: str
    filename: str
    content: str  # Base64 encoded content

class APIKeyUpdate(BaseModel):
    service: str
    api_key: str

class ProviderUpdate(BaseModel):
    provider: str  # "deepseek" or "openrouter"
    model: str

class ScheduledTaskCreate(BaseModel):
    prompt: str
    schedule_time: str  # ISO format datetime
    recurring: bool = False
    interval_minutes: Optional[int] = None
    name: Optional[str] = None

class ChatCreate(BaseModel):
    name: str

class ChatMessage(BaseModel):
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
            # Load provider settings (before building agent)
            load_provider_settings_from_file()
            # Load chat history
            load_chats_from_file()
            # Load scheduled tasks
            load_scheduled_tasks_from_file()
            # Load custom context
            load_custom_context()
            # Load task chains
            load_chains_from_file()
            # Load database settings
            load_database_settings_from_file()
            # Initialize database connection if enabled
            initialize_database_connection()
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
    settings = get_settings()
    components = {
        "agent": agent is not None,
        "scheduler": scheduler_thread is not None and scheduler_thread.is_alive() if 'scheduler_thread' in globals() else False,
        "executor": executor is not None,
    }
    
    # Check API key configuration for current provider
    current_provider = provider_settings_store.get("provider", "deepseek")
    if current_provider == "openrouter":
        api_configured = bool(provider_settings_store.get("openrouter_api_key") or os.getenv("OPENROUTER_API_KEY"))
    else:
        api_configured = bool(provider_settings_store.get("deepseek_api_key") or os.getenv("DEEPSEEK_API_KEY"))
    
    return JSONResponse({
        "status": "healthy" if all(components.values()) and api_configured else "degraded",
        "timestamp": datetime.now().isoformat(),
        "version": "0.3.0",
        "components": components,
        "api_configured": api_configured,
        "llm_provider": current_provider,
        "llm_model": provider_settings_store.get("model", "deepseek-chat"),
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

# ============== PROVIDER SETTINGS ENDPOINTS ==============

@app.get("/api/providers")
async def get_providers():
    """Get list of available providers with their models."""
    providers = []
    for provider_id, config in PROVIDER_CONFIGS.items():
        providers.append({
            "id": provider_id,
            "name": config["name"],
            "models": config["models"],
            "default_model": config["default_model"],
        })
    return JSONResponse(providers)

@app.get("/api/provider/settings")
async def get_provider_settings():
    """Get current provider settings."""
    current_provider = provider_settings_store.get("provider", "deepseek")
    current_model = provider_settings_store.get("model", "deepseek-chat")
    
    has_deepseek = bool(provider_settings_store.get("deepseek_api_key") or os.getenv("DEEPSEEK_API_KEY"))
    has_openrouter = bool(provider_settings_store.get("openrouter_api_key") or os.getenv("OPENROUTER_API_KEY"))
    
    return JSONResponse({
        "provider": current_provider,
        "model": current_model,
        "has_deepseek_key": has_deepseek,
        "has_openrouter_key": has_openrouter,
    })

@app.post("/api/provider/settings")
async def update_provider_settings(update: ProviderUpdate):
    """Update provider settings and reinitialize agent."""
    global agent, provider_settings_store
    
    # Update stored settings
    provider_settings_store["provider"] = update.provider
    provider_settings_store["model"] = update.model
    
    # Apply to runtime settings
    update_runtime_settings(
        llm_provider=update.provider,
        selected_model=update.model,
    )
    
    # Save to file
    save_provider_settings_to_file()
    
    # Rebuild the agent with new settings
    try:
        agent = build_owasp_agent()
        return JSONResponse({
            "success": True,
            "provider": update.provider,
            "model": update.model,
            "message": f"Switched to {PROVIDER_CONFIGS[update.provider]['name']} with model {update.model}"
        })
    except Exception as e:
        return JSONResponse({
            "success": False,
            "error": str(e)
        }, status_code=500)

@app.post("/api/provider/key")
async def set_provider_api_key(data: Dict[str, str]):
    """Set API key for a specific provider."""
    global provider_settings_store
    
    provider = data.get("provider")
    api_key = data.get("api_key", "")
    
    if provider not in ["deepseek", "openrouter"]:
        return JSONResponse({"error": "Invalid provider"}, status_code=400)
    
    key_name = f"{provider}_api_key"
    provider_settings_store[key_name] = api_key
    
    # Also set as environment variable
    env_key = f"{provider.upper()}_API_KEY"
    if api_key:
        os.environ[env_key] = api_key
    elif env_key in os.environ:
        del os.environ[env_key]
    
    # Update runtime settings
    update_runtime_settings(**{key_name: api_key})
    
    # Rebuild agent if this is the current provider
    if provider_settings_store.get("provider") == provider:
        try:
            global agent
            agent = build_owasp_agent()
        except Exception as e:
            print(f"Error rebuilding agent: {e}")
    
    return JSONResponse({
        "success": True,
        "provider": provider,
        "has_key": bool(api_key)
    })

@app.get("/api/provider/key/{provider}")
async def get_provider_api_key_status(provider: str):
    """Check if a provider has an API key configured."""
    if provider not in ["deepseek", "openrouter"]:
        return JSONResponse({"error": "Invalid provider"}, status_code=400)
    
    key_name = f"{provider}_api_key"
    env_key = f"{provider.upper()}_API_KEY"
    
    has_key = bool(
        provider_settings_store.get(key_name) or 
        os.getenv(env_key)
    )
    
    # Mask the key if present
    stored_key = provider_settings_store.get(key_name) or os.getenv(env_key, "")
    masked = ""
    if stored_key:
        masked = stored_key[:4] + "..." + stored_key[-4:] if len(stored_key) > 8 else "****"
    
    return JSONResponse({
        "provider": provider,
        "has_key": has_key,
        "masked_key": masked
    })

# ============== DATABASE STORAGE ENDPOINTS ==============

class DatabaseConfig(BaseModel):
    enabled: bool = False
    connection_type: str = "local"  # local, supabase
    host: str = "localhost"
    port: int = 5432
    database: str = "owasp_agent"
    user: str = "postgres"
    password: str = ""
    ssl_mode: str = "prefer"
    auto_connect: bool = False

@app.get("/api/database/settings")
async def get_database_settings():
    """Get current database settings (password masked)."""
    settings = database_settings_store.copy()
    if settings.get("password"):
        settings["password"] = "••••••••"
        settings["has_password"] = True
    else:
        settings["has_password"] = False
    settings["connected"] = db_storage.enabled
    settings["psycopg2_available"] = HAS_PSYCOPG2
    return JSONResponse(settings)

@app.post("/api/database/settings")
async def update_database_settings(config: DatabaseConfig):
    """Update database settings."""
    global database_settings_store
    
    # Update settings
    database_settings_store["enabled"] = config.enabled
    database_settings_store["connection_type"] = config.connection_type
    database_settings_store["host"] = config.host
    database_settings_store["port"] = config.port
    database_settings_store["database"] = config.database
    database_settings_store["user"] = config.user
    database_settings_store["ssl_mode"] = config.ssl_mode
    database_settings_store["auto_connect"] = config.auto_connect
    
    # Only update password if provided (not masked placeholder)
    if config.password and config.password != "••••••••":
        database_settings_store["password"] = config.password
    
    # Save to file
    save_database_settings_to_file()
    
    return JSONResponse({
        "success": True,
        "message": "Database settings updated"
    })

@app.post("/api/database/test")
async def test_database_connection():
    """Test database connection without persisting."""
    if not HAS_PSYCOPG2:
        return JSONResponse({
            "success": False,
            "error": "psycopg2 not installed",
            "install_hint": "pip install psycopg2-binary",
            "message": "Database driver not found. Install with: pip install psycopg2-binary"
        })
    
    # Configure with current settings
    db_storage.configure(database_settings_store)
    success, message = db_storage.test_connection()
    
    return JSONResponse({
        "success": success,
        "message": message
    })

@app.post("/api/database/connect")
async def connect_database():
    """Connect to the database."""
    if not HAS_PSYCOPG2:
        return JSONResponse({
            "success": False,
            "error": "psycopg2 not installed",
            "install_hint": "pip install psycopg2-binary",
            "message": "Database driver not found. Install with: pip install psycopg2-binary"
        })
    
    # Configure with current settings
    db_storage.configure(database_settings_store)
    success, message = db_storage.connect()
    
    if success:
        database_settings_store["enabled"] = True
        save_database_settings_to_file()
    
    return JSONResponse({
        "success": success,
        "message": message
    })

@app.post("/api/database/disconnect")
async def disconnect_database():
    """Disconnect from the database."""
    db_storage.disconnect()
    database_settings_store["enabled"] = False
    save_database_settings_to_file()
    
    return JSONResponse({
        "success": True,
        "message": "Disconnected from database"
    })

@app.post("/api/database/setup")
async def setup_database():
    """Initialize database tables."""
    if not db_storage.enabled:
        return JSONResponse({
            "success": False,
            "error": "Not connected to database"
        })
    
    success, message = db_storage.initialize_tables()
    
    return JSONResponse({
        "success": success,
        "message": message
    })

@app.get("/api/database/stats")
async def get_database_stats():
    """Get database statistics."""
    stats = db_storage.get_stats()
    return JSONResponse(stats)

@app.post("/api/database/export")
async def export_database_to_local():
    """Export all database data to local JSON files."""
    success, message, counts = db_storage.export_to_local()
    return JSONResponse({
        "success": success,
        "message": message,
        "counts": counts
    })

@app.post("/api/database/import")
async def import_database_from_local():
    """Import data from local JSON files to database."""
    success, message, counts = db_storage.import_from_local()
    return JSONResponse({
        "success": success,
        "message": message,
        "counts": counts
    })

@app.get("/api/database/export/check")
async def check_local_export():
    """Check if local export exists and get its metadata."""
    from pathlib import Path
    import json
    
    export_dir = Path(".db_export")
    if not export_dir.exists():
        return JSONResponse({"exists": False})
    
    metadata_file = export_dir / "export_metadata.json"
    if metadata_file.exists():
        with open(metadata_file) as f:
            metadata = json.load(f)
        return JSONResponse({"exists": True, "metadata": metadata})
    
    return JSONResponse({"exists": True, "metadata": None})

@app.post("/api/database/import-to-local")
async def import_export_to_local():
    """Import exported chat data to local file storage (when DB disconnected)."""
    success, message, counts = import_export_to_local_chats()
    return JSONResponse({
        "success": success,
        "message": message,
        "counts": counts
    })

@app.get("/api/database/export/debug")
async def debug_export():
    """Debug endpoint to see export file contents."""
    from pathlib import Path
    import json
    
    export_dir = Path(".db_export")
    chat_file = export_dir / "chat_history.json"
    
    if not chat_file.exists():
        return JSONResponse({"error": "No export file found", "path": str(chat_file)})
    
    try:
        with open(chat_file) as f:
            data = json.load(f)
        
        # Show sample and structure
        sample = data[:5] if len(data) > 5 else data
        fields = list(data[0].keys()) if data else []
        
        return JSONResponse({
            "total_records": len(data),
            "fields": fields,
            "sample": sample
        })
    except Exception as e:
        return JSONResponse({"error": str(e)})

# ============== CLOUDFLARE TUNNEL ENDPOINTS ==============

@app.get("/api/tunnel/status")
async def get_tunnel_status():
    """Get current Cloudflare Tunnel status."""
    global cloudflare_tunnel_process, cloudflare_tunnel_url
    
    is_running = cloudflare_tunnel_process is not None and cloudflare_tunnel_process.poll() is None
    
    return JSONResponse({
        "running": is_running,
        "url": cloudflare_tunnel_url if is_running else None
    })

@app.post("/api/tunnel/start")
async def start_tunnel():
    """Start Cloudflare Tunnel using cloudflared (trycloudflare.com)."""
    global cloudflare_tunnel_process, cloudflare_tunnel_url
    
    # Check if already running
    if cloudflare_tunnel_process is not None and cloudflare_tunnel_process.poll() is None:
        return JSONResponse({
            "success": True,
            "message": "Tunnel already running",
            "url": cloudflare_tunnel_url
        })
    
    try:
        # Check if cloudflared is installed
        check_result = subprocess.run(
            ["cloudflared", "--version"],
            capture_output=True,
            text=True
        )
        if check_result.returncode != 0:
            return JSONResponse({
                "success": False,
                "message": "cloudflared not installed. Install from: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/",
                "url": None
            })
        
        # Start cloudflared tunnel
        # Using quick tunnel (trycloudflare.com) - no account needed
        cloudflare_tunnel_process = subprocess.Popen(
            ["cloudflared", "tunnel", "--url", "http://localhost:8000"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait and capture the URL from stderr (cloudflared outputs there)
        cloudflare_tunnel_url = None
        start_time = time.time()
        timeout = 30  # Wait up to 30 seconds for URL
        
        while time.time() - start_time < timeout:
            # Read stderr line by line (non-blocking approach)
            if cloudflare_tunnel_process.stderr:
                line = cloudflare_tunnel_process.stderr.readline()
                if line:
                    # Look for the URL in the output
                    # Pattern: https://xxxxx.trycloudflare.com
                    url_match = re.search(r'(https://[a-zA-Z0-9-]+\.trycloudflare\.com)', line)
                    if url_match:
                        cloudflare_tunnel_url = url_match.group(1)
                        break
            
            # Small sleep to avoid CPU spin
            await asyncio.sleep(0.1)
        
        if cloudflare_tunnel_url:
            return JSONResponse({
                "success": True,
                "message": "Tunnel started successfully",
                "url": cloudflare_tunnel_url
            })
        else:
            # If we didn't get URL but process is still running, it might still work
            if cloudflare_tunnel_process.poll() is None:
                return JSONResponse({
                    "success": True,
                    "message": "Tunnel starting... URL will appear shortly",
                    "url": None
                })
            else:
                # Process died
                stderr_output = cloudflare_tunnel_process.stderr.read() if cloudflare_tunnel_process.stderr else ""
                cloudflare_tunnel_process = None
                return JSONResponse({
                    "success": False,
                    "message": f"Tunnel failed to start: {stderr_output[:500]}",
                    "url": None
                })
                
    except FileNotFoundError:
        return JSONResponse({
            "success": False,
            "message": "cloudflared not found. Install from: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/",
            "url": None
        })
    except Exception as e:
        return JSONResponse({
            "success": False,
            "message": f"Error starting tunnel: {str(e)}",
            "url": None
        })

@app.post("/api/tunnel/stop")
async def stop_tunnel():
    """Stop Cloudflare Tunnel."""
    global cloudflare_tunnel_process, cloudflare_tunnel_url
    
    if cloudflare_tunnel_process is None:
        return JSONResponse({
            "success": True,
            "message": "No tunnel running"
        })
    
    try:
        cloudflare_tunnel_process.terminate()
        cloudflare_tunnel_process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        cloudflare_tunnel_process.kill()
    except Exception as e:
        pass
    
    cloudflare_tunnel_process = None
    cloudflare_tunnel_url = None
    
    return JSONResponse({
        "success": True,
        "message": "Tunnel stopped"
    })

# ============== PROXY CONFIGURATION ENDPOINTS ==============

@app.get("/api/proxy/status")
async def get_proxy_status():
    """Get current proxy configuration."""
    global proxy_config
    from app.tools.pentest_tools import get_proxy_url
    
    return JSONResponse({
        "enabled": proxy_config.get("enabled", False),
        "type": proxy_config.get("type", "http"),
        "host": proxy_config.get("host", ""),
        "port": proxy_config.get("port", ""),
        "username": proxy_config.get("username", ""),
        "has_password": bool(proxy_config.get("password", "")),
        "proxy_url": get_proxy_url() if proxy_config.get("enabled") else None
    })

@app.post("/api/proxy/config")
async def save_proxy_config(request: Request):
    """Save proxy configuration."""
    global proxy_config
    from app.tools.pentest_tools import set_proxy_config
    
    try:
        data = await request.json()
        
        # Update config (keep enabled state separate from config save)
        proxy_config["type"] = data.get("type", "http")
        proxy_config["host"] = data.get("host", "")
        proxy_config["port"] = data.get("port", "")
        proxy_config["username"] = data.get("username", "")
        
        # Only update password if provided (non-empty)
        if "password" in data and data["password"]:
            proxy_config["password"] = data["password"]
        
        # Sync with pentest_tools module
        set_proxy_config(proxy_config)
        
        return JSONResponse({
            "success": True,
            "message": "Proxy configuration saved"
        })
    except Exception as e:
        return JSONResponse({
            "success": False,
            "message": f"Error saving proxy config: {str(e)}"
        })

@app.post("/api/proxy/toggle")
async def toggle_proxy(request: Request):
    """Enable or disable proxy."""
    global proxy_config
    from app.tools.pentest_tools import set_proxy_config, get_proxy_url
    
    try:
        data = await request.json()
        enabled = data.get("enabled", False)
        
        # Validate that we have host configured before enabling
        if enabled and not proxy_config.get("host"):
            return JSONResponse({
                "success": False,
                "message": "Cannot enable proxy: Host not configured"
            })
        
        proxy_config["enabled"] = enabled
        
        # Sync with pentest_tools module
        set_proxy_config(proxy_config)
        
        return JSONResponse({
            "success": True,
            "enabled": enabled,
            "proxy_url": get_proxy_url() if enabled else None,
            "message": f"Proxy {'enabled' if enabled else 'disabled'}"
        })
    except Exception as e:
        return JSONResponse({
            "success": False,
            "message": f"Error toggling proxy: {str(e)}"
        })

@app.post("/api/proxy/test")
async def test_proxy():
    """Test proxy connection by checking IP via ifconfig.io."""
    global proxy_config
    from app.tools.pentest_tools import get_proxy_url
    import subprocess
    import shutil
    
    if not shutil.which("curl"):
        return JSONResponse({
            "success": False,
            "message": "curl not installed",
            "ip": None
        })
    
    proxy_url = get_proxy_url()
    
    try:
        # Build curl command
        cmd = ["curl", "-sS", "--max-time", "10", "https://ifconfig.io/ip"]
        
        if proxy_url:
            cmd.insert(1, "-x")
            cmd.insert(2, proxy_url)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            ip = result.stdout.strip()
            return JSONResponse({
                "success": True,
                "message": f"Connection successful",
                "ip": ip,
                "using_proxy": bool(proxy_url),
                "proxy_url": proxy_url
            })
        else:
            return JSONResponse({
                "success": False,
                "message": f"Request failed: {result.stderr}",
                "ip": None
            })
    except subprocess.TimeoutExpired:
        return JSONResponse({
            "success": False,
            "message": "Connection timed out - proxy may be unreachable",
            "ip": None
        })
    except Exception as e:
        return JSONResponse({
            "success": False,
            "message": f"Error: {str(e)}",
            "ip": None
        })

# ============== TOOLS MANAGEMENT ENDPOINTS ==============

@app.get("/api/tools/list")
async def get_tools_list():
    """Get list of all tools with their status."""
    tools_list = []
    for tool_id, tool_info in TOOLS_REGISTRY.items():
        # Check if tool is installed using the shared binary finder
        binary = tool_info.get("binary")
        installed = False
        binary_path = None
        if binary:
            binary_path = _find_binary_path(binary)
            installed = binary_path is not None
        elif tool_id == "playwright":
            try:
                import playwright
                installed = True
            except ImportError:
                installed = False
        
        tools_list.append({
            "id": tool_id,
            "name": tool_info["name"],
            "category": tool_info["category"],
            "description": tool_info["description"],
            "install_cmd": tool_info["install_cmd"],
            "installed": installed,
            "path": binary_path,
            "enabled": tools_enabled_state.get(tool_id, True),
        })
    
    # Group by category
    categories = {}
    for tool in tools_list:
        cat = tool["category"]
        if cat not in categories:
            categories[cat] = {
                "recon": "🔍 Reconnaissance",
                "vuln": "🛡️ Vulnerability Scanning",
                "discovery": "📂 Content Discovery",
                "webapp": "🌐 Web Application",
                "bruteforce": "🔓 Brute Force",
                "exploit": "💥 Exploitation",
                "browser": "🖥️ Browser Automation",
                "infra": "⚙️ Infrastructure",
            }.get(cat, cat)
        
    return JSONResponse({
        "tools": tools_list,
        "categories": {
            "recon": "🔍 Reconnaissance",
            "vuln": "🛡️ Vulnerability Scanning", 
            "discovery": "📂 Content Discovery",
            "webapp": "🌐 Web Application",
            "bruteforce": "🔓 Brute Force",
            "exploit": "💥 Exploitation",
            "browser": "🖥️ Browser Automation",
            "infra": "⚙️ Infrastructure",
        }
    })


@app.post("/api/tools/toggle/{tool_id}")
async def toggle_tool(tool_id: str, request: Request):
    """Enable or disable a tool."""
    global tools_enabled_state
    
    if tool_id not in TOOLS_REGISTRY:
        return JSONResponse({
            "success": False,
            "message": f"Unknown tool: {tool_id}"
        }, status_code=404)
    
    data = await request.json()
    enabled = data.get("enabled", True)
    
    tools_enabled_state[tool_id] = enabled
    
    return JSONResponse({
        "success": True,
        "tool_id": tool_id,
        "enabled": enabled,
        "message": f"{TOOLS_REGISTRY[tool_id]['name']} {'enabled' if enabled else 'disabled'}"
    })


@app.post("/api/tools/install/{tool_id}")
async def install_tool(tool_id: str):
    """Install a tool (runs installation command)."""
    import subprocess
    
    if tool_id not in TOOLS_REGISTRY:
        return JSONResponse({
            "success": False,
            "message": f"Unknown tool: {tool_id}"
        }, status_code=404)
    
    tool_info = TOOLS_REGISTRY[tool_id]
    install_cmd = tool_info.get("install_cmd", "")
    
    if not install_cmd:
        return JSONResponse({
            "success": False,
            "message": f"No installation command defined for {tool_info['name']}"
        })
    
    # Special handling for go install commands
    if install_cmd.startswith("go install"):
        try:
            result = subprocess.run(
                install_cmd.split(),
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode == 0:
                # For nuclei, also download templates after installation
                extra_msg = ""
                if tool_id == "nuclei":
                    nuclei_path = _find_binary_path("nuclei")
                    if nuclei_path:
                        try:
                            template_result = subprocess.run(
                                [nuclei_path, "-update-templates"],
                                capture_output=True,
                                text=True,
                                timeout=300
                            )
                            if template_result.returncode == 0:
                                extra_msg = "\nNuclei templates also downloaded successfully."
                            else:
                                extra_msg = "\nNote: Templates download may have had issues. Run 'nuclei -update-templates' manually."
                        except:
                            extra_msg = "\nNote: Please run 'nuclei -update-templates' to download templates."
                
                return JSONResponse({
                    "success": True,
                    "message": f"{tool_info['name']} installed successfully{extra_msg}",
                    "output": result.stdout
                })
            else:
                return JSONResponse({
                    "success": False,
                    "message": f"Installation failed",
                    "error": result.stderr
                })
        except subprocess.TimeoutExpired:
            return JSONResponse({
                "success": False,
                "message": "Installation timed out"
            })
        except Exception as e:
            return JSONResponse({
                "success": False,
                "message": f"Error: {str(e)}"
            })
    
    # For pip install commands
    elif install_cmd.startswith("pip install"):
        try:
            result = subprocess.run(
                install_cmd.split(),
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                return JSONResponse({
                    "success": True,
                    "message": f"{tool_info['name']} installed successfully"
                })
            else:
                return JSONResponse({
                    "success": False,
                    "message": f"Installation failed: {result.stderr}"
                })
        except Exception as e:
            return JSONResponse({
                "success": False,
                "message": f"Error: {str(e)}"
            })
    
    # For other commands, return the command for user to run manually
    return JSONResponse({
        "success": False,
        "message": f"Manual installation required",
        "install_cmd": install_cmd,
        "instructions": f"Run this command to install {tool_info['name']}: {install_cmd}"
    })


def _find_binary_path(binary_name: str) -> str | None:
    """Find binary path, checking system PATH and Go installation directories."""
    import shutil
    import os
    import glob
    
    # First check standard PATH
    path = shutil.which(binary_name)
    if path:
        return path
    
    # Check Go bin directories for Go-installed tools
    go_paths = [
        os.path.expanduser('~/go/bin'),
        '/root/go/bin',
        '/usr/local/go/bin',
    ]
    
    # Also check GOPATH/bin and GOBIN if set
    gopath = os.environ.get('GOPATH')
    if gopath:
        go_paths.insert(0, os.path.join(gopath, 'bin'))
    
    gobin = os.environ.get('GOBIN')
    if gobin:
        go_paths.insert(0, gobin)
    
    # Expand /home/*/go/bin pattern using glob
    home_go_bins = glob.glob('/home/*/go/bin')
    go_paths.extend(home_go_bins)
    
    for go_path in go_paths:
        tool_path = os.path.join(go_path, binary_name)
        if os.path.isfile(tool_path) and os.access(tool_path, os.X_OK):
            return tool_path
    
    return None


@app.get("/api/tools/check/{tool_id}")
async def check_tool_installed(tool_id: str):
    """Check if a specific tool is installed."""
    import shutil
    
    if tool_id not in TOOLS_REGISTRY:
        return JSONResponse({
            "success": False,
            "installed": False,
            "message": f"Unknown tool: {tool_id}"
        }, status_code=404)
    
    tool_info = TOOLS_REGISTRY[tool_id]
    binary = tool_info.get("binary")
    
    installed = False
    version = None
    binary_path = None
    
    if binary:
        binary_path = _find_binary_path(binary)
        installed = binary_path is not None
        if installed:
            # Try to get version
            try:
                import subprocess
                result = subprocess.run(
                    [binary_path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                version = result.stdout.strip().split("\n")[0][:100] if result.returncode == 0 else None
            except:
                pass
    elif tool_id == "playwright":
        try:
            import playwright
            installed = True
            version = getattr(playwright, "__version__", "installed")
        except ImportError:
            installed = False
    
    return JSONResponse({
        "success": True,
        "tool_id": tool_id,
        "name": tool_info["name"],
        "installed": installed,
        "version": version,
        "path": binary_path,
        "enabled": tools_enabled_state.get(tool_id, True)
    })


@app.get("/api/database/history")
async def get_command_history(session_id: Optional[str] = None, 
                               task_id: Optional[str] = None,
                               limit: int = 100):
    """Get command history from database."""
    history = db_storage.get_command_history(session_id, task_id, limit)
    return JSONResponse({"history": history})

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
    
    # Also save to database if connected
    db_storage.save_chat_message(chat_id, message.type, message.content)
    
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

# Active session tracking for cancel requests
active_sessions: Dict[str, bool] = {}  # session_id/task_id -> cancelled flag

@app.post("/api/cancel")
async def cancel_activity_session(request: dict):
    """Cancel an active activity session/task by marking it as cancelled.
    
    This is used by the frontend Activity Monitor to stop running tasks.
    """
    session_id = request.get("session_id")
    if not session_id:
        return JSONResponse({"error": "session_id required"}, status_code=400)
    
    # Mark session as cancelled - the agent thread should check this
    active_sessions[session_id] = True
    
    # Also try to cancel if it's in task_store
    if session_id in task_store:
        task_store[session_id].status = TaskStatus.cancelled
    
    return JSONResponse({"success": True, "session_id": session_id, "status": "cancelled"})

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
<title>Pentest.Systems Assistant - Professional Security Testing</title>
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
  gap: 0.5rem;
  align-items: center;
  background: rgba(0,0,0,0.25);
  padding: 0.5rem 0.75rem;
  border-radius: 12px;
  border: 1px solid rgba(255,255,255,0.06);
  backdrop-filter: blur(8px);
}
.header-actions-divider {
  width: 1px;
  height: 24px;
  background: rgba(255,255,255,0.1);
  margin: 0 0.25rem;
}
.btn {
  padding: 0.5rem 0.9rem;
  border: none;
  border-radius: 8px;
  font-size: 0.8rem;
  cursor: pointer;
  transition: all 0.2s ease;
  font-weight: 500;
  font-family: inherit;
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  position: relative;
  overflow: hidden;
}
.btn::before {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
  transition: left 0.4s ease;
}
.btn:hover::before {
  left: 100%;
}
.btn svg {
  width: 14px;
  height: 14px;
  flex-shrink: 0;
}
.btn-primary {
  background: var(--gradient-primary);
  color: white;
  box-shadow: var(--shadow-md);
}
.btn-primary:hover {
  transform: translateY(-1px);
  box-shadow: var(--shadow-lg), 0 0 15px rgba(99, 102, 241, 0.35);
}
.btn-secondary {
  background: rgba(255,255,255,0.06);
  color: var(--gray-300);
  border: 1px solid rgba(255,255,255,0.1);
}
.btn-secondary:hover {
  background: rgba(255,255,255,0.12);
  border-color: rgba(255,255,255,0.2);
  color: white;
}
.btn-icon-only {
  padding: 0.5rem;
  width: 34px;
  height: 34px;
  justify-content: center;
}
.btn-icon-only svg {
  margin: 0;
}
.btn-success {
  background: var(--success);
  color: white;
}
.btn-success:hover {
  background: #059669;
}

/* Report Mode Toggle - Premium Switch Style */
.toggle-switch-wrapper {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.35rem 0.6rem 0.35rem 0.5rem;
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(139, 92, 246, 0.08) 100%);
  border-radius: 8px;
  border: 1px solid rgba(99, 102, 241, 0.25);
  cursor: pointer;
  transition: all 0.2s ease;
}
.toggle-switch-wrapper:hover {
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(139, 92, 246, 0.12) 100%);
  border-color: rgba(99, 102, 241, 0.35);
}
.toggle-switch {
  position: relative;
  width: 40px;
  height: 22px;
  flex-shrink: 0;
}
.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}
.toggle-label {
  font-size: 0.75rem;
  color: var(--gray-300);
  display: flex;
  align-items: center;
  gap: 0.35rem;
  white-space: nowrap;
}
.toggle-label svg {
  width: 13px;
  height: 13px;
  opacity: 0.8;
}
.toggle-slider {
  position: absolute;
  cursor: pointer;
  top: 0; left: 0; right: 0; bottom: 0;
  background: var(--gray-600);
  border-radius: 11px;
  transition: 0.3s;
}
.toggle-slider:before {
  position: absolute;
  content: "";
  height: 16px;
  width: 16px;
  left: 3px;
  top: 3px;
  background: white;
  border-radius: 50%;
  transition: 0.3s;
  box-shadow: 0 1px 3px rgba(0,0,0,0.3);
}
.toggle-switch input:checked + .toggle-slider {
  background: var(--success);
}
.toggle-switch input:checked + .toggle-slider:before {
  transform: translateX(18px);
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
.sidebar-tab.has-activity {
  position: relative;
}
.sidebar-tab.has-activity::after {
  content: '';
  position: absolute;
  top: 6px;
  right: 6px;
  width: 8px;
  height: 8px;
  background: #ef4444;
  border-radius: 50%;
  animation: pulse-dot 1.5s ease-in-out infinite;
  box-shadow: 0 0 6px #ef4444;
}
@keyframes pulse-dot {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.7; transform: scale(1.2); }
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
/* Activity Monitor Task Tabs */
.activity-tabs-container {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
  overflow: hidden;
}
.activity-tabs-header {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.5rem;
  background: rgba(0,0,0,0.2);
  border-bottom: 1px solid rgba(255,255,255,0.08);
  overflow-x: auto;
  flex-shrink: 0;
}
.activity-tabs-header::-webkit-scrollbar {
  height: 4px;
}
.activity-tabs-header::-webkit-scrollbar-thumb {
  background: var(--gray-600);
  border-radius: 2px;
}
.activity-task-tab {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.4rem 0.6rem;
  background: rgba(255,255,255,0.05);
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 6px;
  font-size: 0.72rem;
  color: var(--gray-400);
  cursor: pointer;
  white-space: nowrap;
  transition: all 0.2s ease;
  max-width: 160px;
}
.activity-task-tab:hover {
  background: rgba(255,255,255,0.1);
  color: var(--gray-200);
}
.activity-task-tab.active {
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.3) 0%, rgba(139, 92, 246, 0.2) 100%);
  border-color: var(--primary);
  color: white;
}
.activity-task-tab.running {
  border-color: var(--secondary);
}
.activity-task-tab.running::before {
  content: '';
  width: 6px;
  height: 6px;
  background: var(--secondary);
  border-radius: 50%;
  animation: pulse 1.5s ease-in-out infinite;
}
.activity-task-tab.completed {
  border-color: var(--success);
}
.activity-task-tab.completed::before {
  content: '✓';
  font-size: 0.65rem;
  color: var(--success);
}
.activity-task-tab.failed {
  border-color: var(--danger);
}
.activity-task-tab.failed::before {
  content: '✗';
  font-size: 0.65rem;
  color: var(--danger);
}
.activity-task-tab .tab-label {
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100px;
}
.activity-task-tab .tab-close {
  width: 14px;
  height: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background: rgba(255,255,255,0.1);
  color: var(--gray-400);
  font-size: 0.65rem;
  opacity: 0;
  transition: all 0.2s ease;
}
.activity-task-tab:hover .tab-close {
  opacity: 1;
}
.activity-task-tab .tab-close:hover {
  background: var(--danger);
  color: white;
}
.activity-panels {
  flex: 1;
  overflow: hidden;
  position: relative;
  min-height: 0;
}
.activity-panel {
  display: none;
  flex-direction: column;
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  overflow: hidden;
}
.activity-panel.active {
  display: flex;
}
.activity-panel-log {
  flex: 1;
  overflow-y: auto;
  padding: 0;
  min-height: 0;
}
#sidebar.expanded .activity-panel-log {
  padding: 0.75rem;
}
.activity-panel-log::-webkit-scrollbar {
  width: 6px;
}
.activity-panel-log::-webkit-scrollbar-track {
  background: transparent;
}
.activity-panel-log::-webkit-scrollbar-thumb {
  background: var(--gray-600);
  border-radius: 3px;
}
.activity-panel-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.5rem;
  background: rgba(0,0,0,0.2);
  border-top: 1px solid rgba(255,255,255,0.08);
  gap: 0.5rem;
  flex-shrink: 0;
}
.activity-panel-stats {
  display: flex;
  gap: 0.75rem;
  font-size: 0.7rem;
  color: var(--gray-400);
}
.activity-panel-stats .stat {
  display: flex;
  align-items: center;
  gap: 0.25rem;
}
.activity-panel-stats .stat-value {
  color: var(--gray-200);
  font-weight: 600;
}
.activity-panel-actions {
  display: flex;
  gap: 0.4rem;
}
.activity-btn {
  display: flex;
  align-items: center;
  gap: 0.3rem;
  padding: 0.35rem 0.6rem;
  border: none;
  border-radius: 5px;
  font-size: 0.68rem;
  cursor: pointer;
  transition: all 0.2s ease;
}
.activity-btn svg {
  width: 12px;
  height: 12px;
}
.activity-btn-kill {
  background: rgba(239, 68, 68, 0.2);
  color: var(--danger);
}
.activity-btn-kill:hover {
  background: var(--danger);
  color: white;
}
.activity-btn-download {
  background: rgba(99, 102, 241, 0.2);
  color: var(--primary-light);
}
.activity-btn-download:hover {
  background: var(--primary);
  color: white;
}
.no-tasks-message {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: var(--gray-500);
  font-size: 0.85rem;
  gap: 0.5rem;
  padding: 2rem;
  text-align: center;
}
.no-tasks-message svg {
  width: 48px;
  height: 48px;
  opacity: 0.3;
}
/* Legacy activity-log for backwards compatibility */
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

/* Schedule Modal - Premium Design */
.schedule-modal-content {
  max-width: 480px;
  padding: 0;
}
.schedule-modal-header {
  padding: 1.25rem 1.5rem;
  background: linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, rgba(217, 119, 6, 0.05) 100%);
  border-bottom: 1px solid rgba(245, 158, 11, 0.15);
}
.schedule-modal-title-wrapper {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}
.schedule-modal-icon {
  width: 40px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, rgba(245, 158, 11, 0.25) 0%, rgba(217, 119, 6, 0.15) 100%);
  border: 1px solid rgba(245, 158, 11, 0.3);
  border-radius: 10px;
}
.schedule-modal-icon svg {
  width: 22px;
  height: 22px;
  stroke: var(--warning);
}
.schedule-modal-subtitle {
  display: block;
  font-size: 0.75rem;
  color: var(--gray-400);
  font-weight: 400;
  margin-top: 2px;
}
.schedule-modal-body {
  padding: 1rem 1.25rem;
}
.schedule-form-section {
  margin-bottom: 0.75rem;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid rgba(255,255,255,0.06);
}
.schedule-timing-section {
  border-bottom: none;
  margin-bottom: 0;
  padding-bottom: 0;
}
.schedule-form .form-group {
  margin-bottom: 0.6rem;
}
.form-label {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--gray-300);
  margin-bottom: 0.35rem;
}
.form-label svg {
  opacity: 0.7;
}
.schedule-input {
  width: 100%;
  padding: 0.5rem 0.75rem;
  background: rgba(0,0,0,0.3);
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 6px;
  color: var(--light);
  font-size: 0.85rem;
  font-family: inherit;
  transition: all 0.2s ease;
}
.schedule-input:hover {
  border-color: rgba(255,255,255,0.2);
}
.schedule-input:focus {
  outline: none;
  border-color: var(--warning);
  box-shadow: 0 0 0 3px rgba(245, 158, 11, 0.15);
}
.schedule-input::placeholder {
  color: var(--gray-500);
}
.schedule-textarea {
  width: 100%;
  padding: 0.5rem 0.75rem;
  background: rgba(0,0,0,0.3);
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 6px;
  color: var(--light);
  font-size: 0.85rem;
  font-family: inherit;
  resize: vertical;
  min-height: 60px;
  transition: all 0.2s ease;
}
.schedule-textarea:hover {
  border-color: rgba(255,255,255,0.2);
}
.schedule-textarea:focus {
  outline: none;
  border-color: var(--warning);
  box-shadow: 0 0 0 3px rgba(245, 158, 11, 0.15);
}
.schedule-datetime {
  color-scheme: dark;
}
.schedule-recurring-toggle {
  margin: 0.6rem 0;
}
.schedule-checkbox {
  background: rgba(245, 158, 11, 0.08);
  border-color: rgba(245, 158, 11, 0.2);
  padding: 0.4rem 0.6rem;
}
.schedule-checkbox:hover {
  background: rgba(245, 158, 11, 0.12);
  border-color: rgba(245, 158, 11, 0.3);
}
.recurring-options {
  display: none;
  padding: 0.75rem;
  background: rgba(0,0,0,0.2);
  border-radius: 6px;
  border: 1px solid rgba(255,255,255,0.06);
  margin-top: 0.5rem;
}
.recurring-options.active {
  display: block;
}
.recurring-interval-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 0.75rem;
}
.interval-input {
  width: 100px;
  text-align: center;
}
.interval-label {
  font-size: 0.85rem;
  color: var(--gray-400);
}
.recurring-presets {
  display: flex;
  gap: 0.5rem;
}
.preset-btn {
  padding: 0.4rem 0.8rem;
  background: rgba(255,255,255,0.05);
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 6px;
  color: var(--gray-300);
  font-size: 0.75rem;
  cursor: pointer;
  transition: all 0.2s ease;
}
.preset-btn:hover {
  background: rgba(245, 158, 11, 0.15);
  border-color: rgba(245, 158, 11, 0.3);
  color: var(--warning);
}
.schedule-submit-btn {
  width: 100%;
  margin-top: 0.75rem;
  padding: 0.65rem;
  font-size: 0.85rem;
  justify-content: center;
}

/* Collapsible Sections for Tasks/Chains - Improved Scrollable Design */
.tasks-chains-wrapper {
  display: flex;
  flex-direction: column;
  flex: 1;
  overflow: hidden;
  padding: 0.5rem;
  gap: 0.5rem;
  min-height: 0;
}
.collapsible-section {
  background: linear-gradient(135deg, rgba(0,0,0,0.25) 0%, rgba(0,0,0,0.15) 100%);
  border-radius: 12px;
  overflow: hidden;
  border: 1px solid rgba(255,255,255,0.06);
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 120px;
  max-height: 50%;
}
.collapsible-section.collapsed {
  flex: 0 0 auto;
  min-height: auto;
  max-height: none;
}
.section-toggle {
  width: 100%;
  padding: 0.65rem 0.85rem;
  background: linear-gradient(135deg, rgba(255,255,255,0.04) 0%, transparent 100%);
  border: none;
  border-bottom: 1px solid rgba(255,255,255,0.05);
  color: var(--gray-200);
  font-size: 0.78rem;
  font-weight: 600;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  transition: all 0.2s;
  font-family: inherit;
  flex-shrink: 0;
}
.section-toggle:hover {
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(99, 102, 241, 0.05) 100%);
  color: var(--primary-light);
}
.section-toggle .section-icon {
  width: 18px;
  height: 18px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, var(--primary) 0%, #8b5cf6 100%);
  border-radius: 5px;
  flex-shrink: 0;
}
.section-toggle .section-icon svg {
  width: 11px;
  height: 11px;
  stroke: white;
}
.section-toggle .chevron-icon {
  transition: transform 0.2s;
  opacity: 0.6;
}
.section-toggle[data-expanded="false"] .chevron-icon {
  transform: rotate(-90deg);
}
.section-toggle .section-count {
  margin-left: auto;
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.35) 0%, rgba(139, 92, 246, 0.25) 100%);
  color: var(--primary-light);
  padding: 3px 10px;
  border-radius: 12px;
  font-size: 0.68rem;
  font-weight: 600;
  border: 1px solid rgba(99, 102, 241, 0.2);
}
.section-content {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  padding: 0.5rem;
  min-height: 0;
}
.section-content::-webkit-scrollbar {
  width: 5px;
}
.section-content::-webkit-scrollbar-track {
  background: transparent;
}
.section-content::-webkit-scrollbar-thumb {
  background: var(--gray-600);
  border-radius: 3px;
}
.section-content::-webkit-scrollbar-thumb:hover {
  background: var(--gray-500);
}
.section-content.collapsed {
  display: none;
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
/* Scheduled Tasks - Premium Header & Empty State */
.scheduled-header {
  display: flex !important;
  justify-content: space-between !important;
  align-items: center !important;
}
.scheduled-header .header-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.header-icon-wrapper {
  width: 26px;
  height: 26px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 7px;
  flex-shrink: 0;
}
.header-icon-wrapper.scheduled-icon {
  background: linear-gradient(135deg, rgba(245, 158, 11, 0.25) 0%, rgba(217, 119, 6, 0.15) 100%);
  border: 1px solid rgba(245, 158, 11, 0.3);
}
.header-icon-wrapper.scheduled-icon svg {
  width: 14px;
  height: 14px;
  stroke: var(--warning);
}
.btn-add-scheduled {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.4rem 0.7rem;
  background: linear-gradient(135deg, rgba(245, 158, 11, 0.15) 0%, rgba(217, 119, 6, 0.1) 100%);
  border: 1px solid rgba(245, 158, 11, 0.3);
  border-radius: 7px;
  color: var(--warning);
  font-size: 0.72rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
}
.btn-add-scheduled:hover {
  background: linear-gradient(135deg, rgba(245, 158, 11, 0.25) 0%, rgba(217, 119, 6, 0.18) 100%);
  border-color: rgba(245, 158, 11, 0.5);
  transform: translateY(-1px);
}
.btn-add-scheduled svg {
  width: 12px;
  height: 12px;
}
.scheduled-list-container {
  flex: 1;
  overflow-y: auto;
  padding: 0.75rem;
}
.scheduled-list-container::-webkit-scrollbar {
  width: 5px;
}
.scheduled-list-container::-webkit-scrollbar-thumb {
  background: var(--gray-600);
  border-radius: 3px;
}
.no-scheduled-tasks {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 2.5rem 1rem;
  color: var(--gray-500);
  text-align: center;
  gap: 0.5rem;
}
.no-scheduled-tasks svg {
  width: 42px;
  height: 42px;
  opacity: 0.3;
  margin-bottom: 0.5rem;
}
.no-scheduled-tasks span:first-of-type {
  font-size: 0.9rem;
  font-weight: 500;
}
.no-scheduled-hint {
  font-size: 0.75rem;
  opacity: 0.7;
}

/* Send Button - Premium Style */
.btn-send {
  width: 48px;
  height: 48px;
  padding: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 12px;
  flex-shrink: 0;
}
.btn-send svg {
  width: 20px;
  height: 20px;
}
.btn-send:hover {
  transform: scale(1.05);
}
.btn-send:active {
  transform: scale(0.98);
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
  padding: 0;
  min-height: 0;
  display: flex;
  flex-direction: column;
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

/* Settings Sub-Tabs Navigation */
.settings-subtabs-wrapper {
  position: relative;
  flex-shrink: 0;
  background: rgba(0, 0, 0, 0.3);
  border-bottom: 1px solid rgba(255,255,255,0.1);
}
.settings-subtabs-scroll {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(90deg, var(--dark) 60%, transparent 100%);
  cursor: pointer;
  z-index: 5;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.2s ease;
}
.settings-subtabs-scroll.visible {
  opacity: 1;
  pointer-events: auto;
}
.settings-subtabs-scroll.left {
  left: 0;
  background: linear-gradient(90deg, var(--dark) 60%, transparent 100%);
}
.settings-subtabs-scroll.right {
  right: 0;
  background: linear-gradient(-90deg, var(--dark) 60%, transparent 100%);
}
.settings-subtabs-scroll svg {
  width: 16px;
  height: 16px;
  color: var(--gray-400);
  transition: color 0.2s;
}
.settings-subtabs-scroll:hover svg {
  color: var(--primary);
}
.settings-subtabs {
  display: flex;
  gap: 0;
  padding: 0;
  overflow-x: auto;
  scrollbar-width: none;
  -ms-overflow-style: none;
  scroll-behavior: smooth;
}
.settings-subtabs::-webkit-scrollbar {
  display: none;
}
.settings-subtab {
  padding: 0.6rem 0.75rem;
  font-size: 0.7rem;
  font-weight: 500;
  color: var(--gray-400);
  background: transparent;
  border: none;
  cursor: pointer;
  transition: all 0.2s ease;
  white-space: nowrap;
  display: flex;
  align-items: center;
  gap: 0.3rem;
  position: relative;
  flex-shrink: 0;
}
.settings-subtab::after {
  content: '';
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: transparent;
  transition: background 0.2s ease;
}
.settings-subtab:hover {
  color: var(--gray-200);
  background: rgba(255,255,255,0.05);
}
.settings-subtab.active {
  color: var(--primary);
  background: rgba(99, 102, 241, 0.1);
}
.settings-subtab.active::after {
  background: var(--primary);
}
.settings-subtab svg {
  width: 12px;
  height: 12px;
  flex-shrink: 0;
}

/* Settings Sub-Tab Content */
.settings-subtab-content {
  display: none;
  flex: 1;
  overflow-y: auto;
  padding: 1rem;
  min-height: 0;
}
.settings-subtab-content.active {
  display: flex;
  flex-direction: column;
}
.settings-subtab-content::-webkit-scrollbar {
  width: 6px;
}
.settings-subtab-content::-webkit-scrollbar-thumb {
  background: var(--gray-600);
  border-radius: 3px;
}

/* Database Storage Section */
.db-connection-form {
  background: rgba(0,0,0,0.2);
  border-radius: 10px;
  padding: 0.75rem;
  border: 1px solid rgba(255,255,255,0.08);
}
.db-connection-type {
  display: flex;
  gap: 0.35rem;
  margin-bottom: 0.75rem;
}
.db-type-btn {
  flex: 1;
  padding: 0.5rem 0.5rem;
  background: rgba(255,255,255,0.05);
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 6px;
  color: var(--gray-400);
  font-size: 0.65rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.3rem;
  flex-direction: column;
}
.db-type-btn:hover {
  background: rgba(255,255,255,0.1);
  color: var(--gray-200);
}
.db-type-btn.active {
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.2) 0%, rgba(139, 92, 246, 0.1) 100%);
  border-color: var(--primary);
  color: var(--primary);
}
.db-type-btn svg {
  width: 16px;
  height: 16px;
}
.db-form-grid {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
}
.db-form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.5rem;
}
.db-form-group {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  min-width: 0;
}
.db-form-group.full-width {
  grid-column: span 2;
}
.db-form-label {
  font-size: 0.75rem;
  color: var(--gray-400);
  font-weight: 500;
}
.db-form-input {
  padding: 0.5rem 0.75rem;
  background: var(--darker);
  border: 1px solid rgba(255,255,255,0.12);
  border-radius: 6px;
  color: var(--light);
  font-size: 0.8rem;
  font-family: 'JetBrains Mono', monospace;
  transition: all 0.2s ease;
}
.db-form-input:focus {
  outline: none;
  border-color: var(--primary);
  box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
}
.db-form-input::placeholder {
  color: var(--gray-500);
}
.db-form-select {
  padding: 0.5rem 0.75rem;
  background: var(--darker);
  border: 1px solid rgba(255,255,255,0.12);
  border-radius: 6px;
  color: var(--light);
  font-size: 0.8rem;
  cursor: pointer;
}
.db-form-actions {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}
.db-status {
  margin-top: 1rem;
  padding: 0.75rem 1rem;
  border-radius: 8px;
  font-size: 0.8rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.db-status.connected {
  background: rgba(16, 185, 129, 0.15);
  border: 1px solid rgba(16, 185, 129, 0.3);
  color: var(--success);
}
.db-status.disconnected {
  background: rgba(156, 163, 175, 0.15);
  border: 1px solid rgba(156, 163, 175, 0.3);
  color: var(--gray-400);
}
.db-status.error {
  background: rgba(239, 68, 68, 0.15);
  border: 1px solid rgba(239, 68, 68, 0.3);
  color: var(--danger);
}
.db-stats {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 0.5rem;
  margin-top: 1rem;
}
.db-stat-item {
  padding: 0.75rem;
  background: rgba(255,255,255,0.03);
  border-radius: 8px;
  border: 1px solid rgba(255,255,255,0.05);
  text-align: center;
}
.db-stat-value {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--light);
}
.db-stat-label {
  font-size: 0.7rem;
  color: var(--gray-500);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.db-auto-connect {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-top: 1rem;
  padding: 0.75rem;
  background: rgba(255,255,255,0.03);
  border-radius: 8px;
}
.db-auto-connect .checkbox-label {
  font-size: 0.8rem;
  color: var(--gray-300);
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
.provider-select {
  width: 100%;
  padding: 0.5rem 0.75rem;
  background: var(--dark);
  border: 1px solid rgba(255, 255, 255, 0.15);
  border-radius: 6px;
  color: var(--light);
  font-size: 0.85rem;
  font-family: inherit;
  cursor: pointer;
  transition: all 0.2s;
  appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 10px center;
  padding-right: 32px;
}
.provider-select:hover {
  border-color: var(--primary);
}
.provider-select:focus {
  outline: none;
  border-color: var(--primary);
  box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
}
.provider-select option {
  background: var(--dark-lighter);
  color: var(--light);
  padding: 8px;
}
.provider-status-success {
  background: rgba(16, 185, 129, 0.15);
  color: var(--success);
  border: 1px solid rgba(16, 185, 129, 0.3);
}
.provider-status-error {
  background: rgba(239, 68, 68, 0.15);
  color: var(--danger);
  border: 1px solid rgba(239, 68, 68, 0.3);
}
.provider-status-info {
  background: rgba(99, 102, 241, 0.15);
  color: var(--primary);
  border: 1px solid rgba(99, 102, 241, 0.3);
}
body.light-theme .provider-select {
  background-color: #f8fafc;
  border-color: #cbd5e1;
  color: #1e293b;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
}
body.light-theme .provider-select option {
  background: #f1f5f9;
  color: #1e293b;
}
.provider-select optgroup {
  font-weight: 600;
  color: var(--gray-400);
  background: var(--dark);
  padding: 8px 0;
}
body.light-theme .provider-select optgroup {
  background: #e2e8f0;
  color: #475569;
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
  padding-left: 3rem;
  margin-bottom: 0.5rem;
  border-radius: 10px;
  font-size: 0.85rem;
  animation: slideIn 0.3s ease;
  position: relative;
  overflow: hidden;
  backdrop-filter: blur(8px);
}
@keyframes slideIn {
  from { opacity: 0; transform: translateX(-10px); }
  to { opacity: 1; transform: translateX(0); }
}
.activity-icon {
  position: absolute;
  left: 0.75rem;
  top: 0.875rem;
  width: 22px;
  height: 22px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 6px;
}
.activity-icon svg {
  width: 14px;
  height: 14px;
}
/* Task Started */
.activity-start {
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(139, 92, 246, 0.1) 100%);
  border: 1px solid rgba(99, 102, 241, 0.4);
  border-left: 3px solid var(--primary);
}
.activity-start .activity-icon {
  background: linear-gradient(135deg, var(--primary) 0%, #8b5cf6 100%);
  color: white;
}
/* Thinking/Processing */
.activity-thinking {
  background: linear-gradient(135deg, rgba(245, 158, 11, 0.12) 0%, rgba(251, 191, 36, 0.08) 100%);
  border: 1px solid rgba(245, 158, 11, 0.35);
  border-left: 3px solid var(--warning);
}
.activity-thinking .activity-icon {
  background: linear-gradient(135deg, #f59e0b 0%, #fbbf24 100%);
  color: white;
  animation: pulse 1.5s ease-in-out infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.7; transform: scale(0.95); }
}
/* Tool Execution */
.activity-tool {
  background: linear-gradient(135deg, rgba(14, 165, 233, 0.12) 0%, rgba(6, 182, 212, 0.08) 100%);
  border: 1px solid rgba(14, 165, 233, 0.35);
  border-left: 3px solid var(--secondary);
}
.activity-tool .activity-icon {
  background: linear-gradient(135deg, #0ea5e9 0%, #06b6d4 100%);
  color: white;
}
/* Tool Result */
.activity-tool-result {
  background: linear-gradient(135deg, rgba(16, 185, 129, 0.12) 0%, rgba(52, 211, 153, 0.08) 100%);
  border: 1px solid rgba(16, 185, 129, 0.35);
  border-left: 3px solid var(--success);
}
.activity-tool-result .activity-icon {
  background: linear-gradient(135deg, #10b981 0%, #34d399 100%);
  color: white;
}
/* Error */
.activity-error {
  background: linear-gradient(135deg, rgba(239, 68, 68, 0.12) 0%, rgba(248, 113, 113, 0.08) 100%);
  border: 1px solid rgba(239, 68, 68, 0.4);
  border-left: 3px solid var(--danger);
}
.activity-error .activity-icon {
  background: linear-gradient(135deg, #ef4444 0%, #f87171 100%);
  color: white;
}
/* Step/Progress */
.activity-step {
  background: linear-gradient(135deg, rgba(148, 163, 184, 0.1) 0%, rgba(100, 116, 139, 0.08) 100%);
  border: 1px solid rgba(148, 163, 184, 0.3);
  border-left: 3px solid var(--gray-500);
}
.activity-step .activity-icon {
  background: linear-gradient(135deg, #64748b 0%, #94a3b8 100%);
  color: white;
}
/* Complete/Success */
.activity-complete {
  background: linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(52, 211, 153, 0.1) 100%);
  border: 1px solid rgba(16, 185, 129, 0.4);
  border-left: 3px solid var(--success);
}
.activity-complete .activity-icon {
  background: linear-gradient(135deg, #10b981 0%, #059669 100%);
  color: white;
}
/* Warning */
.activity-warning {
  background: linear-gradient(135deg, rgba(245, 158, 11, 0.12) 0%, rgba(217, 119, 6, 0.08) 100%);
  border: 1px solid rgba(245, 158, 11, 0.4);
  border-left: 3px solid var(--warning);
}
.activity-warning .activity-icon {
  background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
  color: white;
}
.activity-title {
  font-weight: 600;
  color: var(--gray-100);
  margin-bottom: 0.35rem;
  font-size: 0.82rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
}
.activity-title-text {
  display: flex;
  align-items: center;
  gap: 0.4rem;
}
.activity-time {
  font-size: 0.7rem;
  color: var(--gray-500);
  font-weight: 400;
  font-family: 'JetBrains Mono', monospace;
  background: rgba(0,0,0,0.2);
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
}
.activity-content {
  word-break: break-word;
  color: var(--gray-300);
  line-height: 1.5;
  font-size: 0.8rem;
}
.activity-content pre {
  background: rgba(0, 0, 0, 0.3);
  color: var(--gray-300);
  padding: 0.75rem;
  border-radius: 6px;
  font-size: 0.72rem;
  overflow-x: auto;
  margin-top: 0.5rem;
  font-family: 'JetBrains Mono', monospace;
  border: 1px solid rgba(255,255,255,0.08);
  max-height: 150px;
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
.message-timestamp {
  font-size: 0.7rem;
  color: var(--gray-500);
  margin-top: 0.5rem;
  text-align: right;
  opacity: 0.7;
}
.msg-user .message-timestamp {
  color: rgba(255,255,255,0.6);
}
.msg-agent .message-timestamp {
  color: var(--gray-500);
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
.spin {
  animation: spin 1s linear infinite;
}

/* Toggle switch styles */
.toggle-switch input:checked + .toggle-slider {
  background-color: var(--primary);
}
.toggle-switch .toggle-slider:before {
  content: "";
  position: absolute;
  height: 18px;
  width: 18px;
  left: 3px;
  bottom: 3px;
  background-color: white;
  transition: .3s;
  border-radius: 50%;
}
.toggle-switch input:checked + .toggle-slider:before {
  transform: translateX(24px);
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

/* Input area - Redesigned */
#input-area {
  padding: 0.75rem 1rem;
  background: linear-gradient(180deg, rgba(0,0,0,0.15) 0%, rgba(0,0,0,0.25) 100%);
  border-top: 1px solid rgba(255,255,255,0.08);
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  flex-shrink: 0;
}
.input-row {
  display: flex;
  gap: 0.5rem;
  align-items: flex-end;
}
.input-wrapper {
  flex: 1;
  position: relative;
  display: flex;
  flex-direction: column;
}
.input-container {
  position: relative;
  display: flex;
  flex-direction: column;
  background: linear-gradient(135deg, rgba(0,0,0,0.3) 0%, rgba(0,0,0,0.2) 100%);
  border: 2px solid rgba(255,255,255,0.08);
  border-radius: 16px;
  transition: all 0.25s ease;
}
.input-container:hover {
  border-color: rgba(255,255,255,0.15);
}
.input-container:focus-within {
  border-color: var(--primary);
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(0,0,0,0.25) 100%);
  box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15), 0 4px 20px rgba(0,0,0,0.2);
}
#message-input {
  width: 100%;
  min-height: 44px;
  max-height: 160px;
  padding: 0.75rem 1rem;
  padding-bottom: 0.5rem;
  border: none;
  border-radius: 16px 16px 0 0;
  font-size: 0.9rem;
  background: transparent;
  color: var(--light);
  font-family: inherit;
  resize: none;
  overflow-y: auto;
  line-height: 1.5;
}
#message-input::-webkit-scrollbar {
  width: 4px;
}
#message-input::-webkit-scrollbar-thumb {
  background: var(--gray-600);
  border-radius: 2px;
}
#message-input::placeholder {
  color: var(--gray-500);
  font-size: 0.85rem;
}
#message-input:focus {
  outline: none;
}
/* Input toolbar with attach & options */
.input-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.35rem 0.75rem 0.5rem;
  border-top: 1px solid rgba(255,255,255,0.05);
  gap: 0.5rem;
}
.input-toolbar-left {
  display: flex;
  align-items: center;
  gap: 0.25rem;
}
.input-toolbar-right {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.toolbar-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.3rem;
  padding: 0.35rem 0.6rem;
  background: transparent;
  border: none;
  border-radius: 6px;
  color: var(--gray-400);
  font-size: 0.72rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
}
.toolbar-btn:hover {
  background: rgba(255,255,255,0.08);
  color: var(--gray-200);
}
.toolbar-btn.active {
  background: rgba(14, 165, 233, 0.15);
  color: var(--secondary);
}
.toolbar-btn svg {
  width: 14px;
  height: 14px;\n}
.toolbar-btn-attach {
  border: 1px dashed rgba(139, 92, 246, 0.3);
}
.toolbar-btn-attach:hover {
  background: rgba(139, 92, 246, 0.12);
  border-color: rgba(139, 92, 246, 0.5);
  color: #a78bfa;
}
.toolbar-divider {
  width: 1px;
  height: 16px;
  background: rgba(255,255,255,0.1);
  margin: 0 0.25rem;
}
#attached-files {
  display: flex;
  gap: 0.35rem;
  flex-wrap: wrap;
  padding: 0 0.75rem 0.5rem;
}
#attached-files:empty {
  display: none;
}
.attached-file {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.25rem 0.6rem;
  background: rgba(99, 102, 241, 0.15);
  color: var(--primary-light);
  border-radius: 14px;
  font-size: 0.72rem;
  border: 1px solid rgba(99, 102, 241, 0.25);
}
.attached-file .remove-file {
  cursor: pointer;
  opacity: 0.7;
  transition: opacity 0.2s;
  font-size: 0.8rem;
}
.attached-file .remove-file:hover {
  opacity: 1;
}
#send-btn {
  padding: 0.85rem 1.5rem;
  min-width: 52px;
  border-radius: 14px;
}

/* Hide old input options - we moved them to toolbar */
.input-options {
  display: none;
}

/* Background task checkbox - Premium Style */
.background-task-toggle {
  display: flex;
  align-items: center;
}
.checkbox-wrapper {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
  font-size: 0.78rem;
  color: var(--gray-400);
  user-select: none;
  padding: 0.4rem 0.7rem;
  background: rgba(255,255,255,0.03);
  border-radius: 8px;
  border: 1px solid rgba(255,255,255,0.06);
  transition: all 0.2s ease;
}
.checkbox-wrapper:hover {
  background: rgba(14, 165, 233, 0.08);
  border-color: rgba(14, 165, 233, 0.2);
}
.checkbox-wrapper input[type="checkbox"] {
  display: none;
}
.checkmark {
  width: 16px;
  height: 16px;
  border: 2px solid var(--gray-500);
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
  flex-shrink: 0;
}
.checkbox-wrapper input:checked + .checkmark {
  background: linear-gradient(135deg, var(--secondary) 0%, #0284c7 100%);
  border-color: var(--secondary);
  box-shadow: 0 0 8px rgba(14, 165, 233, 0.4);
}
.checkbox-wrapper input:checked + .checkmark::after {
  content: '✓';
  color: white;
  font-size: 0.65rem;
  font-weight: bold;
}
.checkbox-wrapper:hover .checkmark {
  border-color: var(--secondary);
}
.checkbox-label {
  transition: color 0.2s;
  display: flex;
  align-items: center;
  gap: 0.35rem;
}
.checkbox-label .label-icon {
  font-size: 0.9rem;
}
.checkbox-wrapper:hover .checkbox-label {
  color: var(--gray-200);
}
.checkbox-wrapper input:checked ~ .checkbox-label {
  color: var(--secondary);
}

/* File attachment - Enhanced Design */
.file-attachment-area {
  display: flex;
  align-items: center;
  gap: 0.5rem;
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
  padding: 0.4rem 0.75rem;
  background: linear-gradient(135deg, rgba(139, 92, 246, 0.1) 0%, rgba(99, 102, 241, 0.08) 100%);
  color: var(--gray-300);
  border: 1px dashed rgba(139, 92, 246, 0.35);
  border-radius: 8px;
  cursor: pointer;
  font-size: 0.78rem;
  transition: all 0.2s ease;
}
.file-input-btn:hover {
  background: linear-gradient(135deg, rgba(139, 92, 246, 0.18) 0%, rgba(99, 102, 241, 0.12) 100%);
  border-color: rgba(139, 92, 246, 0.5);
  color: white;
}
.file-input-btn .attach-icon {
  font-size: 0.9rem;
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
      <h1>Pentest.Systems Assistant</h1>
      <div class="header-subtitle">AI-Powered Security Testing Platform</div>
    </div>
    <span class="status-badge disconnected" id="status-badge">
      <span class="status-dot"></span>
      <span id="status-text">Disconnected</span>
    </span>
  </div>
  <div class="header-actions">
    <div class="toggle-switch-wrapper" id="report-toggle" title="Generate professional security report">
      <label class="toggle-switch">
        <input type="checkbox" id="report-mode-checkbox">
        <span class="toggle-slider"></span>
      </label>
      <span class="toggle-label"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg> Report</span>
    </div>
    <div class="header-actions-divider"></div>
    <button class="btn btn-secondary" id="export-txt-btn" title="Export chat history">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
      <span>Export</span>
    </button>
    <button class="btn btn-secondary" id="clear-btn" title="Clear chat history">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
      <span>Clear</span>
    </button>
    <div class="header-actions-divider"></div>
    <button class="btn btn-secondary btn-icon-only" id="theme-toggle-btn" title="Toggle Light/Dark Theme">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
    </button>
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
      <div class="sidebar-header">
        <span class="header-title"><svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg> Activity Monitor</span>
      </div>
      <div class="activity-tabs-container">
        <div class="activity-tabs-header" id="activity-tabs-header">
          <!-- Task tabs will be added here dynamically -->
        </div>
        <div class="activity-panels" id="activity-panels">
          <div class="no-tasks-message" id="no-activity-message">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
            </svg>
            <span>No active tasks</span>
            <span style="font-size: 0.75rem; opacity: 0.7;">Send a message to start a task</span>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Tasks Tab Content -->
    <div class="tab-content" id="tab-tasks">
      <div class="sidebar-header"><span class="header-title"><svg viewBox="0 0 24 24"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path><rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect></svg> Tasks & Chains</span></div>
      <div class="tasks-chains-wrapper">
        <div class="collapsible-section" id="section-tasks">
          <button class="section-toggle" onclick="toggleSection(this)" data-expanded="true">
            <span class="section-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M12 1v6m0 6v10M1 12h6m6 0h10"></path></svg></span>
            <span>Background Tasks</span>
            <svg class="chevron-icon" viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><polyline points="6 9 12 15 18 9"></polyline></svg>
            <span class="section-count" id="tasks-count">0</span>
          </button>
          <div class="section-content" id="tasks-list">
            <div class="no-tasks">No active tasks</div>
          </div>
        </div>
        
        <div class="collapsible-section" id="section-chains">
          <button class="section-toggle" onclick="toggleSection(this)" data-expanded="true">
            <span class="section-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></span>
            <span>Task Chains</span>
            <svg class="chevron-icon" viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><polyline points="6 9 12 15 18 9"></polyline></svg>
            <span class="section-count" id="chains-count">0</span>
          </button>
          <div class="section-content" id="chains-section-content">
            <button class="create-chain-btn" onclick="openChainBuilder()">
              <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
              Create Task Chain
            </button>
            <div id="chains-list" style="margin-top: 0.5rem;">
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
      <div class="sidebar-header"><span class="header-icon">⚙️</span> Settings</div>
      <div id="settings-content">
        <!-- Settings Sub-Tabs Navigation -->
        <div class="settings-subtabs-wrapper">
          <div class="settings-subtabs-scroll left" id="subtabs-scroll-left" onclick="scrollSubtabs(-1)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"></polyline></svg>
          </div>
          <div class="settings-subtabs" id="settings-subtabs-container">
            <button class="settings-subtab active" data-subtab="llm" onclick="switchSettingsSubtab('llm')">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 2a3 3 0 0 0-3 3v1a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3z"/>
                <path d="M19 9a7 7 0 1 0-14 0"/>
                <path d="M12 12v10"/>
                <path d="M8 18h8"/>
              </svg>
              LLM
            </button>
            <button class="settings-subtab" data-subtab="storage" onclick="switchSettingsSubtab('storage')">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <ellipse cx="12" cy="5" rx="9" ry="3"/>
                <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
                <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
              </svg>
              Storage
            </button>
            <button class="settings-subtab" data-subtab="api" onclick="switchSettingsSubtab('api')">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
              APIs
            </button>
            <button class="settings-subtab" data-subtab="comm" onclick="switchSettingsSubtab('comm')">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/>
              </svg>
              Comm
            </button>
            <button class="settings-subtab" data-subtab="tools" onclick="switchSettingsSubtab('tools')">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
              </svg>
              Tools
            </button>
            <button class="settings-subtab" data-subtab="general" onclick="switchSettingsSubtab('general')">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <path d="M2 12h20"/>
                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
              </svg>
              General
            </button>
          </div>
          <div class="settings-subtabs-scroll right" id="subtabs-scroll-right" onclick="scrollSubtabs(1)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
          </div>
        </div>
        
        <!-- LLM Config Sub-Tab -->
        <div class="settings-subtab-content active" id="settings-llm">
          <div class="settings-section">
            <div class="settings-section-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 2a3 3 0 0 0-3 3v1a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3z"/>
                <path d="M19 9a7 7 0 1 0-14 0"/>
                <path d="M12 12v10"/>
                <path d="M8 18h8"/>
              </svg>
              LLM Provider
            </div>
            
            <div class="provider-selector">
              <div class="form-group" style="margin-bottom: 12px;">
                <label style="font-size: 0.8rem; color: var(--gray-400); margin-bottom: 6px; display: block;">Provider</label>
                <select id="provider-select" class="provider-select" onchange="onProviderChange()">
                  <option value="deepseek">DeepSeek</option>
                  <option value="openrouter">OpenRouter</option>
                </select>
              </div>
              
              <div class="form-group" style="margin-bottom: 12px;">
                <label style="font-size: 0.8rem; color: var(--gray-400); margin-bottom: 6px; display: block;">Model</label>
                <select id="model-select" class="provider-select">
                  <!-- Populated dynamically -->
                </select>
              </div>
              
              <div class="form-group" style="margin-bottom: 12px;">
                <label style="font-size: 0.8rem; color: var(--gray-400); margin-bottom: 6px; display: block;">
                  <span id="provider-key-label">DeepSeek</span> API Key
                </label>
                <div class="api-key-item" style="margin-bottom: 0;">
                  <input type="password" class="api-key-input" id="provider-api-key" placeholder="Enter API key...">
                  <button class="api-key-btn api-key-btn-save" onclick="saveProviderKey()">💾</button>
                </div>
                <div id="provider-key-status" style="font-size: 0.75rem; color: var(--gray-500); margin-top: 4px;"></div>
              </div>
              
              <button class="btn btn-primary" style="width: 100%; margin-top: 8px;" onclick="applyProviderSettings()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;">
                  <path d="M20 6L9 17l-5-5"/>
                </svg>
                Apply Settings
              </button>
              
              <div id="provider-status" style="margin-top: 10px; padding: 8px 12px; border-radius: 6px; font-size: 0.8rem; display: none;"></div>
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
        
        <!-- Storage Config Sub-Tab -->
        <div class="settings-subtab-content" id="settings-storage">
          <div class="settings-section">
            <div class="settings-section-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <ellipse cx="12" cy="5" rx="9" ry="3"/>
                <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
                <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
              </svg>
              Database Storage
            </div>
            <p style="font-size: 0.8rem; color: var(--gray-400); margin-bottom: 1rem; line-height: 1.5;">
              Enable PostgreSQL/Supabase database to persist command history and agent memory. 
              All commands and outputs will be saved for history tracking.
            </p>
            
            <div class="db-connection-form">
              <div class="db-connection-type">
                <button class="db-type-btn active" id="db-type-local" onclick="setDbType('local')">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
                    <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
                    <line x1="6" y1="6" x2="6.01" y2="6"/>
                    <line x1="6" y1="18" x2="6.01" y2="18"/>
                  </svg>
                  Local PostgreSQL
                </button>
                <button class="db-type-btn" id="db-type-supabase" onclick="setDbType('supabase')">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
                    <circle cx="9" cy="7" r="4"/>
                    <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
                    <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
                  </svg>
                  Supabase
                </button>
              </div>
              
              <!-- Connection URI (for Supabase/quick setup) -->
              <div class="db-form-group" id="db-uri-group" style="margin-bottom: 0.75rem; display: none;">
                <label class="db-form-label">Connection URI (recommended)</label>
                <input type="text" class="db-form-input" id="db-connection-uri" placeholder="postgresql://postgres.xxx:pass@aws-0-region.pooler.supabase.com:6543/postgres" style="font-size: 0.7rem;">
                <div style="font-size: 0.65rem; color: var(--gray-500); margin-top: 0.25rem;">Paste your Supabase <strong>Transaction Pooler</strong> connection string (port 6543)</div>
              </div>
              
              <div class="db-form-grid">
                <div class="db-form-group">
                  <label class="db-form-label">Host</label>
                  <input type="text" class="db-form-input" id="db-host" placeholder="localhost or pooler.supabase.com">
                </div>
                <div class="db-form-row">
                  <div class="db-form-group">
                    <label class="db-form-label">Port</label>
                    <input type="number" class="db-form-input" id="db-port" value="5432" placeholder="5432">
                  </div>
                  <div class="db-form-group">
                    <label class="db-form-label">SSL</label>
                    <select class="db-form-select" id="db-ssl-mode">
                      <option value="require">Require</option>
                      <option value="prefer">Prefer</option>
                      <option value="verify-ca">Verify CA</option>
                      <option value="disable">Disable</option>
                    </select>
                  </div>
                </div>
                <div class="db-form-row">
                  <div class="db-form-group">
                    <label class="db-form-label">Database</label>
                    <input type="text" class="db-form-input" id="db-database" value="postgres" placeholder="postgres">
                  </div>
                  <div class="db-form-group">
                    <label class="db-form-label">User</label>
                    <input type="text" class="db-form-input" id="db-user" value="postgres" placeholder="postgres.project-ref">
                  </div>
                </div>
                <div class="db-form-group">
                  <label class="db-form-label">Password</label>
                  <input type="password" class="db-form-input" id="db-password" placeholder="Enter database password">
                </div>
              </div>
              
              <div class="db-form-actions">
                <button class="btn btn-secondary" onclick="testDbConnection()">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                  </svg>
                  Test Connection
                </button>
                <button class="btn btn-primary" onclick="connectDatabase()">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M18.36 6.64a9 9 0 1 1-12.73 0"/>
                    <line x1="12" y1="2" x2="12" y2="12"/>
                  </svg>
                  Connect
                </button>
                <button class="btn btn-secondary" onclick="disconnectDatabase()">
                  Disconnect
                </button>
              </div>
              
              <div id="db-status" class="db-status disconnected" style="display: none;">
                <span id="db-status-icon">⚪</span>
                <span id="db-status-text">Not connected</span>
              </div>
              
              <div class="db-auto-connect">
                <label class="checkbox-wrapper">
                  <input type="checkbox" id="db-auto-connect">
                  <span class="checkmark"></span>
                  <span class="checkbox-label">Auto-connect on startup</span>
                </label>
              </div>
            </div>
            
            <div id="db-stats" class="db-stats" style="display: none;">
              <div class="db-stat-item">
                <div class="db-stat-value" id="db-stat-commands">0</div>
                <div class="db-stat-label">Commands</div>
              </div>
              <div class="db-stat-item">
                <div class="db-stat-value" id="db-stat-tasks">0</div>
                <div class="db-stat-label">Tasks</div>
              </div>
              <div class="db-stat-item">
                <div class="db-stat-value" id="db-stat-memory">0</div>
                <div class="db-stat-label">Memories</div>
              </div>
              <div class="db-stat-item">
                <div class="db-stat-value" id="db-stat-messages">0</div>
                <div class="db-stat-label">Messages</div>
              </div>
            </div>
            
            <!-- Data Migration Section -->
            <div id="db-migration" class="db-migration" style="margin-top: 1rem; padding-top: 0.75rem; border-top: 1px solid rgba(255,255,255,0.08);">
              <div style="font-size: 0.75rem; font-weight: 600; color: var(--gray-300); margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.4rem;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polyline points="17 1 21 5 17 9"></polyline>
                  <path d="M3 11V9a4 4 0 0 1 4-4h14"></path>
                  <polyline points="7 23 3 19 7 15"></polyline>
                  <path d="M21 13v2a4 4 0 0 1-4 4H3"></path>
                </svg>
                Data Migration
              </div>
              <p style="font-size: 0.7rem; color: var(--gray-500); margin-bottom: 0.5rem; line-height: 1.4;">
                Export from database or restore backup to local storage.
              </p>
              <div id="local-export-info" style="display: none; font-size: 0.7rem; color: var(--gray-400); margin-bottom: 0.5rem; padding: 0.4rem 0.6rem; background: rgba(255,255,255,0.05); border-radius: 4px;">
                <span id="local-export-date"></span>
              </div>
              <div style="display: flex; gap: 0.4rem; flex-wrap: wrap;">
                <button class="btn btn-secondary" onclick="exportDatabaseToLocal()" style="font-size: 0.7rem; padding: 0.4rem 0.6rem;" title="Export DB to local files">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                    <polyline points="7 10 12 15 17 10"/>
                    <line x1="12" y1="15" x2="12" y2="3"/>
                  </svg>
                  DB → Backup
                </button>
                <button class="btn btn-secondary" onclick="importDatabaseFromLocal()" style="font-size: 0.7rem; padding: 0.4rem 0.6rem;" title="Import backup to database">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                    <polyline points="17 8 12 3 7 8"/>
                    <line x1="12" y1="3" x2="12" y2="15"/>
                  </svg>
                  Backup → DB
                </button>
                <button class="btn btn-secondary" onclick="restoreBackupToLocal()" style="font-size: 0.7rem; padding: 0.4rem 0.6rem;" title="Restore backup to local chat storage">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>
                    <path d="M3 3v5h5"/>
                  </svg>
                  Restore Local
                </button>
              </div>
            </div>
          </div>
          
          <div class="settings-section">
            <div class="settings-section-title">📁 File Storage</div>
            <p style="font-size: 0.8rem; color: var(--gray-400); line-height: 1.5;">
              Local file storage is always enabled as a fallback. Settings, API keys, and chat history 
              are stored in <code style="background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px;">app/</code> directory.
            </p>
          </div>
        </div>
        
        <!-- Public APIs Sub-Tab -->
        <div class="settings-subtab-content" id="settings-api">
          <div class="settings-section">
            <div class="settings-section-title">🔑 Security API Keys</div>
            
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
            <p style="font-size: 0.75rem; color: var(--gray-500); line-height: 1.4;">
              API keys are persisted to disk. Use Export/Import to backup or transfer your keys.
            </p>
          </div>
        </div>
        
        <!-- Communication Sub-Tab -->
        <div class="settings-subtab-content" id="settings-comm">
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
            <div class="settings-section-title">🔔 Notifications</div>
            <p style="font-size: 0.8rem; color: var(--gray-400); line-height: 1.5;">
              Configure notification channels for scan results and alerts.
              (Coming soon: Discord, Slack, Email integrations)
            </p>
          </div>
        </div>
        
        <!-- Tools Management Sub-Tab -->
        <div class="settings-subtab-content" id="settings-tools">
          <div class="settings-section">
            <div class="settings-section-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
              </svg>
              Security Tools
            </div>
            <p style="font-size: 0.8rem; color: var(--gray-400); line-height: 1.5; margin-bottom: 15px;">
              Manage pentesting tools available to the agent. Install, enable, or disable tools as needed.
            </p>
            
            <!-- Tools Filter -->
            <div style="display: flex; gap: 10px; margin-bottom: 15px;">
              <input type="text" id="tools-search" placeholder="Search tools..." 
                style="flex: 1; padding: 8px 12px; background: var(--dark); border: 1px solid rgba(255,255,255,0.1); border-radius: 6px; color: var(--light); font-size: 0.85rem;"
                oninput="filterTools()">
              <select id="tools-category-filter" style="padding: 8px 12px; background: var(--dark); border: 1px solid rgba(255,255,255,0.1); border-radius: 6px; color: var(--light); font-size: 0.85rem;" onchange="filterTools()">
                <option value="">All Categories</option>
                <option value="recon">🔍 Reconnaissance</option>
                <option value="vuln">🛡️ Vulnerability</option>
                <option value="discovery">📂 Discovery</option>
                <option value="webapp">🌐 Web App</option>
                <option value="bruteforce">🔓 Brute Force</option>
                <option value="exploit">💥 Exploitation</option>
                <option value="browser">🖥️ Browser</option>
                <option value="infra">⚙️ Infrastructure</option>
              </select>
              <button class="btn btn-primary" onclick="refreshToolsList()" title="Refresh tools list">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M23 4v6h-6"/>
                  <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                </svg>
              </button>
            </div>
            
            <!-- Tools List Container -->
            <div id="tools-list-container" style="background: var(--dark); border-radius: 8px; padding: 15px; max-height: 500px; overflow-y: auto;">
              <div id="tools-list" style="display: flex; flex-direction: column; gap: 10px;">
                <!-- Tools will be loaded dynamically -->
                <div style="text-align: center; color: var(--gray-400); padding: 20px;">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation: spin 1s linear infinite;">
                    <circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-dashoffset="10"/>
                  </svg>
                  <p style="margin-top: 10px;">Loading tools...</p>
                </div>
              </div>
            </div>
            
            <!-- Legend -->
            <div style="display: flex; gap: 20px; margin-top: 15px; font-size: 0.75rem; color: var(--gray-500);">
              <div style="display: flex; align-items: center; gap: 5px;">
                <div style="width: 8px; height: 8px; border-radius: 50%; background: #10b981;"></div>
                <span>Installed & Enabled</span>
              </div>
              <div style="display: flex; align-items: center; gap: 5px;">
                <div style="width: 8px; height: 8px; border-radius: 50%; background: #f59e0b;"></div>
                <span>Installed & Disabled</span>
              </div>
              <div style="display: flex; align-items: center; gap: 5px;">
                <div style="width: 8px; height: 8px; border-radius: 50%; background: #6b7280;"></div>
                <span>Not Installed</span>
              </div>
            </div>
          </div>
          
          <!-- Quick Install Section -->
          <div class="settings-section">
            <div class="settings-section-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/>
                <line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              Quick Install
            </div>
            <p style="font-size: 0.8rem; color: var(--gray-400); line-height: 1.5; margin-bottom: 15px;">
              Install common tool bundles with one click.
            </p>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;">
              <button class="btn" style="background: rgba(255,255,255,0.05); padding: 12px; text-align: left;" onclick="installToolBundle('recon')">
                <div style="font-weight: 500; margin-bottom: 4px;">🔍 Recon Bundle</div>
                <div style="font-size: 0.75rem; color: var(--gray-400);">nmap, subfinder, httpx, whatweb</div>
              </button>
              <button class="btn" style="background: rgba(255,255,255,0.05); padding: 12px; text-align: left;" onclick="installToolBundle('vuln')">
                <div style="font-weight: 500; margin-bottom: 4px;">🛡️ Vuln Scanner Bundle</div>
                <div style="font-size: 0.75rem; color: var(--gray-400);">nuclei, nikto, sqlmap</div>
              </button>
              <button class="btn" style="background: rgba(255,255,255,0.05); padding: 12px; text-align: left;" onclick="installToolBundle('discovery')">
                <div style="font-weight: 500; margin-bottom: 4px;">📂 Discovery Bundle</div>
                <div style="font-size: 0.75rem; color: var(--gray-400);">gobuster, ffuf, dirb</div>
              </button>
              <button class="btn" style="background: rgba(255,255,255,0.05); padding: 12px; text-align: left;" onclick="installToolBundle('all')">
                <div style="font-weight: 500; margin-bottom: 4px;">⚡ All Essential Tools</div>
                <div style="font-size: 0.75rem; color: var(--gray-400);">Install all recommended tools</div>
              </button>
            </div>
          </div>
        </div>
        
        <!-- General Sub-Tab -->
        <div class="settings-subtab-content" id="settings-general">
          <div class="settings-section">
            <div class="settings-section-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <path d="M2 12h20"/>
                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
              </svg>
              Cloudflare Tunnel
            </div>
            <p style="font-size: 0.8rem; color: var(--gray-400); line-height: 1.5; margin-bottom: 15px;">
              Make your agent accessible from the internet with one click using <a href="https://trycloudflare.com" target="_blank" style="color: var(--primary);">Cloudflare Quick Tunnels</a>.
              No account needed!
            </p>
            
            <div id="tunnel-status-container" style="background: var(--dark); border-radius: 8px; padding: 15px; margin-bottom: 15px;">
              <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                <div id="tunnel-indicator" style="width: 10px; height: 10px; border-radius: 50%; background: var(--gray-600);"></div>
                <span id="tunnel-status-text" style="font-size: 0.85rem; color: var(--gray-300);">Not connected</span>
              </div>
              <div id="tunnel-url-container" style="display: none;">
                <div style="display: flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.05); border-radius: 6px; padding: 10px;">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2">
                    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
                  </svg>
                  <a id="tunnel-url" href="#" target="_blank" style="color: var(--primary); font-size: 0.85rem; word-break: break-all;"></a>
                  <button onclick="copyTunnelUrl()" title="Copy URL" style="background: none; border: none; cursor: pointer; padding: 4px;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--gray-400)" stroke-width="2">
                      <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                    </svg>
                  </button>
                </div>
              </div>
            </div>
            
            <div style="display: flex; gap: 10px;">
              <button id="tunnel-start-btn" class="btn btn-primary" style="flex: 1;" onclick="startTunnel()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;">
                  <circle cx="12" cy="12" r="10"/>
                  <path d="M2 12h20"/>
                  <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                </svg>
                Start Tunnel
              </button>
              <button id="tunnel-stop-btn" class="btn" style="flex: 1; background: rgba(239,68,68,0.2); color: #ef4444; display: none;" onclick="stopTunnel()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;">
                  <rect x="6" y="6" width="12" height="12" rx="2"/>
                </svg>
                Stop Tunnel
              </button>
            </div>
            
            <div id="tunnel-message" style="margin-top: 10px; padding: 10px; border-radius: 6px; font-size: 0.8rem; display: none;"></div>
            
            <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.1);">
              <p style="font-size: 0.75rem; color: var(--gray-500); line-height: 1.5;">
                <strong>Requirements:</strong> <code style="background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px;">cloudflared</code> must be installed.<br>
                <a href="https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/" target="_blank" style="color: var(--primary);">Download cloudflared →</a>
              </p>
            </div>
          </div>
          
          <!-- Proxy Configuration Section -->
          <div class="settings-section">
            <div class="settings-section-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              Proxy Configuration
            </div>
            <p style="font-size: 0.8rem; color: var(--gray-400); line-height: 1.5; margin-bottom: 15px;">
              Route all pentesting tool HTTP/HTTPS requests through a proxy (e.g., Burp Suite, OWASP ZAP).
              Supports HTTP, HTTPS, and SOCKS5 proxies.
            </p>
            
            <!-- Proxy Toggle - Compact Layout -->
            <div style="display: flex; align-items: center; gap: 12px; background: var(--dark); border-radius: 8px; padding: 12px 15px; margin-bottom: 15px;">
              <label class="toggle-switch" style="position: relative; display: inline-block; width: 48px; height: 24px; flex-shrink: 0;">
                <input type="checkbox" id="proxy-enabled-toggle" onchange="toggleProxy(this.checked)" style="opacity: 0; width: 0; height: 0;">
                <span class="toggle-slider" style="position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: var(--gray-600); transition: .3s; border-radius: 24px;"></span>
              </label>
              <div style="display: flex; align-items: center; gap: 8px; min-width: 0;">
                <div id="proxy-indicator" style="width: 8px; height: 8px; border-radius: 50%; background: var(--gray-600); flex-shrink: 0;"></div>
                <span id="proxy-status-text" style="font-size: 0.8rem; color: var(--gray-300); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">Disabled</span>
              </div>
            </div>
            
            <!-- Proxy Configuration Form -->
            <div id="proxy-config-container" style="background: var(--dark); border-radius: 8px; padding: 15px;">
              <div style="display: grid; grid-template-columns: 1fr 2fr 1fr; gap: 10px; margin-bottom: 12px;">
                <div>
                  <label style="font-size: 0.75rem; color: var(--gray-400); margin-bottom: 4px; display: block;">Type</label>
                  <select id="proxy-type" style="width: 100%; padding: 8px 10px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 6px; color: var(--gray-200); font-size: 0.85rem;">
                    <option value="http">HTTP</option>
                    <option value="https">HTTPS</option>
                    <option value="socks5">SOCKS5</option>
                  </select>
                </div>
                <div>
                  <label style="font-size: 0.75rem; color: var(--gray-400); margin-bottom: 4px; display: block;">Host</label>
                  <input type="text" id="proxy-host" placeholder="127.0.0.1" style="width: 100%; padding: 8px 10px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 6px; color: var(--gray-200); font-size: 0.85rem;">
                </div>
                <div>
                  <label style="font-size: 0.75rem; color: var(--gray-400); margin-bottom: 4px; display: block;">Port</label>
                  <input type="text" id="proxy-port" placeholder="8080" style="width: 100%; padding: 8px 10px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 6px; color: var(--gray-200); font-size: 0.85rem;">
                </div>
              </div>
              
              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px;">
                <div>
                  <label style="font-size: 0.75rem; color: var(--gray-400); margin-bottom: 4px; display: block;">Username (optional)</label>
                  <input type="text" id="proxy-username" placeholder="proxy-user" style="width: 100%; padding: 8px 10px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 6px; color: var(--gray-200); font-size: 0.85rem;">
                </div>
                <div>
                  <label style="font-size: 0.75rem; color: var(--gray-400); margin-bottom: 4px; display: block;">Password (optional)</label>
                  <input type="password" id="proxy-password" placeholder="••••••••" style="width: 100%; padding: 8px 10px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 6px; color: var(--gray-200); font-size: 0.85rem;">
                </div>
              </div>
              
              <div style="display: flex; gap: 10px;">
                <button class="btn btn-primary" style="flex: 1;" onclick="saveProxyConfig()">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;">
                    <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
                    <polyline points="17 21 17 13 7 13 7 21"/>
                    <polyline points="7 3 7 8 15 8"/>
                  </svg>
                  Save Configuration
                </button>
                <button class="btn" style="background: rgba(255,255,255,0.1);" onclick="testProxyConnection()">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                  </svg>
                  Test
                </button>
              </div>
              
              <div id="proxy-message" style="margin-top: 10px; padding: 10px; border-radius: 6px; font-size: 0.8rem; display: none;"></div>
            </div>
            
            <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.1);">
              <p style="font-size: 0.75rem; color: var(--gray-500); line-height: 1.5;">
                <strong>Supported Tools:</strong> nikto, gobuster, ffuf, nuclei, sqlmap, whatweb, curl, wget, and more.<br>
                <strong>Tip:</strong> Use <code style="background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px;">127.0.0.1:8080</code> for Burp Suite or ZAP.
              </p>
            </div>
          </div>
          
          <div class="settings-section">
            <div class="settings-section-title">ℹ️ About</div>
            <p style="font-size: 0.8rem; color: var(--gray-400); line-height: 1.5;">
              OWASP Security Agent - AI-powered security testing assistant.<br>
              Built with FastAPI, smolagents, and modern web technologies.
            </p>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Scheduled Tasks Tab Content -->
    <div class="tab-content" id="tab-scheduled">
      <div class="sidebar-header scheduled-header">
        <span class="header-title">
          <span class="header-icon-wrapper scheduled-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"></circle>
              <polyline points="12 6 12 12 16 14"></polyline>
            </svg>
          </span>
          Scheduled Tasks
        </span>
        <button class="btn-add-scheduled" onclick="showScheduleModal()" title="Create New Scheduled Task">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="12" y1="5" x2="12" y2="19"></line>
            <line x1="5" y1="12" x2="19" y2="12"></line>
          </svg>
          <span>New</span>
        </button>
      </div>
      <div class="scheduled-list-container">
        <div id="scheduled-list">
          <div class="no-scheduled-tasks">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <circle cx="12" cy="12" r="10"></circle>
              <polyline points="12 6 12 12 16 14"></polyline>
            </svg>
            <span>No scheduled tasks</span>
            <span class="no-scheduled-hint">Schedule recurring security scans</span>
          </div>
        </div>
      </div>
    </div>
  </div>
  
  <!-- Schedule Task Modal - Premium Design -->
  <div class="task-modal" id="schedule-modal">
    <div class="task-modal-content schedule-modal-content">
      <div class="task-modal-header schedule-modal-header">
        <div class="schedule-modal-title-wrapper">
          <span class="schedule-modal-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"></circle>
              <polyline points="12 6 12 12 16 14"></polyline>
            </svg>
          </span>
          <div>
            <span class="task-modal-title">Schedule Task</span>
            <span class="schedule-modal-subtitle">Automate recurring security scans</span>
          </div>
        </div>
        <button class="task-modal-close" onclick="closeScheduleModal()">&times;</button>
      </div>
      <div class="task-modal-body schedule-modal-body">
        <div class="schedule-form">
          <div class="schedule-form-section">
            <div class="form-group">
              <label class="form-label">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                  <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                  <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                </svg>
                Task Name
              </label>
              <input type="text" id="schedule-name" class="schedule-input" placeholder="e.g., Daily security scan">
            </div>
            <div class="form-group">
              <label class="form-label">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                  <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                  <polyline points="2 17 12 22 22 17"></polyline>
                  <polyline points="2 12 12 17 22 12"></polyline>
                </svg>
                Task Prompt
              </label>
              <textarea id="schedule-prompt" class="schedule-textarea" placeholder="e.g., Run nmap -sV scan on target.com and report findings..." rows="3"></textarea>
            </div>
          </div>
          
          <div class="schedule-form-section schedule-timing-section">
            <div class="form-group">
              <label class="form-label">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                  <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect>
                  <line x1="16" y1="2" x2="16" y2="6"></line>
                  <line x1="8" y1="2" x2="8" y2="6"></line>
                  <line x1="3" y1="10" x2="21" y2="10"></line>
                </svg>
                Schedule Time
              </label>
              <input type="datetime-local" id="schedule-time" class="schedule-input schedule-datetime">
            </div>
            
            <div class="schedule-recurring-toggle">
              <label class="checkbox-wrapper schedule-checkbox">
                <input type="checkbox" id="schedule-recurring">
                <span class="checkmark"></span>
                <span class="checkbox-label">
                  <span class="label-icon">🔄</span>
                  <span>Make this a recurring task</span>
                </span>
              </label>
            </div>
            
            <div id="recurring-options" class="recurring-options">
              <label class="form-label">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                  <polyline points="23 4 23 10 17 10"></polyline>
                  <polyline points="1 20 1 14 7 14"></polyline>
                  <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
                </svg>
                Repeat Interval
              </label>
              <div class="recurring-interval-row">
                <input type="number" id="schedule-interval" class="schedule-input interval-input" value="60" min="5">
                <span class="interval-label">minutes</span>
              </div>
              <div class="recurring-presets">
                <button type="button" class="preset-btn" onclick="setInterval(30)">30m</button>
                <button type="button" class="preset-btn" onclick="setInterval(60)">1h</button>
                <button type="button" class="preset-btn" onclick="setInterval(360)">6h</button>
                <button type="button" class="preset-btn" onclick="setInterval(1440)">24h</button>
              </div>
            </div>
          </div>
          
          <button class="btn btn-primary schedule-submit-btn" onclick="createScheduledTask()">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
              <circle cx="12" cy="12" r="10"></circle>
              <polyline points="12 6 12 12 16 14"></polyline>
            </svg>
            Schedule Task
          </button>
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
        <div class="input-row">
          <div class="input-wrapper">
            <div class="input-container">
              <textarea id="message-input" placeholder="Ask about OWASP, run security scans, use specific tools..." rows="1"></textarea>
              <div id="attached-files"></div>
              <div class="input-toolbar">
                <div class="input-toolbar-left">
                  <input type="file" id="file-input" multiple accept=".txt,.json,.xml,.html,.log,.csv,.md,.py,.js,.yaml,.yml,.conf,.cfg,.ini" style="display:none;">
                  <button type="button" class="toolbar-btn toolbar-btn-attach" onclick="document.getElementById('file-input').click()" title="Attach files">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                      <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"></path>
                    </svg>
                    <span>Attach</span>
                  </button>
                  <span class="toolbar-divider"></span>
                  <button type="button" class="toolbar-btn" id="bg-task-btn" onclick="toggleBackgroundTask()" title="Run as background task">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                      <circle cx="12" cy="12" r="10"></circle>
                      <polyline points="12 6 12 12 16 14"></polyline>
                    </svg>
                    <span>Background</span>
                  </button>
                </div>
                <div class="input-toolbar-right">
                  <span id="char-counter" style="font-size:0.7rem;color:var(--gray-500);"></span>
                </div>
              </div>
            </div>
            <input type="checkbox" id="background-task-checkbox" style="display:none;">
          </div>
          <button class="btn btn-primary btn-send" id="send-btn" title="Send message">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="22" y1="2" x2="11" y2="13"></line>
              <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
            </svg>
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
const activityTabsHeader = document.getElementById('activity-tabs-header');
const activityPanels = document.getElementById('activity-panels');
const noActivityMessage = document.getElementById('no-activity-message');
const reportToggle = document.getElementById('report-toggle');
const reportCheckbox = document.getElementById('report-mode-checkbox');
const fileInput = document.getElementById('file-input');
const attachedFilesDiv = document.getElementById('attached-files');
const backgroundTaskCheckbox = document.getElementById('background-task-checkbox');

// Activity Monitor - Multi-task management
const activityTasks = {};  // taskId -> { logs: [], status: 'running'|'completed'|'failed', startTime, stepCount, toolCount, prompt }
let currentActivityTaskId = null;

// Stats (legacy compatibility)
let stepCount = 0;
let toolCount = 0;
let startTime = null;
let durationInterval = null;

// File attachments storage
let attachedFiles = [];
let sessionId = 'default';  // Match currentChatId for consistency

let chatHistory = [];
let currentReport = { html: null, markdown: null };

// Determine WebSocket protocol based on page protocol (ws for http, wss for https)
const wsProtocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
const ws = new WebSocket(`${wsProtocol}//${location.host}/ws`);

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
    
    // Load API keys and provider settings when settings tab is opened
    if (tabId === 'settings') {
      loadApiKeys();
      loadProviders();
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
    
    // Check if we have an HTML report
    const hasHtmlReport = task.report_html && task.report_html.includes('<!DOCTYPE html');
    
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
    
    // Build the modal content
    let reportButtonHtml = '';
    if (hasHtmlReport) {
      reportButtonHtml = `
        <div style="margin: 1rem 0; padding: 0.75rem; background: linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(5, 150, 105, 0.1) 100%); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px;">
          <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
            <span style="font-size: 1.2rem;">📋</span>
            <strong style="color: var(--success);">Security Report Available</strong>
          </div>
          <p style="font-size: 0.8rem; color: var(--gray-300); margin-bottom: 0.75rem;">A professional HTML report was generated for this task.</p>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
            <button class="btn btn-primary" onclick="viewTaskReport('${taskId}')" style="font-size: 0.8rem; padding: 0.5rem 1rem;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 0.3rem;">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
                <line x1="16" y1="13" x2="8" y2="13"/>
                <line x1="16" y1="17" x2="8" y2="17"/>
              </svg>
              View Report
            </button>
            <button class="btn btn-secondary" onclick="downloadTaskReport('${taskId}')" style="font-size: 0.8rem; padding: 0.5rem 1rem;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 0.3rem;">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/>
                <line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              Download
            </button>
          </div>
        </div>
      `;
    }
    
    body.innerHTML = `
      <div style="margin-bottom: 1rem;">
        <strong>Status:</strong> <span class="task-status ${task.status}">${task.status}</span><br>
        <strong>Steps:</strong> ${task.step_count} | <strong>Tools Used:</strong> ${task.tool_count}<br>
        ${task.error ? `<strong style="color: var(--danger);">Error:</strong> ${task.error}` : ''}
      </div>
      ${reportButtonHtml}
      <hr style="border-color: rgba(255,255,255,0.1); margin: 1rem 0;">
      <div style="white-space: pre-wrap; word-break: break-word;">${resultHtml}</div>
    `;
    
    modal.classList.add('active');
  } catch (err) {
    alert('Failed to load task result: ' + err.message);
  }
}

// View task report in new window
function viewTaskReport(taskId) {
  const task = taskStore[taskId];
  if (task && task.report_html) {
    const newWindow = window.open('', '_blank');
    newWindow.document.write(task.report_html);
    newWindow.document.close();
  } else {
    // Fetch from server
    fetch(`/api/tasks/${taskId}`)
      .then(r => r.json())
      .then(t => {
        if (t.report_html) {
          const newWindow = window.open('', '_blank');
          newWindow.document.write(t.report_html);
          newWindow.document.close();
        } else {
          alert('No report available for this task');
        }
      });
  }
}

// Download task report
function downloadTaskReport(taskId) {
  fetch(`/api/tasks/${taskId}`)
    .then(r => r.json())
    .then(t => {
      if (t.report_html) {
        const blob = new Blob([t.report_html], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security-report-${taskId}.html`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        alert('No report available for this task');
      }
    });
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

// Provider management
let providersData = [];
let currentProvider = 'deepseek';
let currentModel = 'deepseek-chat';

async function loadProviders() {
  try {
    // Load available providers
    const providersResponse = await fetch('/api/providers');
    providersData = await providersResponse.json();
    
    // Load current settings
    const settingsResponse = await fetch('/api/provider/settings');
    const settings = await settingsResponse.json();
    
    currentProvider = settings.provider || 'deepseek';
    currentModel = settings.model || 'deepseek-chat';
    
    // Populate provider dropdown
    const providerSelect = document.getElementById('provider-select');
    if (providerSelect) {
      providerSelect.innerHTML = providersData.map(p => 
        `<option value="${p.id}" ${p.id === currentProvider ? 'selected' : ''}>${p.name}</option>`
      ).join('');
    }
    
    // Populate model dropdown
    updateModelDropdown();
    
    // Update key status
    updateProviderKeyStatus();
    
    // Update key label
    updateProviderKeyLabel();
  } catch (err) {
    console.error('Failed to load providers:', err);
  }
}

function updateModelDropdown() {
  const modelSelect = document.getElementById('model-select');
  if (!modelSelect) return;
  
  const provider = providersData.find(p => p.id === currentProvider);
  
  if (provider && provider.models) {
    // Group models by category
    const freeModels = provider.models.filter(m => m.category === 'free');
    const paidModels = provider.models.filter(m => m.category === 'paid' || !m.category);
    
    let html = '';
    
    // Add free models group if any exist
    if (freeModels.length > 0) {
      html += '<optgroup label="🆓 Free Models">';
      html += freeModels.map(m => 
        `<option value="${m.id}" ${m.id === currentModel ? 'selected' : ''}>${m.name}</option>`
      ).join('');
      html += '</optgroup>';
    }
    
    // Add paid models group
    if (paidModels.length > 0) {
      html += '<optgroup label="💳 Paid Models">';
      html += paidModels.map(m => 
        `<option value="${m.id}" ${m.id === currentModel ? 'selected' : ''}>${m.name}</option>`
      ).join('');
      html += '</optgroup>';
    }
    
    modelSelect.innerHTML = html;
  }
}

function updateProviderKeyLabel() {
  const label = document.getElementById('provider-key-label');
  if (!label) return;
  
  const provider = providersData.find(p => p.id === currentProvider);
  label.textContent = provider ? provider.name : currentProvider;
}

async function updateProviderKeyStatus() {
  try {
    const response = await fetch(`/api/provider/key/${currentProvider}`);
    const data = await response.json();
    
    const statusEl = document.getElementById('provider-key-status');
    const keyInput = document.getElementById('provider-api-key');
    
    if (!statusEl || !keyInput) return;
    
    if (data.has_key) {
      statusEl.innerHTML = `<span style="color: var(--success);">✓ Key configured</span> <span style="opacity: 0.7;">(${data.masked_key})</span>`;
      keyInput.value = '••••••••••••••••';
      keyInput.setAttribute('data-configured', 'true');
    } else {
      statusEl.innerHTML = '<span style="color: var(--warning);">⚠ No API key configured</span>';
      keyInput.value = '';
      keyInput.removeAttribute('data-configured');
    }
  } catch (err) {
    console.error('Failed to get key status:', err);
  }
}

function onProviderChange() {
  const providerSelect = document.getElementById('provider-select');
  if (!providerSelect) return;
  
  currentProvider = providerSelect.value;
  
  // Update model dropdown with new provider's models
  const provider = providersData.find(p => p.id === currentProvider);
  if (provider) {
    currentModel = provider.default_model;
  }
  
  updateModelDropdown();
  updateProviderKeyLabel();
  updateProviderKeyStatus();
}

async function saveProviderKey() {
  const keyInput = document.getElementById('provider-api-key');
  if (!keyInput) return;
  
  const value = keyInput.value.trim();
  
  if (!value || value === '••••••••••••••••') {
    showProviderStatus('Please enter a valid API key', 'error');
    return;
  }
  
  try {
    const response = await fetch('/api/provider/key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: currentProvider, api_key: value })
    });
    
    const data = await response.json();
    
    if (data.success) {
      keyInput.value = '••••••••••••••••';
      keyInput.setAttribute('data-configured', 'true');
      showProviderStatus('API key saved successfully', 'success');
      updateProviderKeyStatus();
    } else {
      showProviderStatus(data.error || 'Failed to save key', 'error');
    }
  } catch (err) {
    showProviderStatus(`Error: ${err.message}`, 'error');
  }
}

async function applyProviderSettings() {
  const providerSelect = document.getElementById('provider-select');
  const modelSelect = document.getElementById('model-select');
  
  if (!providerSelect || !modelSelect) return;
  
  const provider = providerSelect.value;
  const model = modelSelect.value;
  
  showProviderStatus('Applying settings...', 'info');
  
  try {
    const response = await fetch('/api/provider/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider, model })
    });
    
    const data = await response.json();
    
    if (data.success) {
      currentProvider = provider;
      currentModel = model;
      showProviderStatus(data.message, 'success');
      addMessage('system', `🔄 ${data.message}`);
    } else {
      showProviderStatus(data.error || 'Failed to apply settings', 'error');
    }
  } catch (err) {
    showProviderStatus(`Error: ${err.message}`, 'error');
  }
}

function showProviderStatus(message, type) {
  const statusEl = document.getElementById('provider-status');
  if (!statusEl) return;
  
  statusEl.textContent = message;
  statusEl.className = `provider-status-${type}`;
  statusEl.style.display = 'block';
  
  if (type === 'success' || type === 'info') {
    setTimeout(() => {
      statusEl.style.display = 'none';
    }, 3000);
  }
}

// ============== SETTINGS SUB-TABS ==============
function switchSettingsSubtab(subtab) {
  // Update tab buttons
  document.querySelectorAll('.settings-subtab').forEach(btn => {
    btn.classList.remove('active');
    if (btn.getAttribute('data-subtab') === subtab) {
      btn.classList.add('active');
      // Scroll the active tab into view
      btn.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
    }
  });
  
  // Update content panels
  document.querySelectorAll('.settings-subtab-content').forEach(panel => {
    panel.classList.remove('active');
  });
  const activePanel = document.getElementById('settings-' + subtab);
  if (activePanel) {
    activePanel.classList.add('active');
  }
  
  // Load data for specific tabs
  if (subtab === 'storage') {
    loadDatabaseSettings();
  } else if (subtab === 'general') {
    checkTunnelStatus();
    checkProxyStatus();
  } else if (subtab === 'tools') {
    loadToolsList();
  }
  
  // Update scroll arrows visibility
  updateSubtabsScrollArrows();
}

// Scroll subtabs left or right
function scrollSubtabs(direction) {
  const container = document.getElementById('settings-subtabs-container');
  if (container) {
    const scrollAmount = 100;
    container.scrollBy({ left: direction * scrollAmount, behavior: 'smooth' });
    setTimeout(updateSubtabsScrollArrows, 300);
  }
}

// Update visibility of scroll arrows based on scroll position
function updateSubtabsScrollArrows() {
  const container = document.getElementById('settings-subtabs-container');
  const leftArrow = document.getElementById('subtabs-scroll-left');
  const rightArrow = document.getElementById('subtabs-scroll-right');
  
  if (!container || !leftArrow || !rightArrow) return;
  
  const canScrollLeft = container.scrollLeft > 5;
  const canScrollRight = container.scrollLeft < (container.scrollWidth - container.clientWidth - 5);
  
  leftArrow.classList.toggle('visible', canScrollLeft);
  rightArrow.classList.toggle('visible', canScrollRight);
}

// Initialize subtabs scroll on load
document.addEventListener('DOMContentLoaded', () => {
  const container = document.getElementById('settings-subtabs-container');
  if (container) {
    container.addEventListener('scroll', updateSubtabsScrollArrows);
    // Initial check
    setTimeout(updateSubtabsScrollArrows, 100);
  }
});

// ============== CLOUDFLARE TUNNEL MANAGEMENT ==============
let tunnelCheckInterval = null;

async function checkTunnelStatus() {
  try {
    const response = await fetch('/api/tunnel/status');
    const data = await response.json();
    updateTunnelUI(data.running, data.url);
  } catch (error) {
    console.error('Failed to check tunnel status:', error);
  }
}

function updateTunnelUI(isRunning, url) {
  const indicator = document.getElementById('tunnel-indicator');
  const statusText = document.getElementById('tunnel-status-text');
  const urlContainer = document.getElementById('tunnel-url-container');
  const urlLink = document.getElementById('tunnel-url');
  const startBtn = document.getElementById('tunnel-start-btn');
  const stopBtn = document.getElementById('tunnel-stop-btn');
  
  if (isRunning) {
    indicator.style.background = '#10b981';
    indicator.style.boxShadow = '0 0 10px rgba(16, 185, 129, 0.5)';
    statusText.textContent = 'Connected';
    statusText.style.color = '#10b981';
    startBtn.style.display = 'none';
    stopBtn.style.display = 'flex';
    
    if (url) {
      urlContainer.style.display = 'block';
      urlLink.href = url;
      urlLink.textContent = url;
    }
  } else {
    indicator.style.background = 'var(--gray-600)';
    indicator.style.boxShadow = 'none';
    statusText.textContent = 'Not connected';
    statusText.style.color = 'var(--gray-300)';
    urlContainer.style.display = 'none';
    startBtn.style.display = 'flex';
    stopBtn.style.display = 'none';
  }
}

function showTunnelMessage(message, isError = false) {
  const msgEl = document.getElementById('tunnel-message');
  msgEl.textContent = message;
  msgEl.style.display = 'block';
  msgEl.style.background = isError ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)';
  msgEl.style.color = isError ? '#ef4444' : '#10b981';
  
  setTimeout(() => {
    msgEl.style.display = 'none';
  }, 5000);
}

async function startTunnel() {
  const startBtn = document.getElementById('tunnel-start-btn');
  startBtn.disabled = true;
  startBtn.innerHTML = '<svg class="spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;"><path d="M21 12a9 9 0 11-6.219-8.56"/></svg> Starting...';
  
  try {
    const response = await fetch('/api/tunnel/start', { method: 'POST' });
    const data = await response.json();
    
    if (data.success) {
      showTunnelMessage(data.message);
      
      // Start polling for URL if not immediately available
      if (!data.url) {
        let pollCount = 0;
        const pollInterval = setInterval(async () => {
          pollCount++;
          const statusResp = await fetch('/api/tunnel/status');
          const statusData = await statusResp.json();
          
          if (statusData.url) {
            clearInterval(pollInterval);
            updateTunnelUI(true, statusData.url);
          } else if (pollCount > 30) {
            clearInterval(pollInterval);
            showTunnelMessage('Tunnel started but URL not available yet. Try checking status again.', false);
          }
        }, 1000);
      } else {
        updateTunnelUI(true, data.url);
      }
    } else {
      showTunnelMessage(data.message, true);
      updateTunnelUI(false, null);
    }
  } catch (error) {
    showTunnelMessage('Failed to start tunnel: ' + error.message, true);
    updateTunnelUI(false, null);
  }
  
  startBtn.disabled = false;
  startBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg> Start Tunnel';
}

async function stopTunnel() {
  const stopBtn = document.getElementById('tunnel-stop-btn');
  stopBtn.disabled = true;
  stopBtn.innerHTML = '<svg class="spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;"><path d="M21 12a9 9 0 11-6.219-8.56"/></svg> Stopping...';
  
  try {
    const response = await fetch('/api/tunnel/stop', { method: 'POST' });
    const data = await response.json();
    
    if (data.success) {
      showTunnelMessage(data.message);
      updateTunnelUI(false, null);
    } else {
      showTunnelMessage(data.message || 'Failed to stop tunnel', true);
    }
  } catch (error) {
    showTunnelMessage('Failed to stop tunnel: ' + error.message, true);
  }
  
  stopBtn.disabled = false;
  stopBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;"><rect x="6" y="6" width="12" height="12" rx="2"/></svg> Stop Tunnel';
}

function copyTunnelUrl() {
  const urlEl = document.getElementById('tunnel-url');
  if (urlEl && urlEl.textContent) {
    navigator.clipboard.writeText(urlEl.textContent).then(() => {
      showTunnelMessage('URL copied to clipboard!');
    }).catch(err => {
      showTunnelMessage('Failed to copy URL', true);
    });
  }
}

// ============== PROXY CONFIGURATION MANAGEMENT ==============

async function checkProxyStatus() {
  try {
    const response = await fetch('/api/proxy/status');
    const data = await response.json();
    
    // Update toggle
    const toggle = document.getElementById('proxy-enabled-toggle');
    if (toggle) toggle.checked = data.enabled;
    
    // Update form fields
    if (data.type) document.getElementById('proxy-type').value = data.type;
    if (data.host) document.getElementById('proxy-host').value = data.host;
    if (data.port) document.getElementById('proxy-port').value = data.port;
    if (data.username) document.getElementById('proxy-username').value = data.username;
    
    // Update status display
    updateProxyUI(data.enabled, data.proxy_url);
  } catch (error) {
    console.error('Failed to check proxy status:', error);
  }
}

function updateProxyUI(isEnabled, proxyUrl) {
  const indicator = document.getElementById('proxy-indicator');
  const statusText = document.getElementById('proxy-status-text');
  
  if (isEnabled && proxyUrl) {
    indicator.style.background = '#10b981';
    indicator.style.boxShadow = '0 0 8px rgba(16, 185, 129, 0.5)';
    statusText.textContent = 'Enabled';
    statusText.style.color = '#10b981';
  } else {
    indicator.style.background = 'var(--gray-600)';
    indicator.style.boxShadow = 'none';
    statusText.textContent = 'Disabled';
    statusText.style.color = 'var(--gray-300)';
  }
}

function showProxyMessage(message, isError = false) {
  const msgEl = document.getElementById('proxy-message');
  msgEl.textContent = message;
  msgEl.style.display = 'block';
  msgEl.style.background = isError ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)';
  msgEl.style.color = isError ? '#ef4444' : '#10b981';
  
  setTimeout(() => {
    msgEl.style.display = 'none';
  }, 5000);
}

async function saveProxyConfig() {
  const config = {
    type: document.getElementById('proxy-type').value,
    host: document.getElementById('proxy-host').value.trim(),
    port: document.getElementById('proxy-port').value.trim(),
    username: document.getElementById('proxy-username').value.trim(),
    password: document.getElementById('proxy-password').value
  };
  
  if (!config.host) {
    showProxyMessage('Please enter a proxy host', true);
    return;
  }
  
  try {
    const response = await fetch('/api/proxy/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    });
    const data = await response.json();
    
    if (data.success) {
      showProxyMessage('Proxy configuration saved');
      // Clear password field after save for security
      document.getElementById('proxy-password').value = '';
    } else {
      showProxyMessage(data.message || 'Failed to save configuration', true);
    }
  } catch (error) {
    showProxyMessage('Failed to save: ' + error.message, true);
  }
}

async function toggleProxy(enabled) {
  // First save the current config if enabling
  if (enabled) {
    const host = document.getElementById('proxy-host').value.trim();
    if (!host) {
      document.getElementById('proxy-enabled-toggle').checked = false;
      showProxyMessage('Please configure and save proxy settings first', true);
      return;
    }
  }
  
  try {
    const response = await fetch('/api/proxy/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled })
    });
    const data = await response.json();
    
    if (data.success) {
      updateProxyUI(data.enabled, data.proxy_url);
      showProxyMessage(data.message);
    } else {
      document.getElementById('proxy-enabled-toggle').checked = !enabled;
      showProxyMessage(data.message || 'Failed to toggle proxy', true);
    }
  } catch (error) {
    document.getElementById('proxy-enabled-toggle').checked = !enabled;
    showProxyMessage('Failed to toggle proxy: ' + error.message, true);
  }
}

async function testProxyConnection() {
  const host = document.getElementById('proxy-host').value.trim();
  
  if (!host) {
    showProxyMessage('Please enter a proxy host first', true);
    return;
  }
  
  // First save the config
  const config = {
    type: document.getElementById('proxy-type').value,
    host: host,
    port: document.getElementById('proxy-port').value.trim(),
    username: document.getElementById('proxy-username').value.trim(),
    password: document.getElementById('proxy-password').value
  };
  
  try {
    // Save config first
    await fetch('/api/proxy/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    });
    
    // Temporarily enable proxy for test
    await fetch('/api/proxy/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: true })
    });
    
    showProxyMessage('Testing connection to ifconfig.io...');
    
    // Test the connection
    const testResponse = await fetch('/api/proxy/test', { method: 'POST' });
    const testData = await testResponse.json();
    
    if (testData.success) {
      showProxyMessage(`✓ Proxy working! Your IP: ${testData.ip}`);
      document.getElementById('proxy-enabled-toggle').checked = true;
      updateProxyUI(true, config.type + '://' + config.host + ':' + config.port);
    } else {
      // Disable proxy on failure
      await fetch('/api/proxy/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: false })
      });
      document.getElementById('proxy-enabled-toggle').checked = false;
      updateProxyUI(false, null);
      showProxyMessage('Test failed: ' + testData.message, true);
    }
    
    // Clear password field
    document.getElementById('proxy-password').value = '';
  } catch (error) {
    showProxyMessage('Test failed: ' + error.message, true);
  }
}

// ============== TOOLS MANAGEMENT ==============
let toolsData = [];

async function loadToolsList() {
  const container = document.getElementById('tools-list');
  
  try {
    const response = await fetch('/api/tools/list');
    const data = await response.json();
    
    toolsData = data.tools;
    renderToolsList(toolsData);
  } catch (error) {
    container.innerHTML = `
      <div style="text-align: center; color: #ef4444; padding: 20px;">
        <p>Failed to load tools: ${error.message}</p>
        <button class="btn btn-primary" style="margin-top: 10px;" onclick="loadToolsList()">Retry</button>
      </div>
    `;
  }
}

function renderToolsList(tools) {
  const container = document.getElementById('tools-list');
  
  if (!tools || tools.length === 0) {
    container.innerHTML = '<p style="text-align: center; color: var(--gray-400);">No tools found</p>';
    return;
  }
  
  // Group by category
  const grouped = {};
  const categoryNames = {
    'recon': '🔍 Reconnaissance',
    'vuln': '🛡️ Vulnerability Scanning',
    'discovery': '📂 Content Discovery',
    'webapp': '🌐 Web Application',
    'bruteforce': '🔓 Brute Force',
    'exploit': '💥 Exploitation',
    'browser': '🖥️ Browser Automation',
    'infra': '⚙️ Infrastructure',
  };
  
  tools.forEach(tool => {
    if (!grouped[tool.category]) {
      grouped[tool.category] = [];
    }
    grouped[tool.category].push(tool);
  });
  
  let html = '';
  
  for (const [category, categoryTools] of Object.entries(grouped)) {
    html += `
      <div class="tools-category" style="margin-bottom: 15px;">
        <div style="font-weight: 500; color: var(--gray-300); margin-bottom: 8px; font-size: 0.9rem;">
          ${categoryNames[category] || category}
        </div>
        <div style="display: flex; flex-direction: column; gap: 8px;">
    `;
    
    categoryTools.forEach(tool => {
      const statusColor = tool.installed 
        ? (tool.enabled ? '#10b981' : '#f59e0b') 
        : '#6b7280';
      const statusText = tool.installed 
        ? (tool.enabled ? 'Enabled' : 'Disabled') 
        : 'Not Installed';
      
      html += `
        <div class="tool-item" data-tool-id="${tool.id}" data-category="${tool.category}"
          style="display: flex; align-items: center; gap: 12px; padding: 10px 12px; background: rgba(255,255,255,0.03); border-radius: 6px; transition: all 0.2s;">
          
          <div style="width: 8px; height: 8px; border-radius: 50%; background: ${statusColor}; flex-shrink: 0;"></div>
          
          <div style="flex: 1; min-width: 0;">
            <div style="font-weight: 500; color: var(--light); font-size: 0.9rem;">${tool.name}</div>
            <div style="font-size: 0.75rem; color: var(--gray-500); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${tool.description}</div>
          </div>
          
          <div style="display: flex; gap: 6px; flex-shrink: 0;">
            ${tool.installed ? `
              <label class="toggle-switch" style="width: 40px; height: 20px;">
                <input type="checkbox" ${tool.enabled ? 'checked' : ''} onchange="toggleTool('${tool.id}', this.checked)" style="opacity: 0; width: 0; height: 0;">
                <span class="toggle-slider" style="position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: var(--gray-600); transition: .3s; border-radius: 20px;"></span>
              </label>
            ` : `
              <button class="btn btn-sm" style="padding: 4px 10px; font-size: 0.75rem; background: rgba(59,130,246,0.2); color: #3b82f6;" onclick="installTool('${tool.id}')">
                Install
              </button>
            `}
            <button class="btn btn-sm" style="padding: 4px 8px; background: transparent;" onclick="showToolDetails('${tool.id}')" title="Details">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <path d="M12 16v-4"/>
                <path d="M12 8h.01"/>
              </svg>
            </button>
          </div>
        </div>
      `;
    });
    
    html += '</div></div>';
  }
  
  container.innerHTML = html;
}

function filterTools() {
  const searchTerm = document.getElementById('tools-search').value.toLowerCase();
  const categoryFilter = document.getElementById('tools-category-filter').value;
  
  const filtered = toolsData.filter(tool => {
    const matchesSearch = !searchTerm || 
      tool.name.toLowerCase().includes(searchTerm) || 
      tool.description.toLowerCase().includes(searchTerm) ||
      tool.id.toLowerCase().includes(searchTerm);
    const matchesCategory = !categoryFilter || tool.category === categoryFilter;
    return matchesSearch && matchesCategory;
  });
  
  renderToolsList(filtered);
}

async function refreshToolsList() {
  await loadToolsList();
}

async function toggleTool(toolId, enabled) {
  try {
    const response = await fetch(`/api/tools/toggle/${toolId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled })
    });
    const data = await response.json();
    
    if (data.success) {
      // Update local state
      const tool = toolsData.find(t => t.id === toolId);
      if (tool) tool.enabled = enabled;
      
      showToolsMessage(data.message);
    } else {
      showToolsMessage(data.message || 'Failed to toggle tool', true);
      // Revert toggle
      await loadToolsList();
    }
  } catch (error) {
    showToolsMessage('Error: ' + error.message, true);
    await loadToolsList();
  }
}

async function installTool(toolId) {
  const tool = toolsData.find(t => t.id === toolId);
  
  showToolsMessage(`Installing ${tool?.name || toolId}... This may take a while.`);
  
  try {
    const response = await fetch(`/api/tools/install/${toolId}`, {
      method: 'POST'
    });
    const data = await response.json();
    
    if (data.success) {
      showToolsMessage(data.message);
      await loadToolsList();
    } else if (data.instructions) {
      // Manual installation required
      showToolsMessage(`Manual installation required: ${data.install_cmd}`, true);
      // Copy to clipboard
      navigator.clipboard.writeText(data.install_cmd).then(() => {
        showToolsMessage(`Install command copied to clipboard: ${data.install_cmd}`);
      });
    } else {
      showToolsMessage(data.message || 'Installation failed', true);
    }
  } catch (error) {
    showToolsMessage('Installation error: ' + error.message, true);
  }
}

function showToolDetails(toolId) {
  const tool = toolsData.find(t => t.id === toolId);
  if (!tool) return;
  
  const modal = document.createElement('div');
  modal.className = 'modal-overlay';
  modal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 10000;';
  
  modal.innerHTML = `
    <div style="background: var(--darker); border-radius: 12px; padding: 24px; max-width: 450px; width: 90%; max-height: 80vh; overflow-y: auto;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <h3 style="margin: 0; color: var(--light);">${tool.name}</h3>
        <button onclick="this.closest('.modal-overlay').remove()" style="background: none; border: none; color: var(--gray-400); cursor: pointer; font-size: 1.5rem;">&times;</button>
      </div>
      
      <div style="margin-bottom: 16px;">
        <div style="font-size: 0.85rem; color: var(--gray-400); margin-bottom: 8px;">Description</div>
        <p style="margin: 0; color: var(--gray-200);">${tool.description}</p>
      </div>
      
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px;">
        <div>
          <div style="font-size: 0.75rem; color: var(--gray-500);">Category</div>
          <div style="color: var(--gray-300);">${tool.category}</div>
        </div>
        <div>
          <div style="font-size: 0.75rem; color: var(--gray-500);">Status</div>
          <div style="color: ${tool.installed ? '#10b981' : '#6b7280'};">${tool.installed ? 'Installed' : 'Not Installed'}</div>
        </div>
      </div>
      
      <div style="margin-bottom: 16px;">
        <div style="font-size: 0.85rem; color: var(--gray-400); margin-bottom: 8px;">Installation Command</div>
        <div style="background: var(--dark); padding: 10px; border-radius: 6px; font-family: monospace; font-size: 0.8rem; color: var(--gray-300); word-break: break-all;">
          ${tool.install_cmd}
        </div>
        <button class="btn btn-sm" style="margin-top: 8px; padding: 6px 12px; font-size: 0.8rem;" onclick="navigator.clipboard.writeText('${tool.install_cmd.replace(/'/g, "\\'")}'); this.textContent = 'Copied!'">
          Copy Command
        </button>
      </div>
      
      ${!tool.installed ? `
        <button class="btn btn-primary" style="width: 100%;" onclick="installTool('${tool.id}'); this.closest('.modal-overlay').remove();">
          Install ${tool.name}
        </button>
      ` : ''}
    </div>
  `;
  
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.remove();
  });
  
  document.body.appendChild(modal);
}

function showToolsMessage(message, isError = false) {
  // Use a toast notification
  const toast = document.createElement('div');
  toast.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 12px 20px;
    background: ${isError ? 'rgba(239,68,68,0.9)' : 'rgba(16,185,129,0.9)'};
    color: white;
    border-radius: 8px;
    font-size: 0.9rem;
    z-index: 10000;
    animation: slideIn 0.3s ease;
  `;
  toast.textContent = message;
  document.body.appendChild(toast);
  
  setTimeout(() => {
    toast.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

async function installToolBundle(bundleName) {
  const bundles = {
    'recon': ['nmap', 'subfinder', 'httpx', 'whatweb'],
    'vuln': ['nuclei', 'nikto', 'sqlmap'],
    'discovery': ['gobuster', 'ffuf', 'dirb'],
    'all': ['nmap', 'subfinder', 'httpx', 'whatweb', 'nuclei', 'nikto', 'sqlmap', 'gobuster', 'ffuf']
  };
  
  const tools = bundles[bundleName];
  if (!tools) return;
  
  showToolsMessage(`Starting bundle installation: ${bundleName}...`);
  
  for (const toolId of tools) {
    const tool = toolsData.find(t => t.id === toolId);
    if (tool && !tool.installed) {
      showToolsMessage(`Installing ${tool.name}...`);
      await installTool(toolId);
      // Wait a bit between installs
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  
  showToolsMessage('Bundle installation completed!');
  await loadToolsList();
}

// Check tunnel and proxy status on page load
document.addEventListener('DOMContentLoaded', () => {
  checkTunnelStatus();
  checkProxyStatus();
});

// ============== DATABASE STORAGE MANAGEMENT ==============
let currentDbType = 'local';

function setDbType(type) {
  currentDbType = type;
  
  // Update buttons
  document.getElementById('db-type-local').classList.toggle('active', type === 'local');
  document.getElementById('db-type-supabase').classList.toggle('active', type === 'supabase');
  
  // Show/hide URI input for Supabase
  const uriGroup = document.getElementById('db-uri-group');
  if (uriGroup) {
    uriGroup.style.display = type === 'supabase' ? 'block' : 'none';
  }
  
  // Set default values based on type
  const hostInput = document.getElementById('db-host');
  const portInput = document.getElementById('db-port');
  const dbInput = document.getElementById('db-database');
  const userInput = document.getElementById('db-user');
  const sslSelect = document.getElementById('db-ssl-mode');
  
  if (type === 'supabase') {
    // Use Transaction Pooler (more reliable, works through firewalls)
    hostInput.placeholder = 'aws-0-region.pooler.supabase.com';
    portInput.value = '6543';
    dbInput.value = 'postgres';
    userInput.placeholder = 'postgres.your-project-ref';
    sslSelect.value = 'require';
  } else {
    hostInput.placeholder = 'localhost';
    portInput.value = '5432';
    dbInput.value = 'owasp_agent';
    userInput.placeholder = 'postgres';
    sslSelect.value = 'prefer';
  }
}

// Parse connection URI and fill form fields
function parseConnectionUri() {
  const uri = document.getElementById('db-connection-uri').value.trim();
  if (!uri || !uri.startsWith('postgresql://')) return;
  
  try {
    const url = new URL(uri);
    document.getElementById('db-host').value = url.hostname || '';
    document.getElementById('db-port').value = url.port || '5432';
    document.getElementById('db-database').value = url.pathname.replace('/', '') || 'postgres';
    document.getElementById('db-user').value = url.username || 'postgres';
    document.getElementById('db-password').value = url.password || '';
    
    // Check for sslmode in query params
    const sslMode = url.searchParams.get('sslmode');
    if (sslMode) {
      document.getElementById('db-ssl-mode').value = sslMode;
    }
  } catch (e) {
    console.error('Failed to parse connection URI:', e);
  }
}

// Add listener for URI input
document.addEventListener('DOMContentLoaded', () => {
  const uriInput = document.getElementById('db-connection-uri');
  if (uriInput) {
    uriInput.addEventListener('change', parseConnectionUri);
    uriInput.addEventListener('paste', () => setTimeout(parseConnectionUri, 100));
  }
});

async function loadDatabaseSettings() {
  try {
    const response = await fetch('/api/database/settings');
    const settings = await response.json();
    
    // Populate form
    document.getElementById('db-host').value = settings.host || '';
    document.getElementById('db-port').value = settings.port || 5432;
    document.getElementById('db-database').value = settings.database || 'postgres';
    document.getElementById('db-user').value = settings.user || 'postgres';
    document.getElementById('db-ssl-mode').value = settings.ssl_mode || 'prefer';
    document.getElementById('db-auto-connect').checked = settings.auto_connect || false;
    
    // Set connection type
    currentDbType = settings.connection_type || 'local';
    setDbType(currentDbType);
    
    // Update status
    updateDbStatus(settings.connected, settings.connected ? 'Connected' : 'Not connected');
    
    // Load stats if connected
    if (settings.connected) {
      loadDatabaseStats();
    }
    
    // Show psycopg2 warning if not available
    if (!settings.psycopg2_available) {
      updateDbStatus(false, 'psycopg2 not installed. Run: pip install psycopg2-binary', true);
    }
  } catch (err) {
    console.error('Failed to load database settings:', err);
    updateDbStatus(false, 'Error loading settings: ' + err.message, true);
  }
}

function getDbConfig() {
  return {
    enabled: false,
    connection_type: currentDbType,
    connection_uri: document.getElementById('db-connection-uri')?.value.trim() || '',
    host: document.getElementById('db-host').value.trim(),
    port: parseInt(document.getElementById('db-port').value) || 5432,
    database: document.getElementById('db-database').value.trim() || 'postgres',
    user: document.getElementById('db-user').value.trim() || 'postgres',
    password: document.getElementById('db-password').value,
    ssl_mode: document.getElementById('db-ssl-mode').value,
    auto_connect: document.getElementById('db-auto-connect').checked
  };
}

async function testDbConnection() {
  const config = getDbConfig();
  
  updateDbStatus(null, 'Testing connection...', false);
  
  try {
    // First save settings
    await fetch('/api/database/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    });
    
    // Then test
    const response = await fetch('/api/database/test', { method: 'POST' });
    const result = await response.json();
    
    if (result.success) {
      updateDbStatus(true, result.message);
      addMessage('system', `✅ Database test successful: ${result.message}`);
    } else {
      const errorMsg = result.message || result.error;
      const hasInstallHint = result.install_hint;
      updateDbStatus(false, errorMsg, true);
      if (hasInstallHint) {
        addMessage('system', `⚠️ Database driver missing. Run: <code>${result.install_hint}</code>`);
      } else {
        addMessage('system', `⚠️ Database test failed: ${errorMsg}`);
      }
    }
  } catch (err) {
    updateDbStatus(false, 'Connection failed: ' + err.message, true);
    addMessage('system', `⚠️ Database test failed: ${err.message}`);
  }
}

async function connectDatabase() {
  const config = getDbConfig();
  config.enabled = true;
  
  updateDbStatus(null, 'Connecting...', false);
  
  try {
    // Save settings first
    await fetch('/api/database/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    });
    
    // Connect
    const connectResponse = await fetch('/api/database/connect', { method: 'POST' });
    const connectResult = await connectResponse.json();
    
    if (connectResult.success) {
      // Initialize tables
      const setupResponse = await fetch('/api/database/setup', { method: 'POST' });
      const setupResult = await setupResponse.json();
      
      if (setupResult.success) {
        updateDbStatus(true, 'Connected and tables initialized');
        addMessage('system', '✅ Database connected and initialized successfully');
        loadDatabaseStats();
      } else {
        updateDbStatus(true, 'Connected (tables not initialized: ' + setupResult.message + ')');
        addMessage('system', `⚠️ Connected but tables not initialized: ${setupResult.message}`);
      }
    } else {
      const errorMsg = connectResult.message || connectResult.error;
      const hasInstallHint = connectResult.install_hint;
      updateDbStatus(false, errorMsg, true);
      if (hasInstallHint) {
        addMessage('system', `⚠️ Database driver missing. Run: <code>${connectResult.install_hint}</code>`);
      } else {
        addMessage('system', `⚠️ Database connection failed: ${errorMsg}`);
      }
    }
  } catch (err) {
    updateDbStatus(false, 'Connection failed: ' + err.message, true);
    addMessage('system', `⚠️ Database connection failed: ${err.message}`);
  }
}

async function disconnectDatabase() {
  try {
    const response = await fetch('/api/database/disconnect', { method: 'POST' });
    const result = await response.json();
    
    if (result.success) {
      updateDbStatus(false, 'Disconnected');
      document.getElementById('db-stats').style.display = 'none';
      addMessage('system', '🔌 Database disconnected');
    }
  } catch (err) {
    addMessage('system', `⚠️ Error disconnecting: ${err.message}`);
  }
}

async function loadDatabaseStats() {
  try {
    const response = await fetch('/api/database/stats');
    const stats = await response.json();
    
    if (stats.enabled) {
      document.getElementById('db-stats').style.display = 'grid';
      document.getElementById('db-stat-commands').textContent = stats.total_commands || 0;
      document.getElementById('db-stat-tasks').textContent = stats.total_tasks || 0;
      document.getElementById('db-stat-memory').textContent = stats.total_memories || 0;
      document.getElementById('db-stat-messages').textContent = stats.total_messages || 0;
    } else {
      document.getElementById('db-stats').style.display = 'none';
    }
    
    // Check for local export
    checkLocalExport();
  } catch (err) {
    console.error('Failed to load database stats:', err);
  }
}

async function checkLocalExport() {
  try {
    const response = await fetch('/api/database/export/check');
    const result = await response.json();
    
    const infoEl = document.getElementById('local-export-info');
    const dateEl = document.getElementById('local-export-date');
    
    if (result.exists && result.metadata) {
      infoEl.style.display = 'block';
      const exportDate = new Date(result.metadata.exported_at).toLocaleString();
      const counts = result.metadata.counts || {};
      const total = Object.values(counts).reduce((a, b) => a + b, 0);
      dateEl.innerHTML = `📦 Local backup: ${exportDate} (${total} records)`;
    } else if (result.exists) {
      infoEl.style.display = 'block';
      dateEl.innerHTML = '📦 Local backup available';
    } else {
      infoEl.style.display = 'none';
    }
  } catch (err) {
    console.error('Failed to check local export:', err);
  }
}

async function exportDatabaseToLocal() {
  if (!confirm('Export all database data to local files?\\n\\nThis will create a backup in the .db_export/ directory.')) {
    return;
  }
  
  try {
    addMessage('system', '⏳ Exporting database to local files...');
    const response = await fetch('/api/database/export', { method: 'POST' });
    const result = await response.json();
    
    if (result.success) {
      const counts = result.counts || {};
      const details = Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(', ');
      addMessage('system', `✅ ${result.message}\\n📊 Exported: ${details}`);
      checkLocalExport();
    } else {
      addMessage('system', `⚠️ Export failed: ${result.message}`);
    }
  } catch (err) {
    addMessage('system', `⚠️ Export error: ${err.message}`);
  }
}

async function importDatabaseFromLocal() {
  if (!confirm('Import data from local backup to database?\\n\\nThis will add records from the .db_export/ directory to the connected database.\\n\\nNote: Duplicate records will be skipped.')) {
    return;
  }
  
  try {
    addMessage('system', '⏳ Importing data from local files to database...');
    const response = await fetch('/api/database/import', { method: 'POST' });
    const result = await response.json();
    
    if (result.success) {
      const counts = result.counts || {};
      const details = Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(', ');
      addMessage('system', `✅ ${result.message}\\n📊 Imported: ${details}`);
      loadDatabaseStats();
    } else {
      addMessage('system', `⚠️ Import failed: ${result.message}`);
    }
  } catch (err) {
    addMessage('system', `⚠️ Import error: ${err.message}`);
  }
}

async function restoreBackupToLocal() {
  if (!confirm('Restore backup to local chat storage?\\n\\nThis will import your exported chat history to local file storage.\\nUse this when database is disconnected to restore your conversation history.')) {
    return;
  }
  
  try {
    addMessage('system', '⏳ Restoring backup to local storage...');
    const response = await fetch('/api/database/import-to-local', { method: 'POST' });
    const result = await response.json();
    
    if (result.success) {
      const counts = result.counts || {};
      addMessage('system', `✅ ${result.message}\\n📊 Restored: ${counts.messages || 0} messages to ${counts.chats || 0} chats`);
      // Reload chats to show restored data
      await loadChats();
    } else {
      addMessage('system', `⚠️ Restore failed: ${result.message}`);
    }
  } catch (err) {
    addMessage('system', `⚠️ Restore error: ${err.message}`);
  }
}

function updateDbStatus(connected, message, isError = false) {
  const statusEl = document.getElementById('db-status');
  const iconEl = document.getElementById('db-status-icon');
  const textEl = document.getElementById('db-status-text');
  
  if (!statusEl) return;
  
  statusEl.style.display = 'flex';
  statusEl.className = 'db-status';
  
  if (connected === null) {
    // Loading state
    iconEl.textContent = '⏳';
    statusEl.classList.add('disconnected');
  } else if (connected) {
    iconEl.textContent = '🟢';
    statusEl.classList.add('connected');
  } else if (isError) {
    iconEl.textContent = '🔴';
    statusEl.classList.add('error');
  } else {
    iconEl.textContent = '⚪';
    statusEl.classList.add('disconnected');
  }
  
  textEl.textContent = message;
}

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

// Toggle background task mode
function toggleBackgroundTask() {
  const checkbox = document.getElementById('background-task-checkbox');
  const btn = document.getElementById('bg-task-btn');
  checkbox.checked = !checkbox.checked;
  if (checkbox.checked) {
    btn.classList.add('active');
  } else {
    btn.classList.remove('active');
  }
}

// Update char counter
document.getElementById('message-input').addEventListener('input', function() {
  const counter = document.getElementById('char-counter');
  const len = this.value.length;
  if (len > 0) {
    counter.textContent = len + ' chars';
  } else {
    counter.textContent = '';
  }
});

// SVG icons for activity types
const activityIcons = {
  start: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>',
  thinking: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
  tool: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"></path></svg>',
  'tool-result': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>',
  error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>',
  step: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>',
  complete: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>',
  warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>'
};

// ============================================
// Activity Monitor - Multi-Task Management
// ============================================

function createActivityTask(taskId, prompt) {
  const shortPrompt = prompt.length > 40 ? prompt.substring(0, 40) + '...' : prompt;
  
  activityTasks[taskId] = {
    id: taskId,
    prompt: prompt,
    shortPrompt: shortPrompt,
    logs: [],
    status: 'running',
    startTime: Date.now(),
    stepCount: 0,
    toolCount: 0,
    durationInterval: null
  };
  
  // Hide no-tasks message
  noActivityMessage.style.display = 'none';
  
  // Create tab
  const tab = document.createElement('div');
  tab.className = 'activity-task-tab active running';
  tab.id = `activity-tab-${taskId}`;
  tab.onclick = (e) => {
    if (!e.target.classList.contains('tab-close')) {
      switchActivityTask(taskId);
    }
  };
  tab.innerHTML = `
    <span class="tab-label" title="${escapeHtml(prompt)}">${escapeHtml(shortPrompt)}</span>
    <span class="tab-close" onclick="closeActivityTask('${taskId}')" title="Close tab">✕</span>
  `;
  
  // Deactivate other tabs
  document.querySelectorAll('.activity-task-tab').forEach(t => t.classList.remove('active'));
  activityTabsHeader.appendChild(tab);
  
  // Create panel
  const panel = document.createElement('div');
  panel.className = 'activity-panel active';
  panel.id = `activity-panel-${taskId}`;
  panel.innerHTML = `
    <div class="activity-panel-log" id="activity-log-${taskId}"></div>
    <div class="activity-panel-footer">
      <div class="activity-panel-stats">
        <div class="stat"><span>Steps:</span> <span class="stat-value" id="stat-steps-${taskId}">0</span></div>
        <div class="stat"><span>Tools:</span> <span class="stat-value" id="stat-tools-${taskId}">0</span></div>
        <div class="stat"><span>Time:</span> <span class="stat-value" id="stat-duration-${taskId}">0s</span></div>
      </div>
      <div class="activity-panel-actions">
        <button class="activity-btn activity-btn-kill" id="kill-btn-${taskId}" onclick="killActivityTask('${taskId}')" title="Stop task">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect></svg>
          Stop
        </button>
        <button class="activity-btn activity-btn-download" onclick="downloadActivityLogs('${taskId}')" title="Download logs">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
          Logs
        </button>
      </div>
    </div>
  `;
  
  // Deactivate other panels
  document.querySelectorAll('.activity-panel').forEach(p => p.classList.remove('active'));
  activityPanels.appendChild(panel);
  
  currentActivityTaskId = taskId;
  
  // Start duration timer
  activityTasks[taskId].durationInterval = setInterval(() => {
    updateTaskDuration(taskId);
  }, 1000);
  
  return activityTasks[taskId];
}

function switchActivityTask(taskId) {
  if (!activityTasks[taskId]) return;
  
  // Update tabs
  document.querySelectorAll('.activity-task-tab').forEach(t => t.classList.remove('active'));
  const tab = document.getElementById(`activity-tab-${taskId}`);
  if (tab) tab.classList.add('active');
  
  // Update panels
  document.querySelectorAll('.activity-panel').forEach(p => p.classList.remove('active'));
  const panel = document.getElementById(`activity-panel-${taskId}`);
  if (panel) panel.classList.add('active');
  
  currentActivityTaskId = taskId;
}

function closeActivityTask(taskId) {
  const task = activityTasks[taskId];
  if (!task) return;
  
  // Clear timer
  if (task.durationInterval) {
    clearInterval(task.durationInterval);
  }
  
  // Remove tab and panel
  const tab = document.getElementById(`activity-tab-${taskId}`);
  const panel = document.getElementById(`activity-panel-${taskId}`);
  if (tab) tab.remove();
  if (panel) panel.remove();
  
  delete activityTasks[taskId];
  
  // Switch to another task or show no-tasks message
  const remainingTasks = Object.keys(activityTasks);
  if (remainingTasks.length > 0) {
    switchActivityTask(remainingTasks[remainingTasks.length - 1]);
  } else {
    currentActivityTaskId = null;
    noActivityMessage.style.display = 'flex';
  }
}

async function killActivityTask(taskId) {
  const task = activityTasks[taskId];
  if (!task || task.status !== 'running') return;
  
  if (!confirm('Are you sure you want to stop this task?')) return;
  
  try {
    // Send cancel request to backend
    const response = await fetch('/api/cancel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: taskId })
    });
    
    if (response.ok) {
      updateTaskStatus(taskId, 'cancelled');
      addActivity('error', 'Task Cancelled', 'Task was stopped by user', null, taskId);
    } else {
      addActivity('warning', 'Cancel Failed', 'Could not cancel task - it may have already completed', null, taskId);
    }
  } catch (err) {
    console.error('Failed to cancel task:', err);
    addActivity('warning', 'Cancel Error', 'Failed to send cancel request', null, taskId);
  }
}

function downloadActivityLogs(taskId) {
  const task = activityTasks[taskId];
  if (!task) return;
  
  const logs = task.logs.map(log => {
    return `[${log.time}] [${log.type.toUpperCase()}] ${log.title}\\n${log.content}${log.details ? '\\n' + log.details : ''}`;
  }).join('\\n\\n' + '='.repeat(60) + '\\n\\n');
  
  const header = `Activity Log Export
==================
Task: ${task.prompt}
Status: ${task.status}
Started: ${new Date(task.startTime).toISOString()}
Steps: ${task.stepCount}
Tools: ${task.toolCount}
Duration: ${formatDuration(Date.now() - task.startTime)}

${'='.repeat(60)}

`;
  
  const content = header + logs;
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `activity-log-${taskId}-${new Date().toISOString().slice(0,10)}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

function updateTaskStatus(taskId, status) {
  const task = activityTasks[taskId];
  if (!task) return;
  
  task.status = status;
  
  const tab = document.getElementById(`activity-tab-${taskId}`);
  if (tab) {
    tab.classList.remove('running', 'completed', 'failed', 'cancelled');
    tab.classList.add(status === 'cancelled' ? 'failed' : status);
  }
  
  const killBtn = document.getElementById(`kill-btn-${taskId}`);
  if (killBtn && status !== 'running') {
    killBtn.style.display = 'none';
  }
  
  if (status !== 'running' && task.durationInterval) {
    clearInterval(task.durationInterval);
  }
}

function updateTaskDuration(taskId) {
  const task = activityTasks[taskId];
  if (!task) return;
  
  const elapsed = Math.floor((Date.now() - task.startTime) / 1000);
  const durationEl = document.getElementById(`stat-duration-${taskId}`);
  if (durationEl) {
    durationEl.textContent = formatDuration(elapsed * 1000);
  }
}

function formatDuration(ms) {
  const secs = Math.floor(ms / 1000);
  const mins = Math.floor(secs / 60);
  const remainingSecs = secs % 60;
  return mins > 0 ? `${mins}m ${remainingSecs}s` : `${secs}s`;
}

function updateTaskStats(taskId, stepCount, toolCount) {
  const task = activityTasks[taskId];
  if (!task) return;
  
  task.stepCount = stepCount;
  task.toolCount = toolCount;
  
  const stepsEl = document.getElementById(`stat-steps-${taskId}`);
  const toolsEl = document.getElementById(`stat-tools-${taskId}`);
  if (stepsEl) stepsEl.textContent = stepCount;
  if (toolsEl) toolsEl.textContent = toolCount;
}

function addActivity(type, title, content, details = null, taskId = null) {
  // Use current task if not specified
  const targetTaskId = taskId || currentActivityTaskId;
  
  // If no task exists, create one
  if (!targetTaskId || !activityTasks[targetTaskId]) {
    return; // No active task to add activity to
  }
  
  const task = activityTasks[targetTaskId];
  const time = new Date().toLocaleTimeString('en-US', { hour12: false });
  const icon = activityIcons[type] || activityIcons.step;
  
  // Store in task logs
  task.logs.push({ type, title, content, details, time });
  
  // Create DOM element
  const item = document.createElement('div');
  item.className = `activity-item activity-${type}`;
  
  item.innerHTML = `
    <div class="activity-icon">${icon}</div>
    <div class="activity-title">
      <span class="activity-title-text">${title}</span>
      <span class="activity-time">${time}</span>
    </div>
    <div class="activity-content">${content}${details ? '<pre>' + escapeHtml(details) + '</pre>' : ''}</div>
  `;
  
  const logEl = document.getElementById(`activity-log-${targetTaskId}`);
  if (logEl) {
    logEl.appendChild(item);
    logEl.scrollTop = logEl.scrollHeight;
  }
}

function escapeHtml(text) {
  if (!text) return '';
  const str = String(text);
  const div = document.createElement('div');
  div.textContent = str.substring(0, 1000);
  return div.innerHTML + (str.length > 1000 ? '\\n... (truncated)' : '');
}

// Legacy timer functions (for backwards compatibility)
function startTimer(taskId = null) {
  const id = taskId || currentActivityTaskId;
  if (id && activityTasks[id]) {
    activityTasks[id].startTime = Date.now();
    activityTasks[id].stepCount = 0;
    activityTasks[id].toolCount = 0;
  }
  // Also update legacy variables
  startTime = Date.now();
  stepCount = 0;
  toolCount = 0;
}

function stopTimer(taskId = null) {
  const id = taskId || currentActivityTaskId;
  if (id && activityTasks[id] && activityTasks[id].durationInterval) {
    clearInterval(activityTasks[id].durationInterval);
  }
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
  
  // Add timestamp to message (except progress messages)
  if (type !== 'progress') {
    const timestamp = meta.timestamp ? new Date(meta.timestamp) : new Date();
    const timeStr = timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const dateStr = timestamp.toLocaleDateString([], { month: 'short', day: 'numeric' });
    const timestampDiv = document.createElement('div');
    timestampDiv.className = 'message-timestamp';
    timestampDiv.textContent = `${dateStr}, ${timeStr}`;
    msgDiv.appendChild(timestampDiv);
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
  // Save immediately for important messages, debounce for others
  const isImportant = msgData.type === 'user' || msgData.type === 'agent' || msgData.type === 'assistant';
  
  if (isImportant) {
    // Save important messages immediately
    try {
      await fetch(`/api/chats/${currentChatId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: msgData.type,
          content: msgData.content,
          timestamp: msgData.timestamp
        })
      });
    } catch (err) {
      console.error('Failed to save message:', err);
      // Add to pending for retry
      pendingMessages.push(msgData);
    }
  } else {
    // Debounce system messages
    pendingMessages.push(msgData);
    
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
  addMessage('system', '🟢 Connected to Pentest.Systems Assistant - Ready for security analysis');
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
  
  // Get task_id from message for activity routing
  const msgTaskId = data.task_id;
  
  // Check if message belongs to different chat - store for later
  const msgChatId = data.chat_id;
  if (msgChatId && msgChatId !== currentChatId) {
    // Queue message for the correct chat (will be loaded when chat is switched)
    // For now, skip showing in current chat
    console.log(`Message for chat ${msgChatId} received while in chat ${currentChatId}`);
    // Still process activity and stats updates for the correct task
    if (data.type === 'activity' && msgTaskId && activityTasks[msgTaskId]) {
      addActivity(data.activity_type, data.title || '', data.content, data.details, msgTaskId);
      if (typeof data.tool_count === 'number' || typeof data.step_count === 'number') {
        updateTaskStats(msgTaskId, data.step_count || 0, data.tool_count || 0);
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
    // Activity log update from agent steps - route to correct task
    const targetTaskId = msgTaskId || currentActivityTaskId;
    addActivity(data.activity_type, data.title || '', data.content, data.details, targetTaskId);
    
    // Update task-specific stats if provided
    if (targetTaskId && activityTasks[targetTaskId]) {
      if (typeof data.tool_count === 'number' || typeof data.step_count === 'number') {
        updateTaskStats(targetTaskId, data.step_count || 0, data.tool_count || 0);
      }
    }
    
    // Update legacy global counters
    if (typeof data.tool_count === 'number') {
      toolCount = data.tool_count;
      document.getElementById('stat-tools').textContent = toolCount;
    }
    if (typeof data.step_count === 'number') {
      stepCount = data.step_count;
      document.getElementById('stat-steps').textContent = stepCount;
    }
  } else if (data.type === 'final') {
    const targetTaskId = msgTaskId || currentActivityTaskId;
    stopTimer(targetTaskId);
    
    // Update task status to completed
    if (targetTaskId && activityTasks[targetTaskId]) {
      updateTaskStatus(targetTaskId, 'completed');
      addActivity('complete', 'Task Completed', 'Agent finished processing', null, targetTaskId);
    }
    
    // Remove progress message if exists
    const progressMsg = messagesDiv.querySelector('.msg-progress:last-child');
    if (progressMsg) progressMsg.remove();
    addMessage('agent', data.content);
  } else if (data.type === 'error') {
    const targetTaskId = msgTaskId || currentActivityTaskId;
    if (targetTaskId && activityTasks[targetTaskId]) {
      updateTaskStatus(targetTaskId, 'failed');
      addActivity('error', 'Task Failed', data.content || 'An error occurred', null, targetTaskId);
    }
    addMessage('agent', data.content || 'An error occurred');
  } else if (data.type === 'report') {
    addMessage('report', data.content, { html: data.html, markdown: data.markdown });
    const targetTaskId = msgTaskId || currentActivityTaskId;
    addActivity('tool-result', '📋 Report Generated', 'Professional security report is ready for download', null, targetTaskId);
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
  
  // Create a new activity task for this message
  const taskId = `task_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
  createActivityTask(taskId, content);
  
  startTimer(taskId);
  addActivity('start', 'Task Started', content.substring(0, 100) + (content.length > 100 ? '...' : ''), null, taskId);
  
  // Prepare message payload with task_id for activity tracking
  const payload = {
    content: content,
    session_id: sessionId,
    chat_id: currentChatId,
    task_id: taskId,
    report_mode: reportCheckbox.checked,
    background_task: isBackgroundTask,
    files: attachedFiles.map(f => f.filename)
  };
  
  // Upload files first if any
  if (attachedFiles.length > 0) {
    addActivity('tool', '📤 Uploading Files', `Uploading ${attachedFiles.length} file(s) for analysis`, null, taskId);
    
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
        addActivity('error', '❌ Upload Error', `Failed to upload ${file.filename}`, null, taskId);
      }
    }
    
    addActivity('tool-result', '✅ Files Uploaded', 'Files ready for analysis', null, taskId);
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
    // Highlight Tasks tab instead of switching
    highlightTab('tasks');
    startTaskPolling();
  } else {
    // Highlight Activity tab with red dot instead of switching
    highlightTab('activity');
  }
  
  // Auto-expand sidebar when task starts
  if (!sidebar.classList.contains('expanded')) {
    sidebar.classList.add('expanded');
    sidebarToggle.textContent = '◀';
  }
}

sendBtn.onclick = sendMessage;

// Auto-resize textarea
function autoResizeTextarea() {
  messageInput.style.height = 'auto';
  const newHeight = Math.min(messageInput.scrollHeight, 180);
  messageInput.style.height = newHeight + 'px';
}
messageInput.addEventListener('input', autoResizeTextarea);

messageInput.onkeydown = (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
    // Reset textarea height after send
    messageInput.style.height = 'auto';
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

async function reloadCurrentChat() {
  // Reload messages for the current chat from backend
  try {
    const response = await fetch(`/api/chats/${currentChatId}`);
    const chat = await response.json();
    
    if (chat.messages && chat.messages.length > 0) {
      // Clear and reload
      messagesDiv.innerHTML = '';
      chatHistory = [];
      
      chat.messages.forEach(msg => {
        addMessage(msg.type, msg.content, { skipSave: true, timestamp: msg.timestamp });
      });
      chatHistory = [...chat.messages];
    }
  } catch (err) {
    console.error('Failed to reload chat:', err);
  }
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
    list.innerHTML = `
      <div class="no-scheduled-tasks">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="12" cy="12" r="10"></circle>
          <polyline points="12 6 12 12 16 14"></polyline>
        </svg>
        <span>No scheduled tasks</span>
        <span class="no-scheduled-hint">Schedule recurring security scans</span>
      </div>`;
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
  const recurringOptions = document.getElementById('recurring-options');
  
  if (taskId && scheduledTasksStore[taskId]) {
    // Editing existing task
    const task = scheduledTasksStore[taskId];
    title.textContent = 'Edit Scheduled Task';
    submitBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path><polyline points="17 21 17 13 7 13 7 21"></polyline><polyline points="7 3 7 8 15 8"></polyline></svg> Save Changes';
    
    document.getElementById('schedule-name').value = task.name || '';
    document.getElementById('schedule-prompt').value = task.prompt || '';
    
    // Parse ISO date to local datetime-local format
    const scheduleDate = new Date(task.schedule_time);
    const localDateTime = new Date(scheduleDate.getTime() - scheduleDate.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    document.getElementById('schedule-time').value = localDateTime;
    
    document.getElementById('schedule-recurring').checked = task.recurring || false;
    if (task.recurring) {
      recurringOptions.classList.add('active');
    } else {
      recurringOptions.classList.remove('active');
    }
    document.getElementById('schedule-interval').value = task.interval_minutes || 60;
  } else {
    // New task
    title.textContent = 'Schedule Task';
    submitBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> Schedule Task';
    
    document.getElementById('schedule-name').value = '';
    document.getElementById('schedule-prompt').value = '';
    document.getElementById('schedule-recurring').checked = false;
    recurringOptions.classList.remove('active');
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
  
  title.textContent = `Scheduled Task Result: ${task.name || task.prompt.substring(0, 30)}`;
  
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
  document.getElementById('recurring-options').classList.remove('active');
}

// Toggle recurring options visibility
document.getElementById('schedule-recurring')?.addEventListener('change', (e) => {
  const recurringOptions = document.getElementById('recurring-options');
  if (e.target.checked) {
    recurringOptions.classList.add('active');
  } else {
    recurringOptions.classList.remove('active');
  }
});

// Set interval preset
function setInterval(minutes) {
  document.getElementById('schedule-interval').value = minutes;
}

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

// Function to highlight a tab with red dot notification
function highlightTab(tabName) {
  const tab = document.querySelector(`.sidebar-tab[data-tab="${tabName}"]`);
  if (tab && !tab.classList.contains('active')) {
    tab.classList.add('has-activity');
  }
}

// Function to clear tab highlight
function clearTabHighlight(tabName) {
  const tab = document.querySelector(`.sidebar-tab[data-tab="${tabName}"]`);
  if (tab) {
    tab.classList.remove('has-activity');
  }
}

// Update sidebar tab handling
document.querySelectorAll('.sidebar-tab').forEach(tab => {
  tab.onclick = () => {
    document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    tab.classList.add('active');
    // Clear highlight when tab is clicked
    tab.classList.remove('has-activity');
    const tabId = tab.getAttribute('data-tab');
    document.getElementById('tab-' + tabId).classList.add('active');
    
    // Load data based on tab
    if (tabId === 'tasks') startTaskPolling();
    else stopTaskPolling();
    
    if (tabId === 'settings') {
      loadApiKeys();
      loadProviders();
      loadCustomContext();
      checkTelegramMonitoringStatus();
    }
    
    if (tabId === 'chats') {
      loadChats();
      // Also reload current chat messages to ensure they're up to date
      reloadCurrentChat();
    }
    
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
// Load chats on startup and restore current chat messages
async function initializeChats() {
  await loadChats();
  // Load messages for current chat (default) on page load
  try {
    const response = await fetch(`/api/chats/${currentChatId}`);
    const chat = await response.json();
    
    if (chat.messages && chat.messages.length > 0) {
      // Clear any existing messages first
      messagesDiv.innerHTML = '';
      chatHistory = [];
      
      // Load all messages
      chat.messages.forEach(msg => {
        addMessage(msg.type, msg.content, { skipSave: true, timestamp: msg.timestamp });
      });
      chatHistory = [...chat.messages];
    }
  } catch (err) {
    console.error('Failed to load initial chat:', err);
  }
}
initializeChats();
// Load chains on startup
loadChains();
// Load provider settings on startup  
loadProviders();

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
window.reloadCurrentChat = reloadCurrentChat;
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
// Settings sub-tab functions
window.switchSettingsSubtab = switchSettingsSubtab;
// Database functions
window.setDbType = setDbType;
window.testDbConnection = testDbConnection;
window.connectDatabase = connectDatabase;
window.disconnectDatabase = disconnectDatabase;
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
            task_id = msg_data.get("task_id")  # Activity task tracking ID
            report_mode_enabled = msg_data.get("report_mode", False)
            attached_files = msg_data.get("files", [])
            background_task = msg_data.get("background_task", False)
            
            # Handle report mode toggle commands
            if msg_content == "__REPORT_MODE_ON__" or msg_data.get("action") == "report_mode_on":
                enable_report_mode(
                    title="Security Assessment Report",
                    target="Target to be specified",
                    author="Pentest.Systems Assistant"
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
            
            # Add conversation history for context (last 10 user/assistant exchanges)
            if chat_id in chats_store and chats_store[chat_id].get("messages"):
                messages = chats_store[chat_id]["messages"]
                # Filter for user and assistant messages only (skip system/progress)
                conversation = [m for m in messages if m.get("type") in ("user", "assistant")]
                # Get last 10 exchanges (20 messages)
                recent = conversation[-20:] if len(conversation) > 20 else conversation
                if recent:
                    history_text = "\n\n--- CONVERSATION HISTORY ---\n"
                    for m in recent:
                        role = "User" if m.get("type") == "user" else "Assistant"
                        content = m.get("content", "")[:2000]  # Truncate long messages
                        history_text += f"\n{role}: {content}\n"
                    history_text += "\n--- END HISTORY ---\n"
                    full_message = history_text + "\nCurrent request: " + full_message
            
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
                # Capture chat_id and task_id for this request
                request_chat_id = chat_id
                request_task_id = task_id
                
                # Send initial progress
                await ws.send_text(json.dumps({
                    "type": "activity",
                    "activity_type": "start",
                    "title": "Task Started",
                    "content": f"Processing: {msg_content[:100]}...",
                    "chat_id": request_chat_id,
                    "task_id": request_task_id
                }))
                
                await ws.send_text(json.dumps({
                    "type": "progress",
                    "content": "Agent analyzing your request...",
                    "chat_id": request_chat_id,
                    "task_id": request_task_id
                }))
                
                # Queue for thread-safe communication between agent thread and async handler
                event_queue = queue.Queue()
                
                def run_agent_with_streaming():
                    """Run agent in thread and put events in queue."""
                    try:
                        # Acquire lock for concurrent access
                        with agent_lock:
                            # Log command to database if enabled
                            db_command_id = None
                            if db_storage.enabled:
                                db_command_id = db_storage.log_command(
                                    session_id=session_id,
                                    task_id=request_task_id or "interactive",
                                    command=msg_content,
                                    command_type="prompt"
                                )
                            
                            # Use streaming mode for real-time updates
                            final_result = None
                            step_count = 0
                            tool_count = 0
                            start_time = time.time()
                            
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
                                        
                                        # Categorize tools for better display
                                        if any(x in tool_name.lower() for x in ['scan', 'nmap', 'nikto', 'dirb', 'gobuster', 'nuclei', 'zap']):
                                            activity_msg = f"Running security scan: {tool_name}"
                                        elif any(x in tool_name.lower() for x in ['virustotal', 'shodan', 'hunter', 'dns', 'whois', 'osint']):
                                            activity_msg = f"OSINT lookup: {tool_name}"
                                        elif any(x in tool_name.lower() for x in ['browse', 'page', 'screenshot', 'playwright', 'click', 'form']):
                                            activity_msg = f"Browser automation: {tool_name}"
                                        elif any(x in tool_name.lower() for x in ['curl', 'request', 'http']):
                                            activity_msg = f"HTTP request: {tool_name}"
                                        elif any(x in tool_name.lower() for x in ['report', 'finding', 'summary']):
                                            activity_msg = f"Report generation: {tool_name}"
                                            activity_type = "tool-result"
                                        elif any(x in tool_name.lower() for x in ['owasp', 'classify', 'scenario']):
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
                                            "title": activity_msg,
                                            "content": f"Tool #{tool_count}: {tool_name}{target_info}",
                                            "tool_count": tool_count,
                                            "step_count": step_count
                                        })
                                        
                                        # Log tool call to database
                                        if db_storage.enabled:
                                            tool_cmd_id = db_storage.log_command(
                                                session_id=session_id,
                                                task_id=request_task_id or "interactive",
                                                command=f"{tool_name}: {str(tool_args)[:500]}",
                                                command_type="tool_call",
                                                tool_name=tool_name
                                            )
                                
                                # Check for observations/results
                                if hasattr(event, 'observations') and event.observations:
                                    obs = str(event.observations)[:200]
                                    event_queue.put({
                                        "type": "activity",
                                        "activity_type": "tool-result",
                                        "title": "Tool Result",
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
                                        "title": "Agent Planning",
                                        "content": plan,
                                        "tool_count": tool_count,
                                        "step_count": step_count
                                    })
                                
                                # Capture final result
                                if hasattr(event, 'output') and event.output is not None:
                                    final_result = event.output
                            
                            # Log final output to database
                            if db_storage.enabled and db_command_id:
                                execution_time = int((time.time() - start_time) * 1000)
                                db_storage.log_output(
                                    command_id=db_command_id,
                                    output=str(final_result)[:10000] if final_result else "Task completed",
                                    output_type="final",
                                    status="success",
                                    execution_time_ms=execution_time
                                )
                            
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
                                
                                # Send activity update with counts, chat_id and task_id
                                await ws.send_text(json.dumps({
                                    "type": "activity",
                                    "activity_type": event["activity_type"],
                                    "title": event["title"],
                                    "content": event["content"],
                                    "tool_count": last_tool_count,
                                    "step_count": last_step_count,
                                    "chat_id": request_chat_id,
                                    "task_id": request_task_id
                                }))
                                
                                # Also send progress update for chat
                                await ws.send_text(json.dumps({
                                    "type": "progress",
                                    "content": event["title"],
                                    "chat_id": request_chat_id,
                                    "task_id": request_task_id
                                }))
                            
                            elif event["type"] == "complete":
                                final_response = event["result"]
                                last_tool_count = event.get("tool_count", last_tool_count)
                                last_step_count = event.get("step_count", last_step_count)
                                
                                await ws.send_text(json.dumps({
                                    "type": "activity",
                                    "activity_type": "complete",
                                    "title": "Task Completed",
                                    "content": f"Finished with {last_step_count} steps, {last_tool_count} tool calls",
                                    "tool_count": last_tool_count,
                                    "step_count": last_step_count,
                                    "chat_id": request_chat_id,
                                    "task_id": request_task_id
                                }))
                                break
                            
                            elif event["type"] == "error":
                                await ws.send_text(json.dumps({
                                    "type": "activity",
                                    "activity_type": "error",
                                    "title": "Error Occurred",
                                    "content": event["error"],
                                    "chat_id": request_chat_id,
                                    "task_id": request_task_id
                                }))
                                await ws.send_text(json.dumps({
                                    "type": "error",
                                    "content": f"Error: {event['error']}",
                                    "chat_id": request_chat_id,
                                    "task_id": request_task_id
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
                            "title": "Error",
                            "content": str(e),
                            "chat_id": request_chat_id,
                            "task_id": request_task_id
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
                            "chat_id": request_chat_id,
                            "task_id": request_task_id
                        }))
                        
                        html_report = generate_html_report()
                        md_report = generate_markdown_report()
                        
                        await ws.send_text(json.dumps({
                            "type": "final",
                            "content": str(final_response),
                            "chat_id": request_chat_id,
                            "task_id": request_task_id
                        }))
                        
                        await ws.send_text(json.dumps({
                            "type": "report",
                            "content": "📋 Professional security report has been generated.",
                            "html": html_report,
                            "markdown": md_report,
                            "chat_id": request_chat_id,
                            "task_id": request_task_id
                        }))
                        return
                
                # Send final response
                await ws.send_text(json.dumps({
                    "type": "final",
                    "content": str(final_response) if final_response else "Task completed",
                    "chat_id": request_chat_id,
                    "task_id": request_task_id
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
