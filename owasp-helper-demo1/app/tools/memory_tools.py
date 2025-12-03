"""
VectorDB-based semantic memory for the OWASP Helper agent.

This module provides long-term memory capabilities using vector embeddings,
enabling the agent to:
1. Remember past scan results and findings
2. Recall relevant context from previous conversations
3. Build up knowledge about targets over multiple sessions
4. Find similar vulnerabilities or patterns across assessments

Install: pip install vectordb2
"""
from __future__ import annotations
from smolagents import tool
from pathlib import Path
from datetime import datetime
import json
import os

# Try to import VectorDB
try:
    from vectordb import Memory
    VECTORDB_AVAILABLE = True
except ImportError:
    VECTORDB_AVAILABLE = False
    Memory = None

# Global memory instances
_AGENT_MEMORY = None
_SCAN_MEMORY = None
_KNOWLEDGE_MEMORY = None

# Memory storage directory
MEMORY_DIR = Path("data/memory")
MEMORY_DIR.mkdir(parents=True, exist_ok=True)


def _ensure_vectordb() -> bool:
    """Check if VectorDB is available."""
    if not VECTORDB_AVAILABLE:
        return False
    return True


def initialize_memory(force_reload: bool = False) -> dict:
    """Initialize all memory stores. Called at application startup.
    
    Returns dict with status of each memory store.
    """
    global _AGENT_MEMORY, _SCAN_MEMORY, _KNOWLEDGE_MEMORY
    
    if not _ensure_vectordb():
        return {
            "status": "unavailable",
            "error": "VectorDB not installed. Run: pip install vectordb2"
        }
    
    result = {
        "status": "initialized",
        "memories": {}
    }
    
    try:
        # Agent conversation memory - for remembering conversation context
        if _AGENT_MEMORY is None or force_reload:
            agent_memory_file = str(MEMORY_DIR / "agent_memory.pkl")
            _AGENT_MEMORY = Memory(
                memory_file=agent_memory_file,
                chunking_strategy={"mode": "sliding_window", "window_size": 256, "overlap": 32},
                embeddings="normal"  # BAAI/bge-small-en-v1.5 - good balance of speed and quality
            )
            result["memories"]["agent"] = "loaded"
        
        # Scan results memory - for remembering scan outputs and findings
        if _SCAN_MEMORY is None or force_reload:
            scan_memory_file = str(MEMORY_DIR / "scan_memory.pkl")
            _SCAN_MEMORY = Memory(
                memory_file=scan_memory_file,
                chunking_strategy={"mode": "paragraph"},  # Paragraph mode for structured scan data
                embeddings="normal"
            )
            result["memories"]["scans"] = "loaded"
        
        # Knowledge base memory - for OWASP, CVEs, techniques, etc.
        if _KNOWLEDGE_MEMORY is None or force_reload:
            knowledge_memory_file = str(MEMORY_DIR / "knowledge_memory.pkl")
            _KNOWLEDGE_MEMORY = Memory(
                memory_file=knowledge_memory_file,
                chunking_strategy={"mode": "sliding_window", "window_size": 512, "overlap": 64},
                embeddings="normal"
            )
            result["memories"]["knowledge"] = "loaded"
        
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


def get_memory_stats() -> dict:
    """Get statistics about memory usage."""
    stats = {
        "vectordb_available": VECTORDB_AVAILABLE,
        "memories": {}
    }
    
    if _AGENT_MEMORY is not None:
        stats["memories"]["agent"] = "active"
    if _SCAN_MEMORY is not None:
        stats["memories"]["scans"] = "active"
    if _KNOWLEDGE_MEMORY is not None:
        stats["memories"]["knowledge"] = "active"
    
    return stats


# ============== AGENT TOOLS ==============

@tool
def save_to_memory(content: str, memory_type: str = "agent", metadata: str = "") -> str:
    """Save information to long-term memory for later retrieval.
    
    Use this to remember important findings, conversation context, or any
    information that might be useful in future interactions.
    
    Args:
        content: The text content to save to memory. Can be scan results,
                 findings, notes, or any relevant information.
        memory_type: Type of memory to save to:
                    - "agent" (default): General conversation and context memory
                    - "scan": Scan results and security findings
                    - "knowledge": Security knowledge, techniques, CVEs
        metadata: Optional JSON string with metadata like:
                  {"target": "example.com", "tool": "nmap", "type": "port_scan"}
                  
    Returns: Confirmation that content was saved to memory.
    
    Example:
        save_to_memory(
            "Found SQL injection on login page at /api/login with parameter 'username'",
            memory_type="scan",
            metadata='{"target": "example.com", "vulnerability": "sqli", "severity": "high"}'
        )
    """
    if not _ensure_vectordb():
        return "❌ VectorDB not available. Install with: pip install vectordb2"
    
    # Select appropriate memory store
    if memory_type == "scan":
        memory = _SCAN_MEMORY
    elif memory_type == "knowledge":
        memory = _KNOWLEDGE_MEMORY
    else:
        memory = _AGENT_MEMORY
    
    if memory is None:
        # Try to initialize
        init_result = initialize_memory()
        if init_result["status"] != "initialized":
            return f"❌ Memory not initialized: {init_result.get('error', 'Unknown error')}"
        
        # Re-select after init
        if memory_type == "scan":
            memory = _SCAN_MEMORY
        elif memory_type == "knowledge":
            memory = _KNOWLEDGE_MEMORY
        else:
            memory = _AGENT_MEMORY
    
    # Parse metadata
    meta_dict = {"saved_at": datetime.now().isoformat(), "type": memory_type}
    if metadata:
        try:
            parsed_meta = json.loads(metadata)
            meta_dict.update(parsed_meta)
        except json.JSONDecodeError:
            meta_dict["raw_metadata"] = metadata
    
    try:
        memory.save(content, meta_dict)
        return f"✅ Saved to {memory_type} memory. Content will be searchable in future queries."
    except Exception as e:
        return f"❌ Error saving to memory: {str(e)}"


@tool
def search_memory(query: str, memory_type: str = "all", top_n: int = 5) -> str:
    """Search long-term memory for relevant information.
    
    Use this to recall past findings, scan results, or conversation context
    that might be relevant to the current task.
    
    Args:
        query: Natural language query to search for. Examples:
               - "SQL injection vulnerabilities found"
               - "What did we find on example.com?"
               - "Previous nmap scans"
               - "Open ports on 192.168.1.0/24"
        memory_type: Which memory to search:
                    - "all" (default): Search all memory types
                    - "agent": Conversation and context memory
                    - "scan": Scan results and security findings
                    - "knowledge": Security knowledge base
        top_n: Number of results to return (default: 5)
        
    Returns: Relevant memories with their content and metadata.
    
    Example:
        search_memory("vulnerabilities found on example.com")
        search_memory("nmap scan results", memory_type="scan")
    """
    if not _ensure_vectordb():
        return "❌ VectorDB not available. Install with: pip install vectordb2"
    
    results = []
    
    # Determine which memories to search
    memories_to_search = []
    if memory_type == "all":
        if _AGENT_MEMORY:
            memories_to_search.append(("agent", _AGENT_MEMORY))
        if _SCAN_MEMORY:
            memories_to_search.append(("scan", _SCAN_MEMORY))
        if _KNOWLEDGE_MEMORY:
            memories_to_search.append(("knowledge", _KNOWLEDGE_MEMORY))
    elif memory_type == "scan" and _SCAN_MEMORY:
        memories_to_search.append(("scan", _SCAN_MEMORY))
    elif memory_type == "knowledge" and _KNOWLEDGE_MEMORY:
        memories_to_search.append(("knowledge", _KNOWLEDGE_MEMORY))
    elif memory_type == "agent" and _AGENT_MEMORY:
        memories_to_search.append(("agent", _AGENT_MEMORY))
    
    if not memories_to_search:
        return "⚠️ No memory stores available. Use save_to_memory() first to store information."
    
    try:
        for mem_name, memory in memories_to_search:
            try:
                search_results = memory.search(query, top_n=top_n, unique=True)
                for r in search_results:
                    results.append({
                        "source": mem_name,
                        "content": r.get("chunk", ""),
                        "metadata": r.get("metadata", {}),
                        "relevance": 1 - r.get("distance", 0)  # Convert distance to relevance score
                    })
            except Exception:
                continue  # Memory might be empty
        
        if not results:
            return f"🔍 No relevant memories found for: '{query}'"
        
        # Sort by relevance
        results.sort(key=lambda x: x["relevance"], reverse=True)
        results = results[:top_n]
        
        # Format output
        output = f"🧠 **Found {len(results)} relevant memories:**\n\n"
        for i, r in enumerate(results, 1):
            output += f"### Memory {i} (from {r['source']}, relevance: {r['relevance']:.2f})\n"
            output += f"{r['content'][:1000]}\n"
            if r['metadata']:
                meta_str = ", ".join(f"{k}: {v}" for k, v in r['metadata'].items() 
                                     if k not in ['saved_at'] and v)
                if meta_str:
                    output += f"*Metadata: {meta_str}*\n"
            output += "\n"
        
        return output
        
    except Exception as e:
        return f"❌ Error searching memory: {str(e)}"


@tool
def clear_memory(memory_type: str = "all", confirm: bool = False) -> str:
    """Clear memory stores.
    
    Use with caution - this permanently deletes stored memories.
    
    Args:
        memory_type: Which memory to clear:
                    - "all": Clear all memories
                    - "agent": Clear conversation memory only
                    - "scan": Clear scan results only
                    - "knowledge": Clear knowledge base only
        confirm: Must be True to actually clear the memory
        
    Returns: Confirmation of cleared memory.
    """
    if not confirm:
        return "⚠️ Memory clear requires confirm=True. This will permanently delete memories."
    
    cleared = []
    
    if memory_type in ["all", "agent"] and _AGENT_MEMORY:
        try:
            _AGENT_MEMORY.clear()
            cleared.append("agent")
        except Exception:
            pass
            
    if memory_type in ["all", "scan"] and _SCAN_MEMORY:
        try:
            _SCAN_MEMORY.clear()
            cleared.append("scan")
        except Exception:
            pass
            
    if memory_type in ["all", "knowledge"] and _KNOWLEDGE_MEMORY:
        try:
            _KNOWLEDGE_MEMORY.clear()
            cleared.append("knowledge")
        except Exception:
            pass
    
    if cleared:
        return f"✅ Cleared memories: {', '.join(cleared)}"
    else:
        return "⚠️ No memories to clear or memory stores not initialized."


@tool
def get_memory_status() -> str:
    """Get the status of memory stores.
    
    Shows whether VectorDB is available and which memory stores are active.
    
    Returns: Status information about memory system.
    """
    status = []
    
    if not VECTORDB_AVAILABLE:
        return """❌ **VectorDB Not Installed**

VectorDB provides semantic memory for the agent, enabling:
- Long-term memory of findings and context
- Semantic search across past assessments
- Knowledge accumulation over sessions

**Install with:** `pip install vectordb2`

After installation, restart the application."""
    
    status.append("✅ **VectorDB Available**\n")
    
    stats = get_memory_stats()
    
    if stats["memories"]:
        status.append("**Active Memory Stores:**")
        for name, state in stats["memories"].items():
            status.append(f"  - {name}: {state}")
    else:
        status.append("⚠️ No memory stores initialized. They will be created on first save.")
    
    status.append("\n**Memory Types:**")
    status.append("  - **agent**: Conversation context and general notes")
    status.append("  - **scan**: Scan results, findings, vulnerabilities")
    status.append("  - **knowledge**: Security knowledge, CVEs, techniques")
    
    return "\n".join(status)


# ============== AUTO-SAVE HELPERS ==============

def auto_save_scan_result(tool_name: str, target: str, result: str, 
                          finding_type: str = "scan") -> bool:
    """Automatically save scan results to memory.
    
    Called by scan tools to persist results for future reference.
    
    Args:
        tool_name: Name of the tool (nmap, wpscan, etc.)
        target: Target that was scanned
        result: Scan output/result
        finding_type: Type of finding (scan, vulnerability, recon)
        
    Returns: True if saved successfully
    """
    if not _ensure_vectordb() or _SCAN_MEMORY is None:
        return False
    
    if not result or len(result.strip()) < 50:
        return False  # Don't save very short/empty results
    
    metadata = {
        "tool": tool_name,
        "target": target,
        "type": finding_type,
        "saved_at": datetime.now().isoformat()
    }
    
    try:
        # Truncate very long results
        content = result[:10000] if len(result) > 10000 else result
        _SCAN_MEMORY.save(content, metadata)
        return True
    except Exception:
        return False


def auto_save_conversation(role: str, content: str, chat_id: str = "default") -> bool:
    """Automatically save conversation messages to memory.
    
    Called by the chat handler to persist conversation context.
    
    Args:
        role: Message role (user, assistant)
        content: Message content
        chat_id: Chat session ID
        
    Returns: True if saved successfully
    """
    if not _ensure_vectordb() or _AGENT_MEMORY is None:
        return False
    
    if not content or len(content.strip()) < 20:
        return False  # Don't save very short messages
    
    metadata = {
        "role": role,
        "chat_id": chat_id,
        "saved_at": datetime.now().isoformat()
    }
    
    try:
        # Truncate very long messages
        msg_content = content[:5000] if len(content) > 5000 else content
        _AGENT_MEMORY.save(msg_content, metadata)
        return True
    except Exception:
        return False


def search_relevant_context(query: str, top_n: int = 3) -> list:
    """Search for relevant context from memory.
    
    Used internally to enhance agent responses with past context.
    
    Args:
        query: The current query/prompt
        top_n: Number of results to return
        
    Returns: List of relevant memory chunks
    """
    if not _ensure_vectordb():
        return []
    
    results = []
    
    for memory in [_AGENT_MEMORY, _SCAN_MEMORY]:
        if memory is None:
            continue
        try:
            search_results = memory.search(query, top_n=top_n, unique=True)
            for r in search_results:
                if r.get("distance", 1.0) < 0.7:  # Only include reasonably relevant results
                    results.append({
                        "content": r.get("chunk", ""),
                        "metadata": r.get("metadata", {}),
                        "distance": r.get("distance", 1.0)
                    })
        except Exception:
            continue
    
    # Sort by distance and return top_n
    results.sort(key=lambda x: x["distance"])
    return results[:top_n]
