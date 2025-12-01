from __future__ import annotations
import shutil
import subprocess
import os
from smolagents import tool

# Import proxy config from pentest_tools
try:
    from app.tools.pentest_tools import get_proxy_url, get_proxy_env
except ImportError:
    # Fallback if import fails
    def get_proxy_url():
        return None
    def get_proxy_env():
        return {}

@tool
def curl_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: str | None = None,
    insecure: bool = False,
    timeout: int = 30,
    include_headers: bool = True,
    max_output_chars: int = 100000,
    use_proxy: bool = True,
) -> str:
    """Perform an HTTP request using curl (non-interactive, safe subset of options).

    Args:
        url: Target URL to request.
        method: HTTP method (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH). Defaults to GET.
        headers: Optional HTTP headers as a key-value mapping, e.g., {"Accept":"application/json"}.
        data: Optional request body (sent as --data). Avoid binary uploads in this tool.
        insecure: If true, pass -k to ignore TLS cert validation (use sparingly).
        timeout: Max time in seconds before aborting the request (curl --max-time).
        include_headers: If true, include response headers (-i).
        max_output_chars: Truncate combined output to this many characters to keep responses manageable.
        use_proxy: If true, use configured proxy settings (default True).
    Returns:
        A string containing the curl exit code, and captured output (headers + body if requested). If curl is not
        installed, returns an instruction to install it.
    """
    if shutil.which("curl") is None:
        return "curl not found. Install with: sudo apt-get update && sudo apt-get install -y curl"

    # Build curl command safely (no shell)
    cmd: list[str] = [
        "curl",
        "-sS",  # silent with errors
        "-L",   # follow redirects
        "--max-time", str(int(timeout)),
    ]
    
    # Add proxy if configured and enabled
    if use_proxy:
        proxy_url = get_proxy_url()
        if proxy_url:
            cmd += ["-x", proxy_url]
    
    if include_headers:
        cmd.append("-i")
    if insecure:
        cmd.append("-k")
    method_u = (method or "GET").upper()
    if method_u != "GET":
        cmd += ["-X", method_u]
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if data is not None:
        cmd += ["--data", data]
    cmd.append(url)

    try:
        # Use environment with proxy settings as fallback
        env = os.environ.copy()
        if use_proxy:
            env.update(get_proxy_env())
        
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5, env=env)
        out = (res.stdout or "") + (("\n[stderr]\n" + res.stderr) if res.stderr else "")
        out = out[:max(0, max_output_chars)]
        return f"[exit_code]={res.returncode}\n" + out
    except Exception as e:  # pragma: no cover
        return f"curl execution error: {e}"
