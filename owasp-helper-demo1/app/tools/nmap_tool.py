from __future__ import annotations
from smolagents import tool
import shutil
import subprocess

@tool
def nmap_scan(target: str, ports: str | None = None, flags: str | None = "-sV -T4") -> str:
    """Run a simple nmap scan (requires nmap installed on the system).

    Args:
        target: host or CIDR to scan (e.g., 192.168.0.10 or example.com)
        ports: optional port spec (e.g., 80,443 or 1-1024)
        flags: additional flags (default: -sV -T4)
    Returns:
        Stdout of nmap or an error message.
    """
    if shutil.which("nmap") is None:
        return "nmap not found on PATH. Install with: sudo apt-get update && sudo apt-get install -y nmap"
    cmd = ["nmap"]
    if flags:
        cmd += flags.split()
    if ports:
        cmd += ["-p", ports]
    cmd += [target]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if res.returncode != 0:
            return f"nmap error: {res.stderr.strip()}"
        return res.stdout
    except Exception as e:  # pragma: no cover
        return f"nmap execution error: {e}"
