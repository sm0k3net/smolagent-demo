from __future__ import annotations
from smolagents import tool
import shutil
import subprocess
import tempfile
import os

# Import the helper to save outputs as reports
try:
    from .report_tools import save_task_output_as_report
except ImportError:
    save_task_output_as_report = None

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
        
        output = res.stdout
        
        # Auto-save output as a report file if task tracking is available
        if save_task_output_as_report and output:
            try:
                save_task_output_as_report(output, "nmap", target, "txt")
            except Exception:
                pass  # Don't fail the scan if report saving fails
        
        return output
    except Exception as e:  # pragma: no cover
        return f"nmap execution error: {e}"


@tool
def nmap_scan_full(target: str, ports: str | None = None, flags: str | None = "-sV -sC -T4", output_html: bool = True) -> str:
    """Run a comprehensive nmap scan with XML and optional HTML output for reports.
    
    This function produces both text output and generates XML/HTML reports that can be 
    attached to the penetration test report artifacts.

    Args:
        target: host or CIDR to scan (e.g., 192.168.0.10 or example.com)
        ports: optional port spec (e.g., 80,443 or 1-1024 or "-" for all ports)
        flags: additional flags (default: -sV -sC -T4 for version detection + scripts)
        output_html: if True, generate HTML report using xsltproc (default: True)
    Returns:
        Dictionary with: stdout, xml_output, html_output (if generated), and paths to files.
    """
    import json
    from datetime import datetime
    
    if shutil.which("nmap") is None:
        return "nmap not found on PATH. Install with: sudo apt-get update && sudo apt-get install -y nmap"
    
    # Create temp directory for outputs
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_safe = target.replace("/", "_").replace(":", "_").replace(".", "_")
    
    # Use temp directory
    temp_dir = tempfile.mkdtemp(prefix="nmap_")
    xml_file = os.path.join(temp_dir, f"nmap_{target_safe}_{timestamp}.xml")
    html_file = os.path.join(temp_dir, f"nmap_{target_safe}_{timestamp}.html")
    
    cmd = ["nmap"]
    if flags:
        cmd += flags.split()
    if ports:
        cmd += ["-p", ports]
    
    # Add XML output
    cmd += ["-oX", xml_file]
    cmd += [target]
    
    result = {
        "success": False,
        "stdout": "",
        "xml_output": "",
        "html_output": "",
        "xml_file": xml_file,
        "html_file": "",
        "error": None
    }
    
    try:
        # Run nmap with XML output
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if res.returncode != 0:
            result["error"] = f"nmap error: {res.stderr.strip()}"
            return json.dumps(result, indent=2)
        
        result["stdout"] = res.stdout
        result["success"] = True
        
        # Read XML output
        if os.path.exists(xml_file):
            with open(xml_file, 'r') as f:
                result["xml_output"] = f.read()
        
        # Generate HTML report if requested
        if output_html and result["xml_output"]:
            html_content = _generate_nmap_html_report(result["xml_output"], target)
            if html_content:
                with open(html_file, 'w') as f:
                    f.write(html_content)
                result["html_output"] = html_content
                result["html_file"] = html_file
        
        # Try to auto-add to report if report mode is enabled
        try:
            from app.tools.report_tools import is_report_mode_enabled, add_tool_output_to_report
            if is_report_mode_enabled():
                # Add XML output to report artifacts
                add_tool_output_to_report(
                    tool_name="nmap",
                    output_data=result["xml_output"],
                    output_format="xml",
                    filename=f"nmap_{target_safe}_{timestamp}.xml",
                    description=f"Nmap scan results for {target}"
                )
                
                # Add HTML report if generated
                if result["html_output"]:
                    add_tool_output_to_report(
                        tool_name="nmap",
                        output_data=result["html_output"],
                        output_format="html",
                        filename=f"nmap_{target_safe}_{timestamp}.html",
                        description=f"Nmap HTML report for {target}"
                    )
        except ImportError:
            pass  # Report tools not available
        
        return json.dumps(result, indent=2)
        
    except subprocess.TimeoutExpired:
        result["error"] = "nmap scan timed out after 10 minutes"
        return json.dumps(result, indent=2)
    except Exception as e:
        result["error"] = f"nmap execution error: {str(e)}"
        return json.dumps(result, indent=2)


def _generate_nmap_html_report(xml_data: str, target: str) -> str:
    """Generate an HTML report from nmap XML output."""
    import xml.etree.ElementTree as ET
    from datetime import datetime
    
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return ""
    
    # Extract scan info
    scan_args = root.get('args', 'N/A')
    scan_start = root.get('startstr', 'N/A')
    scanner = root.get('scanner', 'nmap')
    version = root.get('version', 'N/A')
    
    # Extract hosts
    hosts_html = ""
    for host in root.findall('.//host'):
        status = host.find('status')
        host_state = status.get('state', 'unknown') if status is not None else 'unknown'
        
        # Get addresses
        addresses = []
        for addr in host.findall('address'):
            addr_type = addr.get('addrtype', '')
            addr_val = addr.get('addr', '')
            if addr_type and addr_val:
                addresses.append(f"{addr_val} ({addr_type})")
        
        # Get hostnames
        hostnames = []
        for hostname in host.findall('.//hostname'):
            name = hostname.get('name', '')
            if name:
                hostnames.append(name)
        
        # Get ports
        ports_html = ""
        ports = host.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                port_id = port.get('portid', '')
                protocol = port.get('protocol', '')
                
                state = port.find('state')
                port_state = state.get('state', 'unknown') if state is not None else 'unknown'
                
                service = port.find('service')
                if service is not None:
                    svc_name = service.get('name', '')
                    svc_product = service.get('product', '')
                    svc_version = service.get('version', '')
                    svc_info = f"{svc_name}"
                    if svc_product:
                        svc_info += f" ({svc_product}"
                        if svc_version:
                            svc_info += f" {svc_version}"
                        svc_info += ")"
                else:
                    svc_info = 'unknown'
                
                state_class = 'open' if port_state == 'open' else 'filtered' if port_state == 'filtered' else 'closed'
                ports_html += f'''
                <tr>
                    <td>{port_id}/{protocol}</td>
                    <td class="port-{state_class}">{port_state}</td>
                    <td>{svc_info}</td>
                </tr>
                '''
        
        # Get scripts output
        scripts_html = ""
        for hostscript in host.findall('.//hostscript/script') + list(ports.findall('.//script') if ports is not None else []):
            script_id = hostscript.get('id', '')
            script_output = hostscript.get('output', '')
            if script_id and script_output:
                scripts_html += f'''
                <div class="script-output">
                    <h4>{script_id}</h4>
                    <pre>{script_output}</pre>
                </div>
                '''
        
        hosts_html += f'''
        <div class="host-card">
            <div class="host-header">
                <span class="host-ip">{", ".join(addresses) if addresses else "Unknown"}</span>
                <span class="host-state state-{host_state}">{host_state}</span>
            </div>
            {f'<div class="host-names">{", ".join(hostnames)}</div>' if hostnames else ''}
            <div class="host-ports">
                <h3>Open Ports & Services</h3>
                <table>
                    <thead>
                        <tr><th>Port</th><th>State</th><th>Service</th></tr>
                    </thead>
                    <tbody>{ports_html if ports_html else '<tr><td colspan="3">No ports found</td></tr>'}</tbody>
                </table>
            </div>
            {f'<div class="host-scripts"><h3>Script Results</h3>{scripts_html}</div>' if scripts_html else ''}
        </div>
        '''
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nmap Scan Report - {target}</title>
    <style>
        :root {{
            --primary: #1e3a5f;
            --accent: #00b4d8;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ 
            font-family: 'Inter', 'Segoe UI', system-ui, sans-serif; 
            line-height: 1.6; 
            color: #1e293b;
            background: #f1f5f9;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, var(--primary) 0%, #2d5a8a 100%);
            color: white;
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 1.5rem;
        }}
        .header h1 {{ font-size: 1.75rem; margin-bottom: 0.5rem; }}
        .header .meta {{ opacity: 0.85; font-size: 0.9rem; }}
        .scan-info {{
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .scan-info h2 {{ color: var(--primary); margin-bottom: 1rem; font-size: 1.2rem; }}
        .scan-info pre {{ 
            background: #1e293b; 
            color: #e2e8f0; 
            padding: 1rem; 
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.85rem;
        }}
        .host-card {{
            background: white;
            border-radius: 12px;
            margin-bottom: 1.5rem;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .host-header {{
            background: var(--primary);
            color: white;
            padding: 1rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .host-ip {{ font-weight: 700; font-size: 1.1rem; }}
        .host-state {{ 
            padding: 0.25rem 0.75rem; 
            border-radius: 20px; 
            font-size: 0.85rem;
            font-weight: 600;
        }}
        .state-up {{ background: var(--success); }}
        .state-down {{ background: var(--danger); }}
        .host-names {{ padding: 0.75rem 1.5rem; background: #f8fafc; font-size: 0.9rem; color: #64748b; }}
        .host-ports {{ padding: 1.5rem; }}
        .host-ports h3 {{ color: var(--primary); margin-bottom: 1rem; font-size: 1rem; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f8fafc; font-weight: 600; color: #475569; font-size: 0.85rem; }}
        .port-open {{ color: var(--success); font-weight: 700; }}
        .port-filtered {{ color: var(--warning); font-weight: 700; }}
        .port-closed {{ color: var(--danger); font-weight: 700; }}
        .host-scripts {{ padding: 1.5rem; border-top: 1px solid #e2e8f0; }}
        .host-scripts h3 {{ color: var(--primary); margin-bottom: 1rem; font-size: 1rem; }}
        .script-output {{ margin-bottom: 1rem; }}
        .script-output h4 {{ color: #475569; font-size: 0.9rem; margin-bottom: 0.5rem; }}
        .script-output pre {{ 
            background: #1e293b; 
            color: #e2e8f0; 
            padding: 1rem; 
            border-radius: 8px;
            font-size: 0.8rem;
            overflow-x: auto;
        }}
        @media print {{
            body {{ background: white; padding: 0; }}
            .host-card {{ break-inside: avoid; box-shadow: none; border: 1px solid #e2e8f0; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Nmap Scan Report</h1>
            <div class="meta">
                Target: {target} | Scanner: {scanner} {version} | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </div>
        </div>
        
        <div class="scan-info">
            <h2>Scan Configuration</h2>
            <pre>{scan_args}</pre>
            <p style="margin-top: 0.75rem; color: #64748b; font-size: 0.9rem;">Started: {scan_start}</p>
        </div>
        
        <h2 style="color: var(--primary); margin-bottom: 1rem;">Discovered Hosts</h2>
        {hosts_html if hosts_html else '<p>No hosts discovered.</p>'}
    </div>
</body>
</html>'''
    
    return html
