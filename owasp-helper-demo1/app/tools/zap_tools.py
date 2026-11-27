"""
OWASP ZAP Tools for comprehensive web application security scanning.

This module provides tools to interact with OWASP ZAP via its API for:
- Starting ZAP in headless/daemon mode (Docker)
- Spider crawling (traditional and AJAX)
- Active and passive vulnerability scanning
- Extracting URLs with parameters for manual injection testing
- Getting alerts and generating reports
"""

import os
import secrets
import time
import json
import subprocess
import requests
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode
from smolagents import tool

# ZAP API configuration - can be overridden via environment variables
ZAP_API_KEY = os.environ.get("ZAP_API_KEY") or secrets.token_urlsafe(32)
ZAP_HOST = os.environ.get("ZAP_HOST", "127.0.0.1")
ZAP_PORT = int(os.environ.get("ZAP_PORT", "8080"))
ZAP_BASE_URL = f"http://{ZAP_HOST}:{ZAP_PORT}"

# Docker image to use
ZAP_DOCKER_IMAGE = os.environ.get("ZAP_DOCKER_IMAGE", "zaproxy/zap-stable")


def _zap_api_call(component: str, operation_type: str, operation: str, params: Dict[str, Any] = None) -> Dict:
    """Make a ZAP API call.
    
    Args:
        component: API component (spider, ascan, ajaxSpider, etc.)
        operation_type: 'view' or 'action'
        operation: The specific operation name
        params: Optional parameters for the API call
        
    Returns:
        JSON response from ZAP API
    """
    url = f"{ZAP_BASE_URL}/JSON/{component}/{operation_type}/{operation}/"
    params = params or {}
    params["apikey"] = ZAP_API_KEY
    
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def _check_zap_running() -> bool:
    """Check if ZAP is running and accessible."""
    try:
        response = requests.get(f"{ZAP_BASE_URL}/JSON/core/view/version/", 
                               params={"apikey": ZAP_API_KEY}, timeout=5)
        return response.status_code == 200
    except:
        return False


@tool
def zap_start_daemon(
    api_key: str = None,
    port: int = 8080,
    docker: bool = True,
    ajax_spider: bool = True,
    memory: str = "2g"
) -> str:
    """Start OWASP ZAP in headless daemon mode for API access.
    
    This starts ZAP as a background daemon, either via Docker (recommended) or locally.
    The daemon provides API access for spider crawling, active scanning, and more.
    
    Args:
        api_key: Custom API key (default: auto-generated). Keep this for subsequent API calls.
        port: Port for ZAP to listen on (default: 8080)
        docker: Use Docker to run ZAP (recommended, default: True)
        ajax_spider: Enable AJAX Spider support with xvfb (default: True)
        memory: Memory allocation for ZAP (default: 2g)
        
    Returns:
        Status message with connection details and API key
    """
    global ZAP_API_KEY, ZAP_PORT, ZAP_BASE_URL
    
    # Check if ZAP is already running
    if _check_zap_running():
        return f"✅ ZAP is already running at {ZAP_BASE_URL}\nAPI key is configured (value redacted)."
    
    # Set configuration
    if api_key:
        ZAP_API_KEY = api_key
    ZAP_PORT = port
    ZAP_BASE_URL = f"http://{ZAP_HOST}:{ZAP_PORT}"
    
    if docker:
        # Use Docker to run ZAP
        zap_script = "zap-x.sh" if ajax_spider else "zap.sh"
        
        cmd = [
            "docker", "run", "-d",
            "--name", "zap-daemon",
            "-u", "zap",
            "-p", f"127.0.0.1:{port}:{port}",
            "-e", f"ZAP_PORT={port}",
            "--memory", memory,
            ZAP_DOCKER_IMAGE,
            zap_script, "-daemon",
            "-host", "0.0.0.0",
            "-port", str(port),
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
            "-config", f"api.key={ZAP_API_KEY}"
        ]
        
        try:
            # First, try to remove any existing container
            subprocess.run(["docker", "rm", "-f", "zap-daemon"], 
                          capture_output=True, timeout=10)
            
            # Start new container
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                return "❌ Failed to start ZAP Docker container. Check Docker logs locally; output is redacted."
            
            container_id = result.stdout.strip()[:12]
            
            # Wait for ZAP to be ready
            max_wait = 60
            for i in range(max_wait):
                time.sleep(2)
                if _check_zap_running():
                    return f"""✅ ZAP daemon started successfully!

📋 Connection Details:
   Host: {ZAP_HOST}
   Port: {ZAP_PORT}
   API Key: [configured; value redacted]
   Container ID: {container_id}
   
🔗 API URL: {ZAP_BASE_URL}
💡 Use this API key for all subsequent ZAP tool calls.

🛠️ Available operations:
   - zap_spider_scan() - Crawl the application
   - zap_ajax_spider_scan() - Crawl AJAX/JS-heavy applications
   - zap_active_scan() - Run vulnerability scanning
   - zap_get_alerts() - Get discovered vulnerabilities
   - zap_get_urls_with_params() - Get URLs for manual testing"""
            
            return f"⏳ ZAP container started (ID: {container_id}) but API not yet responding. Wait a moment and try again."
            
        except subprocess.TimeoutExpired:
            return "❌ Timeout starting ZAP Docker container"
        except Exception as e:
            return "❌ Error starting ZAP. Check local logs; output is redacted."
    else:
        return """❌ Local ZAP installation not supported via this tool.
        
Please either:
1. Use docker=True (default) to run ZAP via Docker
2. Start ZAP manually with: zap.sh -daemon -port 8080 -config api.key=your-key
3. Then use the other ZAP tools to interact with it"""


@tool
def zap_stop_daemon() -> str:
    """Stop the ZAP daemon Docker container.
    
    Returns:
        Status message
    """
    try:
        result = subprocess.run(
            ["docker", "stop", "zap-daemon"],
            capture_output=True, text=True, timeout=30
        )
        subprocess.run(["docker", "rm", "zap-daemon"], capture_output=True, timeout=10)
        
        if result.returncode == 0:
            return "✅ ZAP daemon stopped and container removed"
        else:
            return f"⚠️ Could not stop ZAP daemon: {result.stderr}"
    except Exception as e:
        return f"❌ Error stopping ZAP: {str(e)}"


@tool
def zap_spider_scan(
    target_url: str,
    max_depth: int = 10,
    max_children: int = 0,
    recurse: bool = True,
    subtree_only: bool = False,
    context_name: str = None,
    max_duration_minutes: int = 0
) -> str:
    """Run the traditional ZAP Spider to crawl and discover URLs in a web application.
    
    The Spider discovers new resources by examining HTML responses and following links.
    This is faster than the AJAX Spider but may miss JavaScript-generated content.
    
    Args:
        target_url: The URL to start spidering from (must include http:// or https://)
        max_depth: Maximum crawl depth (0 = unlimited, default: 10)
        max_children: Maximum children per node (0 = unlimited, default: 0)
        recurse: Whether to recursively crawl (default: True)
        subtree_only: Only crawl under the target URL subtree (default: False)
        context_name: Optional ZAP context to constrain the scan
        max_duration_minutes: Maximum duration in minutes (0 = unlimited)
        
    Returns:
        Spider scan status and discovered URLs summary
    """
    if not _check_zap_running():
        return "❌ ZAP is not running. Start it first with zap_start_daemon()"
    
    # Configure spider options
    if max_depth > 0:
        _zap_api_call("spider", "action", "setOptionMaxDepth", {"Integer": max_depth})
    if max_children > 0:
        _zap_api_call("spider", "action", "setOptionMaxChildren", {"Integer": max_children})
    if max_duration_minutes > 0:
        _zap_api_call("spider", "action", "setOptionMaxDuration", {"Integer": max_duration_minutes})
    
    # Start the spider
    params = {
        "url": target_url,
        "recurse": str(recurse).lower(),
        "subtreeOnly": str(subtree_only).lower()
    }
    if context_name:
        params["contextName"] = context_name
    if max_children > 0:
        params["maxChildren"] = str(max_children)
    
    result = _zap_api_call("spider", "action", "scan", params)
    
    if "error" in result:
        return f"❌ Failed to start spider: {result['error']}"
    
    scan_id = result.get("scan")
    if not scan_id:
        return f"❌ Failed to start spider: {result}"
    
    # Poll for completion
    output_lines = [f"🕷️ Spider scan started for: {target_url}", f"   Scan ID: {scan_id}", ""]
    
    last_progress = -1
    while True:
        status = _zap_api_call("spider", "view", "status", {"scanId": scan_id})
        progress = int(status.get("status", 0))
        
        if progress != last_progress:
            output_lines.append(f"   Progress: {progress}%")
            last_progress = progress
        
        if progress >= 100:
            break
        
        time.sleep(2)
    
    # Get results
    results = _zap_api_call("spider", "view", "results", {"scanId": scan_id})
    urls = results.get("results", [])
    
    # Get full results with more details
    full_results = _zap_api_call("spider", "view", "fullResults", {"scanId": scan_id})
    
    output_lines.extend([
        "",
        f"✅ Spider scan complete!",
        f"   URLs discovered: {len(urls)}",
        "",
        "📋 Sample URLs (first 20):"
    ])
    
    for url in urls[:20]:
        output_lines.append(f"   • {url}")
    
    if len(urls) > 20:
        output_lines.append(f"   ... and {len(urls) - 20} more URLs")
    
    output_lines.extend([
        "",
        "💡 Next steps:",
        "   1. Run zap_ajax_spider_scan() for JavaScript-heavy pages",
        "   2. Run zap_get_urls_with_params() to find injection points",
        "   3. Run zap_active_scan() to test for vulnerabilities",
    ])
    
    return "\n".join(output_lines)


@tool
def zap_ajax_spider_scan(
    target_url: str,
    max_duration_minutes: int = 5,
    max_crawl_depth: int = 10,
    max_crawl_states: int = 0,
    number_of_browsers: int = 1,
    subtree_only: bool = False,
    in_scope: bool = False,
    context_name: str = None
) -> str:
    """Run the ZAP AJAX Spider to crawl JavaScript-heavy web applications.
    
    The AJAX Spider uses a real browser to explore the application, allowing it to
    discover content that is dynamically generated by JavaScript. This is slower
    than the traditional spider but more effective for modern web applications.
    
    Args:
        target_url: The URL to start spidering from
        max_duration_minutes: Maximum duration in minutes (default: 5)
        max_crawl_depth: Maximum crawl depth (default: 10)
        max_crawl_states: Maximum number of states to crawl (0 = unlimited)
        number_of_browsers: Number of browser instances (default: 1)
        subtree_only: Only crawl under the target URL subtree (default: False)
        in_scope: Only crawl in-scope URLs (default: False)
        context_name: Optional ZAP context name
        
    Returns:
        AJAX Spider scan status and discovered URLs summary
    """
    if not _check_zap_running():
        return "❌ ZAP is not running. Start it first with zap_start_daemon()"
    
    # Configure AJAX Spider options
    if max_crawl_depth > 0:
        _zap_api_call("ajaxSpider", "action", "setOptionMaxCrawlDepth", {"Integer": max_crawl_depth})
    if max_crawl_states > 0:
        _zap_api_call("ajaxSpider", "action", "setOptionMaxCrawlStates", {"Integer": max_crawl_states})
    if number_of_browsers > 1:
        _zap_api_call("ajaxSpider", "action", "setOptionNumberOfBrowsers", {"Integer": number_of_browsers})
    if max_duration_minutes > 0:
        _zap_api_call("ajaxSpider", "action", "setOptionMaxDuration", {"Integer": max_duration_minutes})
    
    # Start the AJAX Spider
    params = {"url": target_url}
    if subtree_only:
        params["subtreeOnly"] = "true"
    if in_scope:
        params["inScope"] = "true"
    if context_name:
        params["contextName"] = context_name
    
    result = _zap_api_call("ajaxSpider", "action", "scan", params)
    
    if "error" in result:
        return f"❌ Failed to start AJAX Spider: {result['error']}"
    
    output_lines = [
        f"🌐 AJAX Spider started for: {target_url}",
        f"   Max duration: {max_duration_minutes} minutes",
        ""
    ]
    
    # Poll for completion (AJAX Spider doesn't have percentage, just status)
    timeout = time.time() + (max_duration_minutes * 60) + 60  # Add 1 minute buffer
    last_count = 0
    
    while time.time() < timeout:
        status = _zap_api_call("ajaxSpider", "view", "status")
        current_status = status.get("status", "unknown")
        
        # Get number of results
        num_results = _zap_api_call("ajaxSpider", "view", "numberOfResults")
        count = int(num_results.get("numberOfResults", 0))
        
        if count != last_count:
            output_lines.append(f"   Status: {current_status}, URLs found: {count}")
            last_count = count
        
        if current_status.lower() == "stopped":
            break
        
        time.sleep(3)
    
    # If still running, stop it
    final_status = _zap_api_call("ajaxSpider", "view", "status")
    if final_status.get("status", "").lower() == "running":
        _zap_api_call("ajaxSpider", "action", "stop")
        output_lines.append("   ⏹️ Scan stopped (reached time limit)")
    
    # Get results
    results = _zap_api_call("ajaxSpider", "view", "results", {"start": "0", "count": "1000"})
    urls = results.get("results", [])
    
    output_lines.extend([
        "",
        f"✅ AJAX Spider complete!",
        f"   URLs discovered: {len(urls)}",
        "",
        "📋 Sample URLs (first 20):"
    ])
    
    for item in urls[:20]:
        url = item if isinstance(item, str) else item.get("requestHeader", {}).get("uri", str(item))
        output_lines.append(f"   • {url}")
    
    if len(urls) > 20:
        output_lines.append(f"   ... and {len(urls) - 20} more URLs")
    
    output_lines.extend([
        "",
        "💡 Next steps:",
        "   1. Run zap_get_urls_with_params() to find injection points",
        "   2. Run zap_active_scan() to test for vulnerabilities",
    ])
    
    return "\n".join(output_lines)


@tool
def zap_active_scan(
    target_url: str,
    recurse: bool = True,
    in_scope_only: bool = False,
    scan_policy_name: str = None,
    max_scan_duration_minutes: int = 60,
    max_rule_duration_minutes: int = 5,
    delay_in_ms: int = 0
) -> str:
    """Run ZAP Active Scan to find vulnerabilities by attacking the target.
    
    ⚠️ WARNING: Active scanning performs real attacks against the target.
    Only use this on applications you have permission to test!
    
    Active scanning attempts to find vulnerabilities by using known attacks
    against all discovered pages. This includes testing for:
    - SQL Injection
    - Cross-Site Scripting (XSS)
    - Path Traversal
    - Remote Code Execution
    - And many more...
    
    Args:
        target_url: The URL to scan (should be explored first with spider)
        recurse: Scan URLs under the target URL (default: True)
        in_scope_only: Only scan in-scope URLs (default: False)
        scan_policy_name: Name of scan policy to use (optional)
        max_scan_duration_minutes: Maximum scan duration (default: 60)
        max_rule_duration_minutes: Maximum time per scan rule (default: 5)
        delay_in_ms: Delay between requests in ms (default: 0)
        
    Returns:
        Active scan status and vulnerability summary
    """
    if not _check_zap_running():
        return "❌ ZAP is not running. Start it first with zap_start_daemon()"
    
    # Configure active scan options
    if max_scan_duration_minutes > 0:
        _zap_api_call("ascan", "action", "setOptionMaxScanDurationInMins", 
                     {"Integer": max_scan_duration_minutes})
    if max_rule_duration_minutes > 0:
        _zap_api_call("ascan", "action", "setOptionMaxRuleDurationInMins", 
                     {"Integer": max_rule_duration_minutes})
    if delay_in_ms > 0:
        _zap_api_call("ascan", "action", "setOptionDelayInMs", {"Integer": delay_in_ms})
    
    # Enable handling of anti-CSRF tokens
    _zap_api_call("ascan", "action", "setOptionHandleAntiCSRFTokens", {"Boolean": "true"})
    
    # Start active scan
    params = {
        "url": target_url,
        "recurse": str(recurse).lower(),
        "inScopeOnly": str(in_scope_only).lower()
    }
    if scan_policy_name:
        params["scanPolicyName"] = scan_policy_name
    
    result = _zap_api_call("ascan", "action", "scan", params)
    
    if "error" in result:
        return f"❌ Failed to start active scan: {result['error']}"
    
    scan_id = result.get("scan")
    if not scan_id:
        return f"❌ Failed to start active scan: {result}"
    
    output_lines = [
        f"🎯 Active Scan started for: {target_url}",
        f"   Scan ID: {scan_id}",
        f"   Max duration: {max_scan_duration_minutes} minutes",
        "",
        "⚠️ This may take a while. Scanning for vulnerabilities...",
        ""
    ]
    
    # Poll for completion
    last_progress = -1
    start_time = time.time()
    
    while True:
        status = _zap_api_call("ascan", "view", "status", {"scanId": scan_id})
        progress = int(status.get("status", 0))
        
        # Get current alerts count
        alerts = _zap_api_call("core", "view", "numberOfAlerts", {"baseurl": target_url})
        alert_count = alerts.get("numberOfAlerts", "0")
        
        elapsed = int((time.time() - start_time) / 60)
        
        if progress != last_progress or progress % 10 == 0:
            output_lines.append(f"   Progress: {progress}% | Alerts: {alert_count} | Time: {elapsed}m")
            last_progress = progress
        
        if progress >= 100:
            break
        
        if elapsed >= max_scan_duration_minutes:
            _zap_api_call("ascan", "action", "stop", {"scanId": scan_id})
            output_lines.append(f"   ⏹️ Scan stopped (reached {max_scan_duration_minutes} minute limit)")
            break
        
        time.sleep(5)
    
    # Get final alert summary
    alerts_data = _zap_api_call("core", "view", "alerts", {"baseurl": target_url})
    all_alerts = alerts_data.get("alerts", [])
    
    # Categorize alerts by risk
    high = [a for a in all_alerts if a.get("risk") == "High"]
    medium = [a for a in all_alerts if a.get("risk") == "Medium"]
    low = [a for a in all_alerts if a.get("risk") == "Low"]
    info = [a for a in all_alerts if a.get("risk") == "Informational"]
    
    output_lines.extend([
        "",
        "✅ Active Scan Complete!",
        "",
        "📊 Vulnerability Summary:",
        f"   🔴 High Risk:    {len(high)}",
        f"   🟠 Medium Risk:  {len(medium)}",
        f"   🟡 Low Risk:     {len(low)}",
        f"   🔵 Informational: {len(info)}",
        "",
    ])
    
    # Show high and medium risk findings
    if high:
        output_lines.append("🔴 HIGH RISK Vulnerabilities:")
        for alert in high[:10]:
            output_lines.append(f"   • {alert.get('name')}")
            output_lines.append(f"     URL: {alert.get('url', 'N/A')[:80]}")
        if len(high) > 10:
            output_lines.append(f"   ... and {len(high) - 10} more high-risk findings")
        output_lines.append("")
    
    if medium:
        output_lines.append("🟠 MEDIUM RISK Vulnerabilities:")
        for alert in medium[:10]:
            output_lines.append(f"   • {alert.get('name')}")
            output_lines.append(f"     URL: {alert.get('url', 'N/A')[:80]}")
        if len(medium) > 10:
            output_lines.append(f"   ... and {len(medium) - 10} more medium-risk findings")
        output_lines.append("")
    
    output_lines.extend([
        "💡 Next steps:",
        "   1. Run zap_get_alerts() for detailed vulnerability information",
        "   2. Run zap_get_urls_with_params() for manual injection testing",
        "   3. Validate findings manually before reporting",
    ])
    
    return "\n".join(output_lines)


@tool
def zap_get_urls_with_params(
    base_url: str = None,
    include_post_data: bool = True,
    include_headers: bool = False
) -> str:
    """Get all discovered URLs that have parameters (GET, POST, etc.) for manual testing.
    
    This extracts URLs with query parameters and forms for manual injection testing.
    Each parameter is a potential injection point for:
    - SQL Injection
    - XSS (Cross-Site Scripting)
    - Command Injection
    - Path Traversal
    - LDAP Injection
    - etc.
    
    Args:
        base_url: Filter URLs by base URL (optional)
        include_post_data: Include POST data parameters (default: True)
        include_headers: Include HTTP headers in output (default: False)
        
    Returns:
        List of URLs with parameters organized for manual testing
    """
    if not _check_zap_running():
        return "❌ ZAP is not running. Start it first with zap_start_daemon()"
    
    # Get all URLs from ZAP
    params = {}
    if base_url:
        params["baseurl"] = base_url
    
    urls_result = _zap_api_call("core", "view", "urls", params)
    all_urls = urls_result.get("urls", [])
    
    # Also get messages for POST data
    messages_result = _zap_api_call("core", "view", "messages", params)
    messages = messages_result.get("messages", [])
    
    # Analyze URLs with parameters
    urls_with_params = []
    seen_patterns = set()
    
    for url in all_urls:
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            if query_params:
                # Create a pattern to avoid duplicates (same path + param names)
                param_names = tuple(sorted(query_params.keys()))
                pattern = f"{parsed.netloc}{parsed.path}:{param_names}"
                
                if pattern not in seen_patterns:
                    seen_patterns.add(pattern)
                    urls_with_params.append({
                        "url": url,
                        "method": "GET",
                        "params": list(query_params.keys()),
                        "param_count": len(query_params)
                    })
        except:
            continue
    
    # Analyze POST requests from messages
    post_urls = []
    if include_post_data:
        for msg in messages:
            try:
                request_header = msg.get("requestHeader", "")
                request_body = msg.get("requestBody", "")
                
                if "POST " in request_header and request_body:
                    # Extract URL from request header
                    lines = request_header.split("\n")
                    if lines:
                        first_line = lines[0]
                        parts = first_line.split(" ")
                        if len(parts) >= 2:
                            path = parts[1]
                            # Get host from headers
                            host = ""
                            for line in lines:
                                if line.lower().startswith("host:"):
                                    host = line.split(":", 1)[1].strip()
                                    break
                            
                            full_url = f"https://{host}{path}" if host else path
                            
                            # Parse POST body (assume form data)
                            try:
                                post_params = parse_qs(request_body)
                                param_names = list(post_params.keys()) if post_params else []
                            except:
                                # Try to detect JSON
                                if request_body.strip().startswith("{"):
                                    try:
                                        json_data = json.loads(request_body)
                                        param_names = list(json_data.keys()) if isinstance(json_data, dict) else ["[JSON array]"]
                                    except:
                                        param_names = ["[raw body]"]
                                else:
                                    param_names = ["[raw body]"]
                            
                            if param_names:
                                pattern = f"POST:{host}{path}:{tuple(sorted(param_names))}"
                                if pattern not in seen_patterns:
                                    seen_patterns.add(pattern)
                                    post_urls.append({
                                        "url": full_url,
                                        "method": "POST",
                                        "params": param_names,
                                        "param_count": len(param_names),
                                        "body_sample": request_body[:200] if len(request_body) > 200 else request_body
                                    })
            except:
                continue
    
    # Build output
    output_lines = [
        "🎯 URLs with Parameters for Manual Testing",
        "=" * 50,
        "",
        f"📊 Summary:",
        f"   GET requests with params:  {len(urls_with_params)}",
        f"   POST requests with params: {len(post_urls)}",
        f"   Total injection points:    {sum(u['param_count'] for u in urls_with_params + post_urls)}",
        "",
    ]
    
    # GET URLs
    if urls_with_params:
        output_lines.extend([
            "📋 GET Requests with Parameters:",
            "-" * 40,
        ])
        
        # Sort by param count (more params = more interesting)
        urls_with_params.sort(key=lambda x: x["param_count"], reverse=True)
        
        for i, item in enumerate(urls_with_params[:30], 1):
            output_lines.append(f"\n{i}. {item['url'][:100]}")
            output_lines.append(f"   Parameters: {', '.join(item['params'])}")
        
        if len(urls_with_params) > 30:
            output_lines.append(f"\n   ... and {len(urls_with_params) - 30} more GET URLs")
    
    # POST URLs
    if post_urls:
        output_lines.extend([
            "",
            "📋 POST Requests with Parameters:",
            "-" * 40,
        ])
        
        post_urls.sort(key=lambda x: x["param_count"], reverse=True)
        
        for i, item in enumerate(post_urls[:20], 1):
            output_lines.append(f"\n{i}. [POST] {item['url'][:80]}")
            output_lines.append(f"   Parameters: {', '.join(item['params'][:10])}")
            if len(item['params']) > 10:
                output_lines.append(f"   ... and {len(item['params']) - 10} more params")
        
        if len(post_urls) > 20:
            output_lines.append(f"\n   ... and {len(post_urls) - 20} more POST URLs")
    
    output_lines.extend([
        "",
        "=" * 50,
        "💉 Manual Testing Guide:",
        "",
        "For each parameter, test with these injection payloads:",
        "",
        "🔹 SQL Injection:",
        "   ' OR '1'='1",
        "   1' AND '1'='1",
        "   1 UNION SELECT NULL--",
        "",
        "🔹 XSS (Cross-Site Scripting):",
        '   <script>alert(1)</script>',
        '   "><img src=x onerror=alert(1)>',
        "   javascript:alert(1)",
        "",
        "🔹 Command Injection:",
        "   ; ls -la",
        "   | cat /etc/passwd",
        "   `id`",
        "",
        "🔹 Path Traversal:",
        "   ../../../etc/passwd",
        "   ....//....//....//etc/passwd",
        "",
        "💡 Use curl_request() or browse_page() to test these manually",
    ])
    
    return "\n".join(output_lines)


@tool
def zap_get_alerts(
    base_url: str = None,
    risk_level: str = None,
    start: int = 0,
    count: int = 100
) -> str:
    """Get vulnerability alerts discovered by ZAP scanning.
    
    Retrieves detailed information about vulnerabilities found during
    passive and active scanning.
    
    Args:
        base_url: Filter alerts by base URL (optional)
        risk_level: Filter by risk level: "High", "Medium", "Low", "Informational" (optional)
        start: Start index for pagination (default: 0)
        count: Number of alerts to retrieve (default: 100)
        
    Returns:
        Detailed vulnerability alerts with remediation guidance
    """
    if not _check_zap_running():
        return "❌ ZAP is not running. Start it first with zap_start_daemon()"
    
    # Get alerts
    params = {"start": str(start), "count": str(count)}
    if base_url:
        params["baseurl"] = base_url
    if risk_level:
        params["riskId"] = {"High": "3", "Medium": "2", "Low": "1", "Informational": "0"}.get(risk_level, "")
    
    alerts_result = _zap_api_call("core", "view", "alerts", params)
    alerts = alerts_result.get("alerts", [])
    
    if not alerts:
        return "✅ No vulnerabilities found (or no scans have been run yet)"
    
    # Group alerts by risk
    grouped = {"High": [], "Medium": [], "Low": [], "Informational": []}
    for alert in alerts:
        risk = alert.get("risk", "Informational")
        if risk in grouped:
            grouped[risk].append(alert)
    
    output_lines = [
        "🔍 ZAP Vulnerability Alerts",
        "=" * 50,
        "",
        "📊 Summary by Risk Level:",
        f"   🔴 High:         {len(grouped['High'])}",
        f"   🟠 Medium:       {len(grouped['Medium'])}",
        f"   🟡 Low:          {len(grouped['Low'])}",
        f"   🔵 Informational: {len(grouped['Informational'])}",
        "",
    ]
    
    # Output alerts by risk level
    risk_icons = {"High": "🔴", "Medium": "🟠", "Low": "🟡", "Informational": "🔵"}
    
    for risk in ["High", "Medium", "Low", "Informational"]:
        if grouped[risk]:
            output_lines.extend([
                f"\n{risk_icons[risk]} {risk.upper()} RISK ALERTS:",
                "-" * 40,
            ])
            
            # Group by alert type to reduce repetition
            alert_types = {}
            for alert in grouped[risk]:
                name = alert.get("name", "Unknown")
                if name not in alert_types:
                    alert_types[name] = []
                alert_types[name].append(alert)
            
            for name, instances in list(alert_types.items())[:10]:  # Limit to 10 types
                first = instances[0]
                output_lines.extend([
                    f"\n📌 {name} ({len(instances)} instances)",
                    f"   CWE: {first.get('cweid', 'N/A')} | WASC: {first.get('wascid', 'N/A')}",
                    f"   Confidence: {first.get('confidence', 'N/A')}",
                    "",
                    "   Description:",
                    f"   {first.get('description', 'N/A')[:300]}",
                    "",
                    "   Solution:",
                    f"   {first.get('solution', 'N/A')[:300]}",
                    "",
                    "   Affected URLs (first 3):",
                ])
                
                for instance in instances[:3]:
                    url = instance.get("url", "N/A")[:80]
                    param = instance.get("param", "")
                    output_lines.append(f"   • {url}")
                    if param:
                        output_lines.append(f"     Parameter: {param}")
                    evidence = instance.get("evidence", "")
                    if evidence:
                        output_lines.append(f"     Evidence: {evidence[:100]}")
                
                if len(instances) > 3:
                    output_lines.append(f"   ... and {len(instances) - 3} more instances")
            
            if len(alert_types) > 10:
                output_lines.append(f"\n   ... and {len(alert_types) - 10} more alert types")
    
    return "\n".join(output_lines)


@tool
def zap_get_passive_scan_status() -> str:
    """Get the status of ZAP's passive scanning.
    
    Passive scanning analyzes all requests and responses proxied through ZAP
    without modifying them. It's safe and runs automatically in the background.
    
    Returns:
        Passive scan status including queue size and current scan info
    """
    if not _check_zap_running():
        return "❌ ZAP is not running. Start it first with zap_start_daemon()"
    
    records_to_scan = _zap_api_call("pscan", "view", "recordsToScan")
    scanners = _zap_api_call("pscan", "view", "scanners")
    current_rule = _zap_api_call("pscan", "view", "currentRule")
    max_alerts = _zap_api_call("pscan", "view", "maxAlertsPerRule")
    
    output_lines = [
        "📊 Passive Scan Status",
        "=" * 40,
        "",
        f"Records remaining to scan: {records_to_scan.get('recordsToScan', 'N/A')}",
        f"Current rule: {current_rule.get('currentRule', 'None')}",
        f"Max alerts per rule: {max_alerts.get('maxAlertsPerRule', 'N/A')}",
        "",
        "Active Passive Scan Rules:",
    ]
    
    rules = scanners.get("scanners", [])
    enabled_rules = [r for r in rules if r.get("enabled") == "true"]
    
    for rule in enabled_rules[:20]:
        output_lines.append(f"   • {rule.get('name', 'Unknown')}")
    
    if len(enabled_rules) > 20:
        output_lines.append(f"   ... and {len(enabled_rules) - 20} more rules")
    
    return "\n".join(output_lines)


@tool
def zap_generate_report(
    target_url: str,
    report_format: str = "html",
    output_file: str = None
) -> str:
    """Generate a ZAP scan report in various formats.
    
    Args:
        target_url: Base URL to filter report (use the scanned target)
        report_format: Report format - "html", "xml", "json", or "md" (default: html)
        output_file: Optional file path to save the report
        
    Returns:
        Report content or path to saved file
    """
    if not _check_zap_running():
        return "❌ ZAP is not running. Start it first with zap_start_daemon()"
    
    # Get alerts for the report
    alerts_result = _zap_api_call("core", "view", "alerts", {"baseurl": target_url})
    alerts = alerts_result.get("alerts", [])
    
    # Get site tree
    sites_result = _zap_api_call("core", "view", "sites")
    sites = sites_result.get("sites", [])
    
    # Get URLs
    urls_result = _zap_api_call("core", "view", "urls", {"baseurl": target_url})
    urls = urls_result.get("urls", [])
    
    if report_format.lower() == "json":
        report_data = {
            "target": target_url,
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_alerts": len(alerts),
                "high": len([a for a in alerts if a.get("risk") == "High"]),
                "medium": len([a for a in alerts if a.get("risk") == "Medium"]),
                "low": len([a for a in alerts if a.get("risk") == "Low"]),
                "info": len([a for a in alerts if a.get("risk") == "Informational"]),
                "urls_discovered": len(urls)
            },
            "alerts": alerts,
            "urls": urls
        }
        report_content = json.dumps(report_data, indent=2)
        
    elif report_format.lower() == "html":
        # Generate HTML report
        high = [a for a in alerts if a.get("risk") == "High"]
        medium = [a for a in alerts if a.get("risk") == "Medium"]
        low = [a for a in alerts if a.get("risk") == "Low"]
        info = [a for a in alerts if a.get("risk") == "Informational"]
        
        report_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>ZAP Scan Report - {target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
        .high {{ color: #d32f2f; }}
        .medium {{ color: #f57c00; }}
        .low {{ color: #fbc02d; }}
        .info {{ color: #1976d2; }}
        .alert {{ border: 1px solid #ddd; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .alert-high {{ border-left: 4px solid #d32f2f; }}
        .alert-medium {{ border-left: 4px solid #f57c00; }}
        .alert-low {{ border-left: 4px solid #fbc02d; }}
        h1 {{ color: #333; }}
        h2 {{ color: #555; border-bottom: 1px solid #ddd; }}
    </style>
</head>
<body>
    <h1>🔍 ZAP Security Scan Report</h1>
    <p>Target: <strong>{target_url}</strong></p>
    <p>Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <p><span class="high">🔴 High Risk: {len(high)}</span></p>
        <p><span class="medium">🟠 Medium Risk: {len(medium)}</span></p>
        <p><span class="low">🟡 Low Risk: {len(low)}</span></p>
        <p><span class="info">🔵 Informational: {len(info)}</span></p>
        <p>📋 URLs Discovered: {len(urls)}</p>
    </div>
    
    <h2>🔴 High Risk Vulnerabilities</h2>
    {"".join(f'''
    <div class="alert alert-high">
        <h3>{a.get("name")}</h3>
        <p><strong>URL:</strong> {a.get("url")}</p>
        <p><strong>Parameter:</strong> {a.get("param", "N/A")}</p>
        <p><strong>Description:</strong> {a.get("description", "N/A")}</p>
        <p><strong>Solution:</strong> {a.get("solution", "N/A")}</p>
    </div>
    ''' for a in high[:20])}
    
    <h2>🟠 Medium Risk Vulnerabilities</h2>
    {"".join(f'''
    <div class="alert alert-medium">
        <h3>{a.get("name")}</h3>
        <p><strong>URL:</strong> {a.get("url")}</p>
        <p><strong>Parameter:</strong> {a.get("param", "N/A")}</p>
        <p><strong>Description:</strong> {a.get("description", "N/A")}</p>
    </div>
    ''' for a in medium[:20])}
    
    <h2>🟡 Low Risk Vulnerabilities</h2>
    {"".join(f'''
    <div class="alert alert-low">
        <h3>{a.get("name")}</h3>
        <p><strong>URL:</strong> {a.get("url")}</p>
    </div>
    ''' for a in low[:20])}
    
</body>
</html>"""
    else:
        # Markdown format
        high = [a for a in alerts if a.get("risk") == "High"]
        medium = [a for a in alerts if a.get("risk") == "Medium"]
        low = [a for a in alerts if a.get("risk") == "Low"]
        
        report_content = f"""# ZAP Security Scan Report

**Target:** {target_url}
**Generated:** {time.strftime("%Y-%m-%d %H:%M:%S")}

## Summary

| Risk Level | Count |
|------------|-------|
| 🔴 High | {len(high)} |
| 🟠 Medium | {len(medium)} |
| 🟡 Low | {len(low)} |
| 🔵 Info | {len([a for a in alerts if a.get("risk") == "Informational"])} |

**URLs Discovered:** {len(urls)}

## High Risk Vulnerabilities

{"".join(f'''
### {a.get("name")}
- **URL:** {a.get("url")}
- **Parameter:** {a.get("param", "N/A")}
- **CWE:** {a.get("cweid", "N/A")}
- **Description:** {a.get("description", "N/A")[:500]}
- **Solution:** {a.get("solution", "N/A")[:500]}

''' for a in high[:20])}

## Medium Risk Vulnerabilities

{"".join(f'''
### {a.get("name")}
- **URL:** {a.get("url")}
- **Parameter:** {a.get("param", "N/A")}
- **Description:** {a.get("description", "N/A")[:300]}

''' for a in medium[:20])}
"""
    
    # Save to file if requested
    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report_content)
            return f"✅ Report saved to: {output_file}\n\nReport generated with {len(alerts)} alerts for {target_url}"
        except Exception as e:
            return f"❌ Error saving report: {str(e)}\n\n{report_content[:2000]}..."
    
    return report_content[:5000] + ("\n\n... (truncated, use output_file to save full report)" if len(report_content) > 5000 else "")


@tool  
def zap_full_scan(
    target_url: str,
    spider_duration_minutes: int = 5,
    ajax_spider_enabled: bool = True,
    ajax_spider_duration_minutes: int = 3,
    active_scan_duration_minutes: int = 30
) -> str:
    """Run a complete ZAP scan including spider, AJAX spider, and active scan.
    
    This is a convenience function that runs a full security assessment:
    1. Traditional Spider to discover pages
    2. AJAX Spider for JavaScript content (optional)
    3. Active Scan to find vulnerabilities
    
    ⚠️ WARNING: Active scanning performs real attacks. Only use on authorized targets!
    
    Args:
        target_url: The target URL to scan
        spider_duration_minutes: Max duration for traditional spider (default: 5)
        ajax_spider_enabled: Whether to run AJAX spider (default: True)
        ajax_spider_duration_minutes: Max duration for AJAX spider (default: 3)
        active_scan_duration_minutes: Max duration for active scan (default: 30)
        
    Returns:
        Complete scan summary with vulnerabilities found
    """
    if not _check_zap_running():
        return "❌ ZAP is not running. Start it first with zap_start_daemon()"
    
    output_lines = [
        "🚀 Starting Full ZAP Security Scan",
        "=" * 50,
        f"Target: {target_url}",
        "",
        "Phase 1/3: Traditional Spider",
        "-" * 30,
    ]
    
    # Phase 1: Traditional Spider
    spider_result = zap_spider_scan(
        target_url=target_url,
        max_duration_minutes=spider_duration_minutes
    )
    output_lines.append(spider_result)
    output_lines.append("")
    
    # Phase 2: AJAX Spider (optional)
    if ajax_spider_enabled:
        output_lines.extend([
            "Phase 2/3: AJAX Spider",
            "-" * 30,
        ])
        ajax_result = zap_ajax_spider_scan(
            target_url=target_url,
            max_duration_minutes=ajax_spider_duration_minutes
        )
        output_lines.append(ajax_result)
        output_lines.append("")
    else:
        output_lines.append("Phase 2/3: AJAX Spider (skipped)")
        output_lines.append("")
    
    # Wait for passive scanning to complete
    output_lines.append("Waiting for passive scan to process...")
    max_wait = 60
    for _ in range(max_wait):
        status = _zap_api_call("pscan", "view", "recordsToScan")
        remaining = int(status.get("recordsToScan", 0))
        if remaining == 0:
            break
        time.sleep(1)
    output_lines.append("Passive scan complete.")
    output_lines.append("")
    
    # Phase 3: Active Scan
    output_lines.extend([
        "Phase 3/3: Active Vulnerability Scan",
        "-" * 30,
    ])
    active_result = zap_active_scan(
        target_url=target_url,
        max_scan_duration_minutes=active_scan_duration_minutes
    )
    output_lines.append(active_result)
    
    # Final summary
    output_lines.extend([
        "",
        "=" * 50,
        "✅ Full Scan Complete!",
        "",
        "💡 Next Steps:",
        "   1. Run zap_get_alerts() for detailed findings",
        "   2. Run zap_get_urls_with_params() for manual testing",
        "   3. Run zap_generate_report() to export results",
    ])
    
    return "\n".join(output_lines)
