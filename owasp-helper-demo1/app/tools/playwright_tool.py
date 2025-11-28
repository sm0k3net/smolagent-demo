"""Playwright browser automation tools for real human-like interaction."""
from __future__ import annotations
import base64
import tempfile
import os
import subprocess
import sys
from smolagents import tool


def _check_playwright_installed() -> tuple[bool, str | None]:
    """Check if Playwright is installed and browser is available."""
    try:
        from playwright.sync_api import sync_playwright
        return True, None
    except ImportError:
        return False, "Playwright not installed"


def _install_playwright_package() -> tuple[bool, str]:
    """Install playwright package via pip."""
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', 'playwright'],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode == 0:
            return True, "Playwright package installed successfully"
        return False, f"Failed to install playwright: {result.stderr}"
    except Exception as e:
        return False, f"Error installing playwright: {e}"


def _install_browser(browser: str = "chromium") -> tuple[bool, str]:
    """Install Playwright browser binaries."""
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'playwright', 'install', browser],
            capture_output=True,
            text=True,
            timeout=300  # Browser downloads can take time
        )
        if result.returncode == 0:
            return True, f"{browser} browser installed successfully"
        return False, f"Failed to install {browser}: {result.stderr}"
    except Exception as e:
        return False, f"Error installing browser: {e}"


def _ensure_playwright_ready() -> tuple[bool, str]:
    """Ensure Playwright and Chromium are ready to use. Auto-installs if needed."""
    # Check if playwright package is installed
    installed, _ = _check_playwright_installed()
    if not installed:
        print("📦 Installing Playwright package...")
        success, msg = _install_playwright_package()
        if not success:
            return False, msg
        print(f"✅ {msg}")
    
    # Try to launch browser to check if it's installed
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True, "Playwright ready"
    except Exception as e:
        error_msg = str(e)
        if "Executable doesn't exist" in error_msg or "browserType.launch" in error_msg:
            print("📦 Installing Chromium browser...")
            success, msg = _install_browser("chromium")
            if success:
                print(f"✅ {msg}")
                return True, "Playwright and Chromium installed successfully"
            return False, msg
        return False, f"Playwright error: {e}"


def _get_playwright_with_auto_install():
    """Get Playwright sync API, auto-installing if needed."""
    ready, msg = _ensure_playwright_ready()
    if not ready:
        return None, msg
    
    try:
        from playwright.sync_api import sync_playwright
        return sync_playwright, None
    except ImportError:
        return None, "Failed to import playwright after installation"


def _get_playwright():
    """Get Playwright sync API or return None with error."""
    installed, error = _check_playwright_installed()
    if not installed:
        return None, error
    
    try:
        from playwright.sync_api import sync_playwright
        return sync_playwright, None
    except ImportError:
        return None, "Playwright not installed. Install with: pip install playwright && playwright install chromium"


@tool
def fetch_page_title(url: str) -> str:
    """Fetch a page title using Playwright (headless). Auto-installs Playwright if needed.

    Args:
        url: The URL to open.
    Returns:
        Extracted <title> text or an error message.
    """
    sync_playwright, err = _get_playwright_with_auto_install()
    if err:
        return err
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            title = page.title()
            browser.close()
            return title
    except Exception as e:
        return f"Playwright error: {e}"


@tool
def browse_page(url: str, wait_for: str | None = None, timeout: int = 30000) -> str:
    """Navigate to a URL and return the page content and metadata. Auto-installs Playwright if needed.

    Args:
        url: The URL to navigate to.
        wait_for: Optional CSS selector to wait for before returning.
        timeout: Navigation timeout in milliseconds (default 30000).
    Returns: Page title, URL, and text content summary.
    """
    sync_playwright, err = _get_playwright_with_auto_install()
    if err:
        return err
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            page = context.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=timeout)
            
            # Wait for load state with shorter timeout (don't block forever)
            try:
                page.wait_for_load_state("load", timeout=10000)
            except:
                pass  # Continue if load times out
            
            if wait_for:
                page.wait_for_selector(wait_for, timeout=timeout)
            
            title = page.title()
            final_url = page.url
            
            # Get text content (limited)
            text = page.inner_text("body")
            if len(text) > 5000:
                text = text[:5000] + "... (truncated)"
            
            browser.close()
            
            return f"Title: {title}\nURL: {final_url}\n\nContent:\n{text}"
    except Exception as e:
        return f"Playwright error: {e}"


@tool
def take_screenshot(url: str, full_page: bool = False, output_dir: str = "/tmp/screenshots") -> str:
    """Take a screenshot of a webpage and return the image data. Auto-installs Playwright if needed.

    Args:
        url: The URL to screenshot.
        full_page: Whether to capture the full scrollable page (default False).
        output_dir: Directory to save screenshots (default /tmp/screenshots).
    Returns: Screenshot information including base64 data for display and file path.
    """
    # Use auto-install version to ensure Playwright and browser are ready
    sync_playwright, err = _get_playwright_with_auto_install()
    if err:
        return err
    
    try:
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate unique filename
        from datetime import datetime
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.replace(":", "_").replace(".", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"screenshot_{domain}_{timestamp}.png"
        screenshot_path = os.path.join(output_dir, filename)
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1920, "height": 1080})
            
            # Set user agent
            page.set_extra_http_headers({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            })
            
            # Use domcontentloaded for faster, more reliable page loading
            page.goto(url, wait_until="domcontentloaded", timeout=60000)
            # Give extra time for dynamic content but don't block on network
            try:
                page.wait_for_load_state("load", timeout=10000)
            except:
                pass  # Continue if load state times out
            page.wait_for_timeout(1500)  # Brief wait for any lazy-loaded content
            
            page.screenshot(path=screenshot_path, full_page=full_page)
            title = page.title()
            browser.close()
            
            # Read and encode as base64 for display
            with open(screenshot_path, "rb") as f:
                image_data = f.read()
                base64_data = base64.b64encode(image_data).decode()
            
            file_size = len(image_data) / 1024  # KB
            
            # Return format optimized for chat display with embedded image
            # Use SCREENSHOT_IMAGE_DATA format that the UI recognizes
            return f"""📸 Screenshot Captured Successfully!

**URL:** {url}
**Page Title:** {title}
**Size:** {file_size:.1f} KB
**Saved to:** `{screenshot_path}`

SCREENSHOT_IMAGE_DATA:{base64_data}:END_IMAGE_DATA"""
    except Exception as e:
        error_msg = str(e)
        if "Executable doesn't exist" in error_msg or "browserType.launch" in error_msg:
            return f"""Chromium browser not installed. Please run:

```bash
playwright install chromium
```

Or install all browsers:
```bash
playwright install
```

Original error: {error_msg}"""
        return f"Playwright error: {e}"


@tool
def click_and_extract(url: str, click_selector: str, extract_selector: str) -> str:
    """Click an element and extract text from another element. Auto-installs Playwright if needed.

    Args:
        url: The URL to navigate to.
        click_selector: CSS selector of element to click.
        extract_selector: CSS selector of element to extract text from after clicking.
    Returns: Extracted text content.
    """
    sync_playwright, err = _get_playwright_with_auto_install()
    if err:
        return err
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            page = context.new_page()
            page.goto(url, wait_until="networkidle", timeout=30000)
            
            # Click the element
            page.click(click_selector)
            page.wait_for_timeout(1000)  # Wait for any animations/loads
            
            # Extract text
            text = page.inner_text(extract_selector)
            
            browser.close()
            return f"Extracted text:\n{text}"
    except Exception as e:
        return f"Playwright error: {e}"


@tool
def fill_form(url: str, form_data: str, submit_selector: str | None = None) -> str:
    """Fill a form on a webpage with provided data. Auto-installs Playwright if needed.

    Args:
        url: The URL containing the form.
        form_data: JSON string of selector:value pairs (e.g., '{"#username": "test", "#password": "pass"}').
        submit_selector: Optional CSS selector for submit button to click.
    Returns: Result of form submission or page state after filling.
    """
    sync_playwright, err = _get_playwright_with_auto_install()
    if err:
        return err
    
    try:
        import json
        data = json.loads(form_data)
    except Exception as e:
        return f"Invalid form_data JSON: {e}"
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            page = context.new_page()
            page.goto(url, wait_until="networkidle", timeout=30000)
            
            # Fill each field
            for selector, value in data.items():
                page.fill(selector, value)
            
            result = f"Filled {len(data)} form fields"
            
            # Submit if requested
            if submit_selector:
                page.click(submit_selector)
                page.wait_for_load_state("networkidle")
                result += f"\nSubmitted form. New URL: {page.url}\nTitle: {page.title()}"
            
            browser.close()
            return result
    except Exception as e:
        return f"Playwright error: {e}"


@tool
def get_page_links(url: str, filter_domain: bool = True) -> str:
    """Extract all links from a webpage. Auto-installs Playwright if needed.

    Args:
        url: The URL to extract links from.
        filter_domain: Only return links from the same domain (default True).
    Returns: List of discovered links.
    """
    sync_playwright, err = _get_playwright_with_auto_install()
    if err:
        return err
    
    try:
        from urllib.parse import urlparse
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=30000)
            
            # Get all links
            links = page.eval_on_selector_all("a[href]", "elements => elements.map(e => e.href)")
            
            # Filter by domain if requested
            if filter_domain:
                base_domain = urlparse(url).netloc
                links = [l for l in links if urlparse(l).netloc == base_domain]
            
            # Deduplicate
            links = sorted(set(links))
            
            browser.close()
            
            result = [f"Found {len(links)} links on {url}:", ""]
            result.extend([f"  - {l}" for l in links[:100]])
            if len(links) > 100:
                result.append(f"  ... and {len(links) - 100} more")
            
            return "\n".join(result)
    except Exception as e:
        return f"Playwright error: {e}"


@tool
def get_page_forms(url: str) -> str:
    """Extract all forms and their inputs from a webpage. Auto-installs Playwright if needed.

    Args:
        url: The URL to analyze for forms.
    Returns: Detailed information about forms and their fields.
    """
    sync_playwright, err = _get_playwright_with_auto_install()
    if err:
        return err
        return err
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=30000)
            
            # Extract form info
            forms = page.eval_on_selector_all("form", """forms => forms.map(form => ({
                action: form.action,
                method: form.method,
                id: form.id,
                inputs: Array.from(form.querySelectorAll('input, select, textarea')).map(input => ({
                    type: input.type || input.tagName.toLowerCase(),
                    name: input.name,
                    id: input.id,
                    placeholder: input.placeholder,
                    required: input.required
                }))
            }))""")
            
            browser.close()
            
            if not forms:
                return f"No forms found on {url}"
            
            result = [f"Found {len(forms)} forms on {url}:", ""]
            
            for i, form in enumerate(forms, 1):
                result.append(f"Form {i}:")
                result.append(f"  Action: {form.get('action', 'N/A')}")
                result.append(f"  Method: {form.get('method', 'GET').upper()}")
                result.append(f"  ID: {form.get('id', 'N/A')}")
                result.append("  Fields:")
                
                for inp in form.get('inputs', []):
                    req = " (required)" if inp.get('required') else ""
                    result.append(f"    - {inp.get('name', 'unnamed')}: {inp.get('type', 'text')}{req}")
                
                result.append("")
            
            return "\n".join(result)
    except Exception as e:
        return f"Playwright error: {e}"


@tool
def intercept_requests(url: str, log_types: str = "xhr,fetch,document") -> str:
    """Navigate to a URL and log network requests. Auto-installs Playwright if needed.

    Args:
        url: The URL to navigate to.
        log_types: Comma-separated request types to log (xhr, fetch, document, stylesheet, image, script).
    Returns: List of network requests made by the page.
    """
    sync_playwright, err = _get_playwright_with_auto_install()
    if err:
        return err
    
    types = [t.strip().lower() for t in log_types.split(",")]
    requests = []
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            
            def log_request(request):
                if request.resource_type.lower() in types:
                    requests.append({
                        "method": request.method,
                        "url": request.url[:200],
                        "type": request.resource_type
                    })
            
            page.on("request", log_request)
            page.goto(url, wait_until="networkidle", timeout=30000)
            
            browser.close()
            
            result = [f"Network requests from {url}:", f"Logged {len(requests)} requests:", ""]
            
            for req in requests[:50]:
                result.append(f"  [{req['method']}] {req['type']}: {req['url']}")
            
            if len(requests) > 50:
                result.append(f"  ... and {len(requests) - 50} more")
            
            return "\n".join(result)
    except Exception as e:
        return f"Playwright error: {e}"


@tool
def check_console_errors(url: str) -> str:
    """Navigate to a URL and capture JavaScript console errors. Auto-installs Playwright if needed.

    Args:
        url: The URL to check for console errors.
    Returns: List of console errors and warnings.
    """
    sync_playwright, err = _get_playwright_with_auto_install()
    if err:
        return err
    
    console_logs = []
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            
            def log_console(msg):
                if msg.type in ["error", "warning"]:
                    console_logs.append({
                        "type": msg.type,
                        "text": msg.text[:500]
                    })
            
            page.on("console", log_console)
            page.goto(url, wait_until="networkidle", timeout=30000)
            page.wait_for_timeout(2000)  # Wait for any delayed errors
            
            browser.close()
            
            if not console_logs:
                return f"No console errors or warnings found on {url}"
            
            result = [f"Console output from {url}:", f"Found {len(console_logs)} errors/warnings:", ""]
            
            for log in console_logs:
                prefix = "❌" if log['type'] == "error" else "⚠️"
                result.append(f"  {prefix} [{log['type']}] {log['text']}")
            
            return "\n".join(result)
    except Exception as e:
        return f"Playwright error: {e}"

