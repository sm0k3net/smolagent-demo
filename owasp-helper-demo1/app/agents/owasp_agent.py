from __future__ import annotations
from pathlib import Path
from smolagents import CodeAgent, OpenAIServerModel
from app.tools.searxng_tool import searxng_search
from app.tools.owasp_lookup import list_owasp_top10, get_owasp_item
from app.tools.classify import classify_vulnerability
from app.tools.scenarios import generate_test_scenarios
from app.tools.playwright_tool import (
    fetch_page_title,
    browse_page,
    take_screenshot,
    click_and_extract,
    fill_form,
    get_page_links,
    get_page_forms,
    intercept_requests,
    check_console_errors,
)
from app.tools.nmap_tool import nmap_scan
from app.tools.curl_tool import curl_request
from app.tools.osint_tools import (
    virustotal_domain_report,
    virustotal_ip_report,
    shodan_host_info,
    shodan_search,
    hunter_domain_search,
    dns_lookup,
    whois_lookup,
    crt_sh_search,
    securitytrails_domain_info,
    haveibeenpwned_domain,
)
from app.tools.pentest_tools import (
    dnsrecon_scan,
    dirb_scan,
    nikto_scan,
    zap_baseline_scan,
    gobuster_scan,
    whatweb_scan,
    sslyze_scan,
    testssl_scan,
    wpscan_scan,
    subfinder_scan,
    httpx_probe,
    nuclei_scan,
    searchsploit_search,
    searchsploit_examine,
    searchsploit_copy,
    wpscan_full,
    wpscan_password_attack,
    list_available_tools,
    sqlmap_scan,
    sqlmap_dump,
    ffuf_scan,
    ffuf_vhost,
)
from app.tools.report_tools import (
    enable_report_mode,
    disable_report_mode,
    get_report_status,
    add_finding_to_report,
    add_scope_item,
    set_executive_summary,
    set_conclusion,
    generate_html_report,
    generate_markdown_report,
    generate_pdf_report,
)
from app.config import get_settings

# DefectDojo tools are optional; import only if base URL is configured
try:
    from app.tools.defectdojo_tool import (
        defectdojo_health,
        defectdojo_list_products,
        defectdojo_list_engagements,
        defectdojo_ensure_product,
        defectdojo_create_engagement,
        defectdojo_import_scan,
        defectdojo_list_findings,
        defectdojo_create_finding,
        defectdojo_ensure_product_and_create_engagement,
        defectdojo_get_current_context,
        defectdojo_set_current_context,
        defectdojo_record_finding,
    )
    DEFECTDOJO_AVAILABLE = True
except ImportError:
    DEFECTDOJO_AVAILABLE = False

DEFAULT_PROMPT = (
    "You are an OWASP security assistant. Provide concise, actionable guidance aligned with OWASP standards."
)

def load_prompt_text() -> str:
    settings = get_settings()
    # If PROMPT_PATH set, try that first
    candidates = []
    if settings.prompt_path:
        candidates.append(Path(settings.prompt_path))
    candidates.append(Path(__file__).resolve().parent.parent / "prompts" / "owasp_pen_tester.md")
    for p in candidates:
        try:
            if p.exists():
                return p.read_text(encoding="utf-8")
        except Exception:
            continue
    return DEFAULT_PROMPT

def build_owasp_agent() -> CodeAgent:
    settings = get_settings()
    # Prefer OpenAI-compatible DeepSeek API via smolagents
    api_base = settings.deepseek_api_base if hasattr(settings, "deepseek_api_base") else None
    if not api_base:
        # Fallback: derive base by stripping a trailing path if present
        api_base = (settings.deepseek_api_url or "https://api.deepseek.com/v1").split("/v1")[0] + "/v1"
    model = OpenAIServerModel(
        model_id=settings.model,
        api_base=api_base,
        api_key=settings.deepseek_api_key,
        flatten_messages_as_text=True,
    )
    
    # Core OWASP tools
    tools = [
        searxng_search,
        list_owasp_top10,
        get_owasp_item,
        classify_vulnerability,
        generate_test_scenarios,
    ]
    
    # Playwright browser automation tools
    tools.extend([
        fetch_page_title,
        browse_page,
        take_screenshot,
        click_and_extract,
        fill_form,
        get_page_links,
        get_page_forms,
        intercept_requests,
        check_console_errors,
    ])
    
    # Network tools
    tools.extend([
        nmap_scan,
        curl_request,
    ])
    
    # OSINT / Passive Recon tools
    tools.extend([
        virustotal_domain_report,
        virustotal_ip_report,
        shodan_host_info,
        shodan_search,
        hunter_domain_search,
        dns_lookup,
        whois_lookup,
        crt_sh_search,
        securitytrails_domain_info,
        haveibeenpwned_domain,
    ])
    
    # Pentest / Active Recon tools
    tools.extend([
        dnsrecon_scan,
        dirb_scan,
        nikto_scan,
        zap_baseline_scan,
        gobuster_scan,
        whatweb_scan,
        sslyze_scan,
        testssl_scan,
        wpscan_scan,
        wpscan_full,
        wpscan_password_attack,
        subfinder_scan,
        httpx_probe,
        nuclei_scan,
        searchsploit_search,
        searchsploit_examine,
        searchsploit_copy,
        list_available_tools,
        sqlmap_scan,
        sqlmap_dump,
        ffuf_scan,
        ffuf_vhost,
    ])
    
    # Report generation tools
    tools.extend([
        enable_report_mode,
        disable_report_mode,
        get_report_status,
        add_finding_to_report,
        add_scope_item,
        set_executive_summary,
        set_conclusion,
        generate_html_report,
        generate_markdown_report,
        generate_pdf_report,
    ])
    
    # Add DefectDojo tools only if configured
    if DEFECTDOJO_AVAILABLE and settings.defectdojo_base_url:
        tools.extend([
            defectdojo_health,
            defectdojo_list_products,
            defectdojo_list_engagements,
            defectdojo_ensure_product,
            defectdojo_create_engagement,
            defectdojo_import_scan,
            defectdojo_list_findings,
            defectdojo_create_finding,
            defectdojo_ensure_product_and_create_engagement,
            defectdojo_get_current_context,
            defectdojo_set_current_context,
            defectdojo_record_finding,
        ])
    
    # Provide instructions from prompt file
    agent = CodeAgent(tools=tools, model=model, instructions=load_prompt_text())
    return agent
