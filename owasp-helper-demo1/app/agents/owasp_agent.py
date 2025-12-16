from __future__ import annotations
from pathlib import Path
from smolagents import CodeAgent, OpenAIServerModel
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
from app.tools.nmap_tool import nmap_scan, nmap_scan_full
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
    duckduckgo_search,
    duckduckgo_news,
    google_dork_suggestions,
)
# Enhanced SearXNG tools with auto-discovery
from app.tools.searxng_tools import (
    searxng_find_instances,
    searxng_search as searxng_metasearch,
    searxng_security_search,
    searxng_dork_search,
)
# Enhanced VirusTotal tools
from app.tools.virustotal_tools import (
    virustotal_subdomains,
    virustotal_domain_analysis,
    virustotal_ip_analysis,
    virustotal_resolutions,
    virustotal_url_scan,
    virustotal_file_hash,
    virustotal_ssl_certificates,
    virustotal_communicating_files,
    virustotal_whois_history,
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
    nuclei_update_templates,
    nuclei_search_templates,
    nuclei_download_template,
    nuclei_list_templates,
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
    amass_enum,
    amass_intel,
    xsser_scan,
    xsser_fuzzing,
    # Wordlist and brute force tools
    get_wordlist,
    list_wordlists,
    hydra_brute_force,
    hydra_ssh_brute,
    hydra_ftp_brute,
    hydra_rdp_brute,
    hydra_mysql_brute,
    hydra_http_form_brute,
    nmap_with_brute,
    # Proxy status tool
    check_proxy_status,
    # Installation tools
    install_python_package,
    install_playwright_browsers,
    install_system_tool,
    install_cloudflared,
    check_and_install_dependencies,
    # Advanced bug bounty tools
    arjun_scan,
    paramspider_scan,
    jwt_analyze,
    jwt_forge,
    graphql_introspection,
    race_condition_test,
    ssrf_payloads,
    xss_payloads,
    idor_payloads,
    # CVE exploitation tools
    vulners_search_cve,
    vulners_search_exploit,
    nvd_lookup,
    run_exploit,
    msfconsole_command,
    exploit_db_search,
    download_exploit,
    cve_to_exploit_workflow,
)
# Multi-agent delegation tools (old system - kept for backwards compatibility)
from app.agents.sub_agents import (
    delegate_reconnaissance,
    delegate_vulnerability_scan,
    delegate_exploitation,
    delegate_report_generation,
    run_parallel_scans,
    get_sub_agent_status,
    get_sub_agent_results,
    create_custom_sub_agent,
)
# New hierarchical multi-agent system with shared context
from app.agents.multi_agent_system import (
    # Project initialization
    initialize_pentest_project,
    get_project_status,
    # Shared context access
    submit_recon_data,
    submit_finding,
    get_recon_data,
    get_pending_findings,
    validate_finding,
    mark_finding_exploited,
    mark_phase_complete,
    get_validated_findings_for_report,
    save_tool_output,
    add_qc_note,
    get_agent_activity_log,
    # Report compilation
    compile_final_report,
    review_final_report,
    approve_final_report,
    # Agent dispatchers
    dispatch_recon_agent,
    dispatch_vuln_scanner_agent,
    dispatch_manual_tester_agent,
    dispatch_exploitation_agent,
    dispatch_qc_agent_review,
    dispatch_reporting_agent,
    dispatch_qc_final_review,
    run_full_pentest_orchestration,
)
from app.tools.report_tools import (
    enable_report_mode,
    disable_report_mode,
    get_report_status,
    add_finding_to_report,
    add_scope_item,
    set_executive_summary,
    set_conclusion,
    add_screenshot_to_report,
    add_screenshot_to_finding,
    add_tool_output_to_report,
    generate_html_report,
    generate_markdown_report,
    generate_pdf_report,
    add_recon_data,
    add_bulk_scope,
    get_recon_summary,
    add_dns_record,
    add_service_discovery,
    add_technology_stack,
    add_network_topology,
    record_tool_used,
    # Finding import helpers
    import_zap_alerts_to_findings,
    import_nikto_findings,
    # Note access tools
    get_note_content,
    list_available_notes,
    insert_note_content_to_report,
    # Note creation/modification tools
    create_note,
    update_note,
    create_note_folder,
    # Project management tools
    create_project,
    add_task_to_project,
    list_projects,
    # Report regeneration tools
    save_pentest_session,
    restore_pentest_session,
    modify_finding,
    remove_finding,
    list_current_findings,
    update_executive_summary,
    update_conclusion,
)
# VectorDB-based semantic memory tools
from app.tools.memory_tools import (
    save_to_memory,
    search_memory,
    clear_memory,
    get_memory_status,
    initialize_memory,
)
from app.tools.telegram_tool import (
    telegram_connect,
    telegram_set_chat,
    telegram_send_message,
    telegram_send_file,
    telegram_get_updates,
    telegram_status,
    telegram_disconnect,
)
from app.tools.slack_tool import (
    slack_connect,
    slack_send_message,
    slack_send_formatted,
    slack_send_alert,
    slack_send_report_summary,
    slack_send_file,
    slack_start_listening,
    slack_stop_listening,
    slack_get_messages,
    slack_status,
    slack_disconnect,
)
from app.tools.zap_tools import (
    zap_start_daemon,
    zap_stop_daemon,
    zap_spider_scan,
    zap_ajax_spider_scan,
    zap_active_scan,
    zap_get_passive_scan_status,
    zap_get_alerts,
    zap_get_urls_with_params,
    zap_generate_report,
    zap_full_scan,
)
from app.config import get_settings, PROVIDER_CONFIGS

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


def build_model():
    """Build the LLM model based on current settings."""
    settings = get_settings()
    
    # Get provider-specific configuration
    provider = settings.llm_provider
    api_key = settings.get_active_api_key()
    api_base = settings.get_active_api_base()
    model_id = settings.get_active_model()
    
    # Log provider info for debugging
    provider_name = PROVIDER_CONFIGS.get(provider, {}).get("name", provider)
    print(f"[Agent] Using {provider_name} provider with model: {model_id}")
    
    # OpenRouter requires additional headers for proper attribution
    extra_headers = {}
    if provider == "openrouter":
        extra_headers = {
            "HTTP-Referer": "https://github.com/owasp-helper",
            "X-Title": "OWASP Security Helper",
        }
    
    model = OpenAIServerModel(
        model_id=model_id,
        api_base=api_base,
        api_key=api_key,
        flatten_messages_as_text=True,
        extra_headers=extra_headers if extra_headers else None,
    )
    
    return model


def build_owasp_agent() -> CodeAgent:
    settings = get_settings()
    
    # Build the model using provider-aware configuration
    model = build_model()
    
    # Core OWASP tools
    tools = [
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
        nmap_scan_full,
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
        duckduckgo_search,
        duckduckgo_news,
        google_dork_suggestions,
    ])
    
    # Enhanced SearXNG tools with auto-discovery
    tools.extend([
        searxng_find_instances,
        searxng_metasearch,
        searxng_security_search,
        searxng_dork_search,
    ])
    
    # Enhanced VirusTotal tools
    tools.extend([
        virustotal_subdomains,
        virustotal_domain_analysis,
        virustotal_ip_analysis,
        virustotal_resolutions,
        virustotal_url_scan,
        virustotal_file_hash,
        virustotal_ssl_certificates,
        virustotal_communicating_files,
        virustotal_whois_history,
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
        nuclei_update_templates,
        nuclei_search_templates,
        nuclei_download_template,
        nuclei_list_templates,
        searchsploit_search,
        searchsploit_examine,
        searchsploit_copy,
        list_available_tools,
        sqlmap_scan,
        sqlmap_dump,
        ffuf_scan,
        ffuf_vhost,
        amass_enum,
        amass_intel,
        xsser_scan,
        xsser_fuzzing,
    ])
    
    # Wordlist and brute force tools
    tools.extend([
        get_wordlist,
        list_wordlists,
        hydra_brute_force,
        hydra_ssh_brute,
        hydra_ftp_brute,
        hydra_rdp_brute,
        hydra_mysql_brute,
        hydra_http_form_brute,
        nmap_with_brute,
        check_proxy_status,
    ])
    
    # Advanced bug bounty tools
    tools.extend([
        arjun_scan,
        paramspider_scan,
        jwt_analyze,
        jwt_forge,
        graphql_introspection,
        race_condition_test,
        ssrf_payloads,
        xss_payloads,
        idor_payloads,
    ])
    
    # CVE exploitation tools
    tools.extend([
        vulners_search_cve,
        vulners_search_exploit,
        nvd_lookup,
        run_exploit,
        msfconsole_command,
        exploit_db_search,
        download_exploit,
        cve_to_exploit_workflow,
    ])
    
    # Installation tools
    tools.extend([
        install_python_package,
        install_playwright_browsers,
        install_system_tool,
        install_cloudflared,
        check_and_install_dependencies,
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
        add_screenshot_to_report,
        add_screenshot_to_finding,
        add_tool_output_to_report,
        generate_html_report,
        generate_markdown_report,
        generate_pdf_report,
        # Finding import helpers
        import_zap_alerts_to_findings,
        import_nikto_findings,
        # Recon data collection tools
        add_recon_data,
        add_bulk_scope,
        get_recon_summary,
        add_dns_record,
        add_service_discovery,
        add_technology_stack,
        add_network_topology,
        record_tool_used,
        # Note access tools
        get_note_content,
        list_available_notes,
        insert_note_content_to_report,
        # Note creation/modification tools
        create_note,
        update_note,
        create_note_folder,
        # Project management tools
        create_project,
        add_task_to_project,
        list_projects,
        # Report regeneration tools
        save_pentest_session,
        restore_pentest_session,
        modify_finding,
        remove_finding,
        list_current_findings,
        update_executive_summary,
        update_conclusion,
    ])
    
    # VectorDB-based semantic memory tools
    tools.extend([
        save_to_memory,
        search_memory,
        clear_memory,
        get_memory_status,
    ])
    
    # Telegram integration tools
    tools.extend([
        telegram_connect,
        telegram_set_chat,
        telegram_send_message,
        telegram_send_file,
        telegram_get_updates,
        telegram_status,
        telegram_disconnect,
    ])
    
    # Slack integration tools
    tools.extend([
        slack_connect,
        slack_send_message,
        slack_send_formatted,
        slack_send_alert,
        slack_send_report_summary,
        slack_send_file,
        slack_start_listening,
        slack_stop_listening,
        slack_get_messages,
        slack_status,
        slack_disconnect,
    ])
    
    # OWASP ZAP - Web Application Vulnerability Scanner
    tools.extend([
        zap_start_daemon,
        zap_stop_daemon,
        zap_spider_scan,
        zap_ajax_spider_scan,
        zap_active_scan,
        zap_get_passive_scan_status,
        zap_get_alerts,
        zap_get_urls_with_params,
        zap_full_scan,
        zap_generate_report,
    ])
    
    # Multi-agent delegation tools - for complex task distribution (legacy system)
    tools.extend([
        delegate_reconnaissance,
        delegate_vulnerability_scan,
        delegate_exploitation,
        delegate_report_generation,
        run_parallel_scans,
        get_sub_agent_status,
        get_sub_agent_results,
        create_custom_sub_agent,
    ])
    
    # NEW: Hierarchical Multi-Agent System with shared context
    # This is the recommended approach for comprehensive pentesting
    tools.extend([
        # Project lifecycle
        initialize_pentest_project,
        get_project_status,
        # Shared context - recon data
        submit_recon_data,
        get_recon_data,
        # Shared context - findings
        submit_finding,
        get_pending_findings,
        validate_finding,
        mark_finding_exploited,
        get_validated_findings_for_report,
        # Phase management
        mark_phase_complete,
        # Tool output storage
        save_tool_output,
        # QC notes
        add_qc_note,
        get_agent_activity_log,
        # Report compilation
        compile_final_report,
        review_final_report,
        approve_final_report,
        # Sub-agent dispatchers (for delegating specific phases)
        dispatch_recon_agent,
        dispatch_vuln_scanner_agent,
        dispatch_manual_tester_agent,
        dispatch_exploitation_agent,
        dispatch_qc_agent_review,
        dispatch_reporting_agent,
        dispatch_qc_final_review,
        # Full orchestration (runs complete pentest with all sub-agents)
        run_full_pentest_orchestration,
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
    # max_print_outputs_length limits tool output size to prevent context overflow
    # Most LLMs have 128K-200K context limits, but we need to be conservative
    # Each tool output is limited to ~10K chars to allow for more tool calls
    # max_steps limits iterations to prevent runaway context growth
    # Use configurable max_steps from settings (default 200 for comprehensive pentesting)
    settings = get_settings()
    agent = CodeAgent(
        tools=tools, 
        model=model, 
        instructions=load_prompt_text(),
        max_print_outputs_length=10000,  # Reduced from 20K to prevent context explosion
        max_steps=settings.agent_max_steps,  # Configurable via Settings->General
    )
    return agent
