from __future__ import annotations
from smolagents import CodeAgent, OpenAIServerModel
from app.tools.searxng_tool import searxng_search
from app.tools.owasp_lookup import list_owasp_top10, get_owasp_item
from app.tools.classify import classify_vulnerability
from app.tools.scenarios import generate_test_scenarios
from app.tools.playwright_tool import fetch_page_title
from app.tools.nmap_tool import nmap_scan
from app.tools.curl_tool import curl_request
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
from app.config import get_settings
from pathlib import Path

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
    tools = [
        searxng_search,
        list_owasp_top10,
        get_owasp_item,
        classify_vulnerability,
    generate_test_scenarios,
    fetch_page_title,
    nmap_scan,
    curl_request,
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
    ]
    # Provide instructions from prompt file
    agent = CodeAgent(tools=tools, model=model, instructions=load_prompt_text())
    return agent
