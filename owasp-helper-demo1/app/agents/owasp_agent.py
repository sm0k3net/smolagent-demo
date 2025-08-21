from __future__ import annotations
from smolagents import CodeAgent, OpenAIServerModel
from app.tools.searxng_tool import searxng_search
from app.tools.owasp_lookup import list_owasp_top10, get_owasp_item
from app.tools.classify import classify_vulnerability
from app.tools.scenarios import generate_test_scenarios
from app.config import get_settings

OWASP_SYSTEM_PROMPT = (
    "You are an OWASP security assistant. You classify vulnerabilities into OWASP Top 10 categories, "
    "explain reasoning, and generate testing scenarios referencing OWASP WSTG / MSTG / API Security Top 10 / ASVS. "
    "When using external search results, cite source URLs if available. Provide actionable, concise answers. "
    "When listing test scenarios, structure them as: Scenario, Objective, Steps, Expected Result, References."
)

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
    )
    tools = [
        searxng_search,
        list_owasp_top10,
        get_owasp_item,
        classify_vulnerability,
        generate_test_scenarios,
    ]
    # Provide instructions to be inserted in the system prompt
    agent = CodeAgent(tools=tools, model=model, instructions=OWASP_SYSTEM_PROMPT)
    return agent
