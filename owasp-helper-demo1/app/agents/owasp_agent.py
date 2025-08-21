from __future__ import annotations
from smolagents import CodeAgent
from app.tools.searxng_tool import searxng_search
from app.tools.owasp_lookup import list_owasp_top10, get_owasp_item
from app.tools.classify import classify_vulnerability
from app.tools.scenarios import generate_test_scenarios
from app.agents.deepseek_model import DeepSeekChatModel

OWASP_SYSTEM_PROMPT = (
    "You are an OWASP security assistant. You classify vulnerabilities into OWASP Top 10 categories, "
    "explain reasoning, and generate testing scenarios referencing OWASP WSTG / MSTG / API Security Top 10 / ASVS. "
    "When using external search results, cite source URLs if available. Provide actionable, concise answers. "
    "When listing test scenarios, structure them as: Scenario, Objective, Steps, Expected Result, References."
)

def build_owasp_agent() -> CodeAgent:
    model = DeepSeekChatModel()
    tools = [
        searxng_search,
        list_owasp_top10,
        get_owasp_item,
        classify_vulnerability,
        generate_test_scenarios,
    ]
    # Current smolagents version does not accept system_prompt kw; inject manually per run.
    agent = CodeAgent(tools=tools, model=model)
    return agent

def format_owasp_query(user_query: str) -> str:
    """Prepend OWASP system instructions to user query for models without native system prompt support."""
    return f"{OWASP_SYSTEM_PROMPT}\n\nUser Query:\n{user_query}" 
