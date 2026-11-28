from __future__ import annotations

from smolagents import tool

from app.knowledge.owasp_top10_2021 import OWASP_TOP10_2021

_TEMPLATE = """Scenario: {title}\nObjective: {objective}\nSteps:\n{steps}\nExpected Result: {expected}\nReferences: {refs}\n"""
_NORMATIVE_REFS = {
    "A01:2021": ["WSTG-ATHZ", "ASVS 4.0 V4", "OWASP Cheat Sheet: Access Control"],
    "A02:2021": ["WSTG-CRYP", "ASVS 4.0 V6", "Cheat Sheet: Cryptographic Storage"],
    "A03:2021": ["WSTG-INPV-05", "ASVS 4.0 V5", "Cheat Sheet: Injection Prevention"],
    "A05:2021": ["WSTG-CONF", "ASVS 4.0 V14", "Cheat Sheet: Secure Headers"],
    "A10:2021": ["WSTG-INPV", "Cheat Sheet: SSRF Prevention"],
}
_CATEGORIES = {str(item["id"]).upper(): item for item in OWASP_TOP10_2021}


@tool
def generate_test_scenarios(owasp_id: str, count: int = 3) -> str:
    """Generate scoped, non-destructive test plans for OWASP Top 10 2021.

    Args:
        owasp_id: Valid category ID such as A01:2021.
        count: Number of scenarios to generate (1 through 5).
    Returns:
        Scenario plans requiring authorization, safe test data, and evidence recording.
    """
    if not isinstance(owasp_id, str):
        return "Invalid OWASP category. Use an ID from A01:2021 through A10:2021."
    category_id = owasp_id.strip().upper()
    category = _CATEGORIES.get(category_id)
    if category is None:
        return "Invalid OWASP category. Use an ID from A01:2021 through A10:2021."
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 5:
        return "Invalid scenario count. Choose an integer from 1 through 5."

    category_name = category.get("name", category_id)
    refs = _NORMATIVE_REFS.get(category_id, ["OWASP WSTG", "ASVS", "OWASP Cheat Sheets"])
    scenarios = []
    for i in range(1, count + 1):
        scenarios.append(_TEMPLATE.format(
            title=f"{category_id} Test #{i}: {category_name}",
            objective=f"Assess the authorized application's controls related to {category_name}.",
            steps=(
                "- Confirm written authorization, in-scope assets, test window, and prohibited actions.\n"
                "- Select a representative endpoint and use a test account or synthetic data.\n"
                "- Make one controlled request at a time; do not access other users' data, persist changes, or cause load.\n"
                "- Compare the response with the documented expected access/control behavior.\n"
                "- Record the request, redacted response, timestamp, and relevant tool/output; stop if unexpected impact occurs."
            ),
            expected="Controls behave as intended; record a suspected issue for review without escalating access or impact.",
            refs=", ".join(refs),
        ))
    return "\n".join(scenarios)
