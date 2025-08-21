from __future__ import annotations
from smolagents import tool

_TEMPLATE = """Scenario: {title}\nObjective: {objective}\nSteps:\n{steps}\nExpected Result: {expected}\nReferences: {refs}\n"""

@tool
def generate_test_scenarios(owasp_id: str, count: int = 3) -> str:
    """Generate high-level security testing scenarios for a given OWASP Top 10 2021 item.

    Args:
        owasp_id: e.g. A01:2021
        count: number of scenarios (max 5)
    """
    normative_refs = {
        "A01:2021": ["WSTG-ATHN-02", "ASVS 4.0 V4", "OWASP Cheat Sheet: Access Control"],
        "A02:2021": ["WSTG-CRYP-01", "ASVS 4.0 V7", "Cheat Sheet: Cryptographic Storage"],
        "A03:2021": ["WSTG-INPV-05", "ASVS 4.0 V5", "Cheat Sheet: Injection Prevention"],
        "A05:2021": ["WSTG-CONF-02", "ASVS 4.0 V1", "Cheat Sheet: Secure Headers"],
        "A10:2021": ["WSTG-INFO-09", "ASVS 4.0 V14", "Cheat Sheet: SSRF Prevention"],
    }
    base = owasp_id.upper()
    refs = normative_refs.get(base, ["OWASP WSTG", "ASVS", "Cheat Sheets"])
    scenarios = []
    for i in range(1, min(count, 5) + 1):
        scenarios.append(_TEMPLATE.format(
            title=f"{base} Test #{i}",
            objective=f"Assess presence of {base} weaknesses",
            steps="- Define scope\n- Craft inputs / conditions\n- Observe responses / side-effects\n- Document evidence",
            expected="Vulnerability not exploitable; controls enforce policy.",
            refs=", ".join(refs)
        ))
    return "\n".join(scenarios)
