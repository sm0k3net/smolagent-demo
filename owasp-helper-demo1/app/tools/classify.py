from __future__ import annotations
import re
from smolagents import tool
from app.knowledge.owasp_top10_2021 import OWASP_TOP10_2021

# Naive keyword hints (seed; improve with data-driven approach later)
_KEYWORDS = {
    "A01:2021": ["access control", "unauthorized", "idOR", "insecure direct object", "privilege escalation", "bypass"],
    "A02:2021": ["encryption", "plaintext", "crypto", "cipher", "ssl", "tls", "hash", "md5", "sha1", "secret"],
    "A03:2021": ["sql", "injection", "sqli", "os command", "ldap", "xpath", "nosql", "eval(", "deserialize"],
    "A04:2021": ["design", "threat modeling", "architect", "abuse case", "missing control"],
    "A05:2021": ["default", "misconfiguration", "directory listing", "verbose error", "cors", "cloud bucket", ".env"],
    "A06:2021": ["outdated", "cve-", "deprecated", "unpatched", "library version"],
    "A07:2021": ["authentication", "session", "jwt", "password", "2fa", "mfa", "captcha", "credential"],
    "A08:2021": ["integrity", "supply chain", "unsigned", "ci/cd", "dependency confusion", "artifact"],
    "A09:2021": ["log", "monitor", "siem", "alert", "detection"],
    "A10:2021": ["ssrf", "server-side request", "internal http", "169.254.169.254", "metadata service"],
}
_INDEX = {i["id"]: i for i in OWASP_TOP10_2021}

@tool
def classify_vulnerability(description: str) -> str:
    """Classify a vulnerability description into the most likely OWASP Top 10 2021 category using heuristic keyword scoring and return ranked candidates with rationale.

    Args:
        description: Free-text vulnerability description.
    """
    text = description.lower()
    scores: dict[str, int] = {}
    for cat, words in _KEYWORDS.items():
        score = 0
        for w in words:
            if re.search(r"\b" + re.escape(w.lower()) + r"\b", text):
                score += 3
        # frequency of generic tokens
        for w in words:
            score += text.count(w.lower())
        if score:
            scores[cat] = score
    if not scores:
        return "No strong keyword match. Consider: Insecure Design (A04:2021) or further manual analysis."
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    lines = ["Ranked OWASP Top 10 candidates:"]
    for cat, sc in ranked[:5]:
        meta = _INDEX[cat]
        lines.append(f"{cat} {meta['name']} score={sc} -> {meta['description']}")
    lines.append("Heuristic only. Ask the agent for deeper reasoning if needed.")
    return "\n".join(lines)
