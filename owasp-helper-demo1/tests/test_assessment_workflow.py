from __future__ import annotations

import sys
import types
from datetime import datetime

from app.agents import multi_agent_system as mas
from app.tools.header_analysis import analyze_http_security_headers
from app.tools.scenarios import generate_test_scenarios


def test_scenario_generator_accepts_all_categories_and_count_bounds() -> None:
    for category in (f"A{i:02d}:2021" for i in range(1, 11)):
        assert category in generate_test_scenarios(category, 1)
    assert generate_test_scenarios(" a03:2021 ", 5).count("Scenario:") == 5


def test_scenario_generator_rejects_unknown_categories_and_invalid_counts() -> None:
    assert "Invalid OWASP category" in generate_test_scenarios("A11:2021", 2)
    for count in (0, 6, -1, True, 1.5):
        assert "Invalid scenario count" in generate_test_scenarios("A01:2021", count)


def test_scenarios_require_scope_and_non_destructive_evidence() -> None:
    result = generate_test_scenarios("A01:2021", 1).lower()
    assert "written authorization" in result
    assert "synthetic data" in result
    assert "do not access other users' data" in result
    assert "record the request" in result


def test_header_analysis_is_offline_and_identifies_common_gaps() -> None:
    result = analyze_http_security_headers("https://example.test", '{"Server":"example"}')
    assert "Strict-Transport-Security is absent" in result
    assert "Content-Security-Policy is absent" in result
    assert "no network request was made" in result


def test_header_analysis_handles_complete_policy_and_cors_observations() -> None:
    complete = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
    }
    result = analyze_http_security_headers("https://example.test", __import__("json").dumps(complete))
    assert "No checked gaps were observed" in result
    wildcard = analyze_http_security_headers(
        "https://example.test",
        '{"Access-Control-Allow-Origin":"*","Access-Control-Allow-Credentials":"true"}',
    )
    assert "[Info] CORS combines wildcard origin" in wildcard
    assert "Browsers reject this combination" in wildcard


def test_header_analysis_rejects_malformed_and_oversized_input() -> None:
    assert "Invalid input" in analyze_http_security_headers("file:///etc/passwd", "{}")
    assert "Invalid input" in analyze_http_security_headers("https://example.test", "[]")
    assert "32 KB or smaller" in analyze_http_security_headers("https://example.test", " " * 32769)
    assert "do not include credentials" in analyze_http_security_headers("https://user:secret@example.test", "{}")
    rendered = analyze_http_security_headers("https://<img>.example.test", "{}")
    assert "&lt;img&gt;.example.test" in rendered


def _valid_finding(**changes: object) -> mas.SharedFinding:
    fields = dict(
        id="FIND-TEST0001",
        title="Missing access control",
        severity="High",
        description="The endpoint does not enforce the documented access policy.",
        evidence="A controlled request using the test account returned the protected test record.",
        affected_component="https://example.test/api/test-record",
        discovered_by="manual_tester",
        discovered_at=datetime.now(),
        remediation="Enforce authorization on the server for every request.",
        status=mas.FindingStatus.VALIDATED,
    )
    fields.update(changes)
    return mas.SharedFinding(**fields)


def test_report_completeness_does_not_require_exploitation_or_screenshots() -> None:
    finding = _valid_finding()
    assert not finding.exploited
    assert finding.screenshots == []
    assert mas._finding_completeness_issues(finding) == []


def test_report_completeness_requires_core_fields() -> None:
    finding = _valid_finding(evidence="", remediation="", severity="urgent")
    issues = mas._finding_completeness_issues(finding)
    assert any("missing evidence" in issue for issue in issues)
    assert any("missing remediation" in issue for issue in issues)
    assert any("invalid severity" in issue for issue in issues)


def test_final_review_tracks_included_findings_and_allows_unexploited_findings(monkeypatch) -> None:
    ctx = mas.SharedContext(
        phases_completed={
            "reconnaissance": True,
            "vulnerability_scanning": True,
            "quality_control_review": True,
        },
        findings=[_valid_finding()],
        report_generated=True,
        report_finding_ids=["FIND-TEST0001"],
    )
    monkeypatch.setattr(mas, "get_shared_context", lambda: ctx)
    result = mas.review_final_report()
    assert "PASSED" in result
    assert ctx.report_reviewed is True


def test_final_review_finds_unincluded_validated_finding(monkeypatch) -> None:
    ctx = mas.SharedContext(
        phases_completed={
            "reconnaissance": True,
            "vulnerability_scanning": True,
            "quality_control_review": True,
        },
        findings=[_valid_finding()],
        report_generated=True,
        report_finding_ids=[],
    )
    monkeypatch.setattr(mas, "get_shared_context", lambda: ctx)
    result = mas.review_final_report()
    assert "missing from report" in result
    assert ctx.report_reviewed is False


def test_report_approval_requires_successful_review(monkeypatch) -> None:
    ctx = mas.SharedContext(report_generated=True, report_reviewed=False)
    monkeypatch.setattr(mas, "get_shared_context", lambda: ctx)
    assert "successful review_final_report() is required" in mas.approve_final_report()
    assert ctx.report_reviewed is False


def test_focused_report_needs_qc_but_not_exhaustive_phase_flags(monkeypatch) -> None:
    ctx = mas.SharedContext(
        target="https://example.test",
        phases_completed={"quality_control_review": True},
        findings=[_valid_finding(tool_used="", discovered_by="manual_tester")],
        tool_outputs={"test": "sensitive raw output must not be auto-included"},
    )
    monkeypatch.setattr(mas, "get_shared_context", lambda: ctx)
    report_module = types.ModuleType("app.tools.report_tools")
    imported_findings: list[dict[str, object]] = []
    report_module.enable_report_mode = lambda *args: None
    report_module.add_finding_to_report = lambda **kwargs: imported_findings.append(kwargs)
    report_module.set_executive_summary = lambda *args: None
    report_module.set_conclusion = lambda *args: None
    report_module.generate_html_report = lambda: "Report generated"
    report_module.add_recon_data = lambda *args: None
    monkeypatch.setitem(sys.modules, "app.tools.report_tools", report_module)

    result = mas.compile_final_report()

    assert "Status: Ready for QC final review" in result
    assert len(imported_findings) == 1
    assert imported_findings[0]["tool_used"] == ""
    assert ctx.report_finding_ids == ["FIND-TEST0001"]
