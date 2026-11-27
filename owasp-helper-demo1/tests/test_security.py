from __future__ import annotations

import base64
from pathlib import Path

import pytest

from app.security import (
    LocalOrBasicAuthMiddleware,
    resolve_allowed_path,
    validate_storage_id,
)


def test_storage_id_rejects_traversal_and_accepts_opaque_ids() -> None:
    assert validate_storage_id("task_ABC-123") == "task_ABC-123"
    for value in ("../secret", "a/b", "", "a" * 129):
        with pytest.raises(ValueError):
            validate_storage_id(value)


def test_resolve_allowed_path_uses_path_boundaries(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    sibling = tmp_path / "reports-escape" / "secret.txt"
    sibling.parent.mkdir()
    sibling.write_text("secret")
    assert resolve_allowed_path(reports / "ok.txt", [reports]) == (reports / "ok.txt").resolve()
    with pytest.raises(PermissionError):
        resolve_allowed_path(sibling, [reports])
    with pytest.raises(PermissionError):
        resolve_allowed_path(reports / ".." / "reports-escape" / "secret.txt", [reports])


def test_auth_middleware_requires_remote_basic_auth() -> None:
    middleware = LocalOrBasicAuthMiddleware(lambda *_: None, username="operator", password="a-long-test-password")
    good = base64.b64encode(b"operator:a-long-test-password").decode()
    assert middleware._authorized({"client": ("203.0.113.5", 1234)}, {b"authorization": f"Basic {good}".encode()})
    assert not middleware._authorized({"client": ("203.0.113.5", 1234)}, {})
    assert not middleware._authorized({"client": ("203.0.113.5", 1234)}, {b"authorization": b"Basic invalid"})


def test_auth_middleware_without_credentials_is_loopback_only() -> None:
    middleware = LocalOrBasicAuthMiddleware(lambda *_: None, username="", password="")
    assert middleware._authorized({"client": ("127.0.0.1", 8000)}, {})
    assert middleware._authorized({"client": ("::1", 8000)}, {})
    assert not middleware._authorized({"client": ("203.0.113.5", 8000)}, {})
    assert not middleware._authorized({}, {})


def test_note_markdown_escapes_html_and_blocks_script_links() -> None:
    from app.tools.report_tools import _markdown_to_html

    rendered = _markdown_to_html('<script>alert(1)</script>\n[x](javascript:alert(1))\n[y](https://example.org)')
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert 'href="javascript:' not in rendered
    assert 'href="https://example.org"' in rendered


def test_task_persistence_rejects_traversal(tmp_path: Path) -> None:
    from app.task_persistence import TaskPersistenceManager

    manager = TaskPersistenceManager(str(tmp_path / "tasks"))
    assert manager._get_task_file("task_123").parent == (tmp_path / "tasks")
    with pytest.raises(ValueError):
        manager._get_task_file("../../outside")
    manager.stop_auto_save()


def test_report_screenshots_require_bounded_png_data() -> None:
    import base64

    from app.tools.report_tools import _safe_png_data

    png = b"\x89PNG\r\n\x1a\n" + b"valid-test-payload"
    encoded = base64.b64encode(png).decode("ascii")
    assert _safe_png_data(encoded) == encoded
    assert _safe_png_data('" onerror="alert(1)') is None
    assert _safe_png_data(base64.b64encode(b"not a png").decode()) is None
    assert _safe_png_data("A" * 7_000_001) is None
