from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx


DEFAULT_PENDOC_BASE_URL = "https://hterhcgaayxxebhvsjnp.supabase.co/functions/v1/api"


def _settings_file_path() -> Path:
    # Stored alongside other app-level settings files in app/ (like .api_keys.json)
    return Path(__file__).resolve().parent.parent / ".pendoc_settings.json"


def load_pendoc_settings() -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "enabled": False,
        "auto_submit": False,
        "base_url": DEFAULT_PENDOC_BASE_URL,
        "project_id": "",
        "folder_id": "",
    }

    p = _settings_file_path()
    if not p.exists():
        return defaults

    try:
        loaded = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            defaults.update({k: v for k, v in loaded.items() if v is not None})
    except Exception:
        return defaults

    return defaults


def save_pendoc_settings(settings: dict[str, Any]) -> None:
    p = _settings_file_path()
    p.write_text(json.dumps(settings, indent=2), encoding="utf-8")


def get_pendoc_api_token() -> str | None:
    # Stored in app's API key store and mirrored into env var by main.py.
    tok = os.getenv("PENDOC_API_TOKEN")
    return tok.strip() if tok and tok.strip() else None


@dataclass
class PenDocConfig:
    enabled: bool
    auto_submit: bool
    base_url: str
    api_token: str
    project_id: str
    folder_id: str | None = None


def get_pendoc_config() -> tuple[Optional[PenDocConfig], Optional[str]]:
    s = load_pendoc_settings()
    token = get_pendoc_api_token()
    if not token:
        return None, "PenDoc API token not configured. Set PENDOC_API_TOKEN in Settings → General."

    base_url = (s.get("base_url") or DEFAULT_PENDOC_BASE_URL).strip()
    if not base_url:
        base_url = DEFAULT_PENDOC_BASE_URL

    project_id = (s.get("project_id") or "").strip()

    return (
        PenDocConfig(
            enabled=bool(s.get("enabled", False)),
            auto_submit=bool(s.get("auto_submit", False)),
            base_url=base_url.rstrip("/"),
            api_token=token,
            project_id=project_id,
            folder_id=(s.get("folder_id") or "").strip() or None,
        ),
        None,
    )


def _pendoc_client(cfg: PenDocConfig) -> httpx.Client:
    return httpx.Client(
        base_url=cfg.base_url,
        headers={
            "x-api-token": cfg.api_token,
            "Content-Type": "application/json",
        },
        timeout=30.0,
    )


def pendoc_test_connection(base_url: str | None = None, api_token: str | None = None) -> tuple[bool, str, dict[str, Any] | None]:
    token = (api_token or "").strip() or get_pendoc_api_token()
    if not token:
        return False, "Missing API token", None

    url = (base_url or load_pendoc_settings().get("base_url") or DEFAULT_PENDOC_BASE_URL).rstrip("/")

    try:
        with httpx.Client(
            base_url=url,
            headers={"x-api-token": token, "Content-Type": "application/json"},
            timeout=15.0,
        ) as c:
            r = c.get("/profile")
            r.raise_for_status()
            data = r.json()
            if isinstance(data, dict) and isinstance(data.get("profile"), dict):
                return True, "Connected", data.get("profile")
            return True, "Connected", data if isinstance(data, dict) else {"raw": data}
    except Exception as e:
        return False, f"Connection failed: {e}", None


def pendoc_list_projects(cfg: PenDocConfig) -> tuple[bool, str, list[dict[str, Any]]]:
    try:
        with _pendoc_client(cfg) as c:
            r = c.get("/projects")
            r.raise_for_status()
            data = r.json()
            projects = data.get("projects") if isinstance(data, dict) else None
            if not isinstance(projects, list):
                return False, "Unexpected response from /projects", []
            return True, "OK", projects
    except Exception as e:
        return False, f"Failed to list projects: {e}", []


def pendoc_create_file(
    cfg: PenDocConfig,
    *,
    project_id: str,
    name: str,
    content: str,
    file_type: str = "note",
    mime_type: str | None = None,
    folder_id: str | None = None,
) -> tuple[bool, str, dict[str, Any] | None]:
    payload: dict[str, Any] = {
        "project_id": project_id,
        "name": name,
        "content": content,
        "file_type": file_type,
    }
    if mime_type:
        payload["mime_type"] = mime_type
    if folder_id:
        payload["folder_id"] = folder_id

    try:
        with _pendoc_client(cfg) as c:
            r = c.post("/files", json=payload)
            r.raise_for_status()
            data = r.json()
            if isinstance(data, dict) and isinstance(data.get("file"), dict):
                return True, "Created", data.get("file")
            return True, "Created", data if isinstance(data, dict) else {"raw": data}
    except Exception as e:
        return False, f"Failed to create file: {e}", None


def pendoc_create_vulnerability(cfg: PenDocConfig, payload: dict[str, Any]) -> tuple[bool, str, dict[str, Any] | None]:
    try:
        with _pendoc_client(cfg) as c:
            r = c.post("/vulnerabilities", json=payload)
            r.raise_for_status()
            data = r.json()
            if isinstance(data, dict) and isinstance(data.get("vulnerability"), dict):
                return True, "Created", data.get("vulnerability")
            return True, "Created", data if isinstance(data, dict) else {"raw": data}
    except Exception as e:
        return False, f"Failed to create vulnerability: {e}", None


def pendoc_create_folder(
    cfg: PenDocConfig,
    *,
    project_id: str,
    name: str,
    parent_id: str | None = None,
) -> tuple[bool, str, dict[str, Any] | None]:
    payload: dict[str, Any] = {
        "project_id": project_id,
        "name": name,
    }
    if parent_id:
        payload["parent_id"] = parent_id

    try:
        with _pendoc_client(cfg) as c:
            r = c.post("/folders", json=payload)
            r.raise_for_status()
            data = r.json()
            if isinstance(data, dict) and isinstance(data.get("folder"), dict):
                return True, "Created", data.get("folder")
            return True, "Created", data if isinstance(data, dict) else {"raw": data}
    except Exception as e:
        return False, f"Failed to create folder: {e}", None


def pendoc_list_project_folders(cfg: PenDocConfig, project_id: str) -> tuple[bool, str, list[dict[str, Any]]]:
    try:
        with _pendoc_client(cfg) as c:
            r = c.get(f"/projects/{project_id}/folders")
            r.raise_for_status()
            data = r.json()
            folders = data.get("folders") if isinstance(data, dict) else None
            if not isinstance(folders, list):
                return False, "Unexpected response from /projects/{id}/folders", []
            return True, "OK", folders
    except Exception as e:
        return False, f"Failed to list folders: {e}", []


def pendoc_add_vulnerability_comment(
    cfg: PenDocConfig,
    *,
    vulnerability_id: str,
    content: str,
    comment_type: str = "annotation",
    parent_id: str | None = None,
) -> tuple[bool, str, dict[str, Any] | None]:
    payload: dict[str, Any] = {
        "content": content,
        "comment_type": comment_type,
    }
    if parent_id:
        payload["parent_id"] = parent_id

    try:
        with _pendoc_client(cfg) as c:
            r = c.post(f"/vulnerabilities/{vulnerability_id}/comments", json=payload)
            r.raise_for_status()
            data = r.json()
            if isinstance(data, dict) and isinstance(data.get("comment"), dict):
                return True, "Created", data.get("comment")
            return True, "Created", data if isinstance(data, dict) else {"raw": data}
    except Exception as e:
        return False, f"Failed to create comment: {e}", None
