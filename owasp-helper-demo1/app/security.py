"""Security primitives shared by the HTTP app and persistent file handlers."""
from __future__ import annotations

import base64
import binascii
import hmac
import ipaddress
import os
import re
from pathlib import Path
from typing import Any


def validate_storage_id(value: str) -> str:
    """Return a safe opaque storage identifier or raise ValueError."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
        raise ValueError("Invalid identifier")
    return value


def resolve_allowed_path(value: str | os.PathLike[str], roots: list[Path]) -> Path:
    """Resolve a path and ensure it is a descendant of one of the trusted roots."""
    candidate = Path(value).expanduser().resolve(strict=False)
    for root in roots:
        trusted_root = root.expanduser().resolve(strict=False)
        try:
            candidate.relative_to(trusted_root)
            return candidate
        except ValueError:
            continue
    raise PermissionError("Path is outside the permitted directories")


class LocalOrBasicAuthMiddleware:
    """Require HTTP Basic auth for remote clients; permit loopback-only local use.

    Configure APP_USERNAME and APP_PASSWORD to require credentials for every route
    other than the liveness endpoint. Without credentials, non-loopback requests are
    denied. This is an access-control backstop, not a replacement for a secure proxy.
    """

    def __init__(self, app: Any, username: str | None = None, password: str | None = None):
        self.app = app
        self.username = username if username is not None else os.getenv("APP_USERNAME", "")
        self.password = password if password is not None else os.getenv("APP_PASSWORD", "")
        self.enabled = bool(self.username and self.password)

    def _authorized(self, scope: dict, headers: dict[bytes, bytes]) -> bool:
        if not self.enabled:
            client = scope.get("client")
            if not client:
                return False
            try:
                return ipaddress.ip_address(client[0]).is_loopback
            except ValueError:
                return False
        raw = headers.get(b"authorization", b"")
        try:
            scheme, encoded = raw.decode("ascii").split(" ", 1)
            if scheme.lower() != "basic":
                return False
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
            supplied_user, supplied_password = decoded.split(":", 1)
        except (UnicodeDecodeError, ValueError, binascii.Error):
            return False
        return hmac.compare_digest(supplied_user, self.username) and hmac.compare_digest(supplied_password, self.password)

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if scope["type"] == "http" and path in ("/health", "/api/health"):
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        if self._authorized(scope, headers):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 4401, "reason": "Authentication required"})
            return
        body = b"Authentication required. Configure APP_USERNAME and APP_PASSWORD for remote access."
        await send({"type": "http.response.start", "status": 401, "headers": [(b"www-authenticate", b'Basic realm="OWASP Helper", charset="UTF-8"'), (b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})
