"""Forged JWTs for authentication tests. They are built here instead of taken from a library so the
test says exactly what is wrong with each token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

# crAPI's identity service ships this value as JWT_SECRET in the release compose; it is public.
CRAPI_DEMO_SECRET = b"crapi"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _part(obj: dict[str, Any]) -> str:
    return _b64(json.dumps(obj, separators=(",", ":")).encode())


def claims(email: str, role: str = "user", ttl_days: int = 7) -> dict[str, Any]:
    issued = 1793000000
    return {"sub": email, "role": role, "iat": issued, "exp": issued + ttl_days * 86400}


def unsigned(email: str) -> str:
    """`alg: none` with an empty signature — the classic signature-stripping token."""
    return f"{_part({'alg': 'none', 'typ': 'JWT'})}.{_part(claims(email))}."


def hs256_with_demo_secret(email: str) -> str:
    """Signed with the service's published demo secret, while the real tokens are RS256."""
    body = f"{_part({'alg': 'HS256', 'typ': 'JWT'})}.{_part(claims(email))}"
    return f"{body}.{_b64(hmac.new(CRAPI_DEMO_SECRET, body.encode(), hashlib.sha256).digest())}"


def tampered(token: str) -> str:
    """A genuine token whose payload was edited, so the signature no longer matches."""
    header, payload, signature = token.split(".")
    body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    body["role"] = "admin"
    return f"{header}.{_part(body)}.{signature}"
