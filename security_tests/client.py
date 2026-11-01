"""HTTP client for the local crAPI stand.

Every request in this repository goes through `CrapiClient`, which refuses any base URL that is not a
loopback address or a container on the stand's Docker network (rules of engagement, guardrail 2).
"""

from __future__ import annotations

import ipaddress
import os
import quopri
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

# Hostnames that exist only inside the qa-crapi Docker network.
_STAND_HOSTS = {"localhost", "crapi-web", "mailhog", "canary"}

CRAPI_URL = os.environ.get("CRAPI_URL", "http://127.0.0.1:8888")
MAILHOG_URL = os.environ.get("MAILHOG_URL", "http://127.0.0.1:8025")
# SSRF destination as seen from inside the stand (the canary container), never an external host.
CANARY_URL = os.environ.get("CANARY_URL", "http://canary:8080")


class OutOfScopeError(RuntimeError):
    """A request would leave the local stand."""


def ensure_local(url: str) -> str:
    host = urlsplit(url).hostname or ""
    if host in _STAND_HOSTS:
        return url
    try:
        if ipaddress.ip_address(host).is_loopback:
            return url
    except ValueError:
        pass
    raise OutOfScopeError(f"{url} is not the local stand (allowed: loopback, {sorted(_STAND_HOSTS)})")


@dataclass(frozen=True)
class User:
    """A test user created by the seed. Credentials are test-only values for the local stand."""

    name: str
    email: str
    number: str
    password: str


ALICE = User("QA Alice", "qa-alice@example.com", "9000000001", "QaAlice#2026")
BOB = User("QA Bob", "qa-bob@example.com", "9000000002", "QaBob#2026")


class CrapiClient:
    def __init__(self, base_url: str = CRAPI_URL, token: str | None = None, timeout: float = 30.0) -> None:
        self.base_url = ensure_local(base_url).rstrip("/")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.http = httpx.Client(base_url=self.base_url, headers=headers, timeout=timeout)

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        return self.http.request(method, path, **kwargs)

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("DELETE", path, **kwargs)

    # --- identity -----------------------------------------------------------------------------
    def signup(self, user: User) -> httpx.Response:
        body = {"name": user.name, "email": user.email, "number": user.number, "password": user.password}
        return self.post("/identity/api/auth/signup", json=body)

    def login(self, user: User) -> str:
        res = self.post("/identity/api/auth/login", json={"email": user.email, "password": user.password})
        res.raise_for_status()
        return str(res.json()["token"])

    def as_user(self, user: User) -> CrapiClient:
        return CrapiClient(self.base_url, token=self.login(user))


def latest_mail(to: str, subject_contains: str = "", timeout: float = 20.0) -> str:
    """Plain text of the newest MailHog message to `to` (HTML tags stripped, quoted-printable decoded)."""
    deadline = time.monotonic() + timeout
    with httpx.Client(base_url=ensure_local(MAILHOG_URL), timeout=10.0) as mh:
        while True:
            items = mh.get("/api/v2/search", params={"kind": "to", "query": to}).json().get("items") or []
            for item in items:  # newest first
                subject = " ".join(item["Content"]["Headers"].get("Subject", []))
                if subject_contains in subject:
                    raw: str = item["Raw"]["Data"]
                    body = raw.split("\r\n\r\n", 1)[-1]
                    text = quopri.decodestring(body.encode()).decode("utf-8", "ignore")
                    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text))
            if time.monotonic() > deadline:
                raise TimeoutError(f"no mail to {to} with subject containing {subject_contains!r}")
            time.sleep(0.5)
