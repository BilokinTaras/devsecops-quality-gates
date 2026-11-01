"""OWASP API2:2023 — Broken Authentication.

Each test asserts the SECURE behaviour. While the stand is vulnerable the test carries a strict xfail with
its FINDING id (`xfail_strict = true` in pyproject): green today, red the moment the behaviour changes in
either direction — fixed upstream, or no longer reproducing.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from .client import ALICE, BOB, CrapiClient
from .jwt_tokens import hs256_with_demo_secret, tampered, unsigned

# Endpoints of the three services that require authentication.
PROTECTED = [
    ("identity", "/identity/api/v2/user/dashboard"),
    ("community", "/community/api/v2/community/posts/recent"),
    ("workshop", "/workshop/api/shop/orders/all"),
]
# A refusal is what matters; crAPI is inconsistent about which status it uses (see OBS-1).
REFUSED = (401, 403, 404)


@pytest.mark.finding("FINDING-001")
@pytest.mark.xfail(reason="FINDING-001: all three services accept a token with alg=none")
@pytest.mark.parametrize(("service", "path"), PROTECTED, ids=[s for s, _ in PROTECTED])
def test_unsigned_token_is_rejected(stand: dict[str, Any], service: str, path: str) -> None:
    """A token with `alg: none` has no signature at all and must never authenticate anyone (CWE-347)."""
    forged = CrapiClient(token=unsigned(BOB.email))
    assert forged.get(path).status_code in REFUSED


@pytest.mark.finding("FINDING-002")
@pytest.mark.xfail(reason="FINDING-002: identity accepts HS256 signed with the published demo secret")
def test_token_signed_with_the_published_demo_secret_is_rejected(stand: dict[str, Any]) -> None:
    """Real tokens are RS256; a HS256 token signed with the service's published secret must not pass."""
    forged = CrapiClient(token=hs256_with_demo_secret(BOB.email))
    assert forged.get("/identity/api/v2/user/dashboard").status_code in REFUSED


@pytest.mark.positive_control
@pytest.mark.parametrize(
    "path", ["/community/api/v2/community/posts/recent", "/workshop/api/shop/orders/all"]
)
def test_community_and_workshop_reject_the_demo_secret(stand: dict[str, Any], path: str) -> None:
    """These two services do check the algorithm and key — the behaviour identity should have."""
    forged = CrapiClient(token=hs256_with_demo_secret(BOB.email))
    assert forged.get(path).status_code in REFUSED


@pytest.mark.finding("FINDING-015")
@pytest.mark.xfail(reason="FINDING-015: identity accepts a genuine token whose payload was edited")
def test_identity_rejects_a_tampered_token(stand: dict[str, Any], anon: CrapiClient) -> None:
    """Editing the payload of a genuine token breaks its signature, so it must stop working."""
    forged = CrapiClient(token=tampered(anon.login(ALICE)))
    assert forged.get("/identity/api/v2/user/dashboard").status_code in REFUSED


@pytest.mark.positive_control
@pytest.mark.parametrize("path", [path for service, path in PROTECTED if service != "identity"])
def test_community_and_workshop_reject_a_tampered_token(
    stand: dict[str, Any], anon: CrapiClient, path: str
) -> None:
    forged = CrapiClient(token=tampered(anon.login(ALICE)))
    assert forged.get(path).status_code in REFUSED


@pytest.mark.positive_control
def test_anonymous_access_to_protected_endpoints_is_rejected(
    stand: dict[str, Any], anon: CrapiClient
) -> None:
    """Identity answers 404 rather than 401 here (recorded as OBS-1), which still refuses the request."""
    for _, path in PROTECTED:
        assert anon.get(path).status_code in REFUSED, path


@pytest.mark.finding("FINDING-012")
@pytest.mark.xfail(reason="FINDING-012: /auth/v2/check-otp accepts unlimited attempts")
def test_otp_check_is_rate_limited(stand: dict[str, Any], anon: CrapiClient) -> None:
    """A 4-digit OTP is brute-forceable unless the endpoint limits attempts (CWE-307).

    Volume: at most 20 attempts against an account this suite created (rules of engagement, guardrail 4).
    """
    anon.post("/identity/api/auth/forget-password", json={"email": ALICE.email})
    statuses = []
    for attempt in range(20):
        res = anon.post(
            "/identity/api/auth/v2/check-otp",
            json={"email": ALICE.email, "otp": f"{attempt:04d}", "password": ALICE.password},
        )
        statuses.append(res.status_code)
        if res.status_code == 503:
            break
    assert 503 in statuses, f"20 wrong OTPs accepted without throttling: {sorted(set(statuses))}"


@pytest.mark.positive_control
def test_otp_v3_is_rate_limited(stand: dict[str, Any], anon: CrapiClient) -> None:
    """v3 of the same endpoint blocks after a handful of attempts — the fixed version."""
    anon.post("/identity/api/auth/forget-password", json={"email": ALICE.email})
    statuses = []
    for attempt in range(20):
        res = anon.post(
            "/identity/api/auth/v3/check-otp",
            json={"email": ALICE.email, "otp": f"{attempt:04d}", "password": ALICE.password},
        )
        statuses.append(res.status_code)
        if res.status_code == 503:
            break
        time.sleep(0.05)
    assert 503 in statuses, f"v3 did not throttle either: {sorted(set(statuses))}"
    assert len(statuses) <= 15, f"v3 throttled only after {len(statuses)} attempts"
