"""Injection (CWE-89, CWE-943), SSRF (OWASP API7:2023) and excessive data exposure (API3:2023)."""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from .client import ALICE, BOB, CANARY_URL, CrapiClient


def canary(path: str) -> dict[str, Any]:
    """Talks to the canary from inside the stand's network; it is never published to the host."""
    code = (
        f"import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080{path}').read().decode())"
    )
    out = subprocess.run(  # noqa: S603 - fixed argument list, container of this stand
        ["docker", "exec", "qa-crapi-canary-1", "python", "-c", code],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    )
    return dict(json.loads(out.stdout))


@pytest.mark.finding("FINDING-003")
@pytest.mark.xfail(reason="FINDING-003: coupon_code is concatenated into a SQL statement")
def test_coupon_code_is_not_concatenated_into_sql(stand: dict[str, Any], alice: CrapiClient) -> None:
    """Reads another user's phone number out of `user_login` through the coupon parameter (CWE-89)."""
    payload = "'; SELECT number FROM user_login WHERE email='" + BOB.email  # noqa: S608 - attack payload, not a query
    res = alice.post("/workshop/api/shop/apply_coupon", json={"coupon_code": payload, "amount": 75})
    assert stand["users"]["bob"]["phone"] not in res.text, (
        "another user's phone number came back in the message"
    )


@pytest.mark.positive_control
def test_unknown_coupon_is_rejected(stand: dict[str, Any], alice: CrapiClient) -> None:
    res = alice.post(
        "/workshop/api/shop/apply_coupon", json={"coupon_code": "QA-NO-SUCH-COUPON", "amount": 10}
    )
    assert res.status_code == 400


@pytest.mark.finding("FINDING-004")
@pytest.mark.xfail(reason="FINDING-004: a Mongo operator in coupon_code returns a valid coupon")
@pytest.mark.parametrize("operator", [{"$ne": "zzz"}, {"$gt": ""}])
def test_coupon_validation_rejects_mongo_operators(
    stand: dict[str, Any], alice: CrapiClient, operator: dict[str, str]
) -> None:
    """A JSON object where a string is expected must not become part of the query (CWE-943)."""
    res = alice.post("/community/api/v2/coupon/validate-coupon", json={"coupon_code": operator})
    assert res.status_code != 200 or "coupon_code" not in res.text


@pytest.mark.finding("FINDING-005")
@pytest.mark.xfail(reason="FINDING-005: contact_mechanic fetches any URL the caller supplies")
def test_contact_mechanic_does_not_fetch_a_caller_supplied_url(
    stand: dict[str, Any], alice: CrapiClient
) -> None:
    """Server-side request forgery; the only destination used here is the stand's canary (CWE-918)."""
    canary("/__reset")
    alice.post(
        "/workshop/api/merchant/contact_mechanic",
        json={
            "mechanic_api": f"{CANARY_URL}/ssrf-regression",
            "mechanic_code": "TRAC_JHN",
            "number_of_repeats": 1,
            "repeat_request_if_failed": False,
            "problem_details": "regression test",
            "vin": stand["users"]["alice"]["vehicle"]["vin"],
        },
    )
    hits = [r for r in canary("/__requests")["requests"] if "ssrf-regression" in r["path"]]
    assert not hits, f"the server fetched the supplied URL: {hits}"


@pytest.mark.finding("FINDING-011")
@pytest.mark.xfail(reason="FINDING-011: community posts expose other users' e-mail and vehicle id")
def test_community_posts_do_not_expose_personal_data(stand: dict[str, Any], alice: CrapiClient) -> None:
    """A public feed needs a display name, not an e-mail address and a vehicle identifier (CWE-213)."""
    posts = alice.get("/community/api/v2/community/posts/recent").json()["posts"]
    others = [p for p in posts if p["author"]["email"] != ALICE.email]
    assert others, "seed should have created a post by another user"
    leaked = [
        p["author"]["email"] for p in others if p["author"].get("email") or p["author"].get("vehicleid")
    ]
    assert not leaked, f"personal data of other users in the feed: {leaked}"


@pytest.mark.finding("FINDING-013")
@pytest.mark.xfail(reason="FINDING-013: receive_report creates a service request without a token")
def test_service_report_creation_requires_authentication(stand: dict[str, Any], anon: CrapiClient) -> None:
    """Anyone who can reach the API can create mechanic reports for any VIN (CWE-306)."""
    res = anon.get(
        "/workshop/api/mechanic/receive_report",
        params={
            "mechanic_code": "TRAC_JHN",
            "problem_details": "unauthenticated probe",
            "vin": stand["users"]["alice"]["vehicle"]["vin"],
            "repeat_request_if_failed": "false",
            "number_of_repeats": 1,
        },
    )
    assert res.status_code == 401
