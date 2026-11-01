"""OWASP API1:2023 (BOLA), API3:2023 (property-level authorization) and API5:2023 (BFLA).

Alice and Bob are both created by this suite; every object touched belongs to one of them.
"""

from __future__ import annotations

from typing import Any

import pytest

from .client import CrapiClient


@pytest.mark.finding("FINDING-006")
@pytest.mark.xfail(reason="FINDING-006: any authenticated user can read any vehicle's location")
def test_vehicle_location_of_another_user_is_refused(stand: dict[str, Any], alice: CrapiClient) -> None:
    """GPS position, owner name and e-mail of a car that belongs to someone else (CWE-639)."""
    bob_vehicle = stand["users"]["bob"]["vehicle"]["id"]
    assert alice.get(f"/identity/api/v2/vehicle/{bob_vehicle}/location").status_code in (401, 403, 404)


@pytest.mark.positive_control
def test_own_vehicle_location_is_allowed(stand: dict[str, Any], alice: CrapiClient) -> None:
    own = stand["users"]["alice"]["vehicle"]["id"]
    res = alice.get(f"/identity/api/v2/vehicle/{own}/location")
    assert res.status_code == 200
    assert res.json()["email"] == stand["users"]["alice"]["email"]


@pytest.mark.positive_control
def test_vehicle_location_requires_authentication(stand: dict[str, Any], anon: CrapiClient) -> None:
    own = stand["users"]["alice"]["vehicle"]["id"]
    assert anon.get(f"/identity/api/v2/vehicle/{own}/location").status_code == 401


@pytest.mark.finding("FINDING-007")
@pytest.mark.xfail(reason="FINDING-007: any authenticated user can read any order by id")
def test_order_of_another_user_is_refused(stand: dict[str, Any], alice: CrapiClient) -> None:
    """Order details include the buyer's e-mail, phone number and transaction id."""
    assert alice.get(f"/workshop/api/shop/orders/{stand['users']['bob']['order_id']}").status_code in (
        401,
        403,
        404,
    )


@pytest.mark.positive_control
def test_changing_another_users_order_is_refused(stand: dict[str, Any], alice: CrapiClient) -> None:
    """crAPI checks ownership on write even though it does not on read — the asymmetry is the finding."""
    bob_order = stand["users"]["bob"]["order_id"]
    res = alice.put(f"/workshop/api/shop/orders/{bob_order}", json={"status": "returned", "quantity": 1})
    assert res.status_code == 403


@pytest.mark.finding("FINDING-008")
@pytest.mark.xfail(reason="FINDING-008: mechanic reports are readable by id by any authenticated user")
def test_mechanic_report_of_another_user_is_refused(stand: dict[str, Any], alice: CrapiClient) -> None:
    """Reports carry the owner's e-mail, phone number, VIN and free-text problem description."""
    res = alice.get("/workshop/api/mechanic/mechanic_report", params={"report_id": 1})
    assert res.status_code in (401, 403, 404)


@pytest.mark.finding("FINDING-010")
@pytest.mark.xfail(reason="FINDING-010: the management user list is open to any authenticated user")
def test_management_user_list_is_refused_to_a_customer(stand: dict[str, Any], alice: CrapiClient) -> None:
    """Returns every user of the shop with e-mail, phone number and credit balance (CWE-285)."""
    assert alice.get("/workshop/api/management/users/all").status_code in (401, 403)


@pytest.mark.finding("FINDING-009")
@pytest.mark.xfail(reason="FINDING-009: the admin video route accepts a normal user's token")
def test_admin_video_route_is_refused_to_a_customer(
    stand: dict[str, Any], alice: CrapiClient, bob: CrapiClient
) -> None:
    """An administrative function must check the role, not only the token (CWE-285)."""
    upload = alice.post(
        "/identity/api/v2/user/videos", files={"file": ("qa.mp4", b"\x00\x00\x00\x18ftypmp42qa", "video/mp4")}
    )
    assert upload.status_code == 200, upload.text
    video_id = upload.json()["id"]
    try:
        assert bob.delete(f"/identity/api/v2/admin/videos/{video_id}").status_code in (401, 403)
    finally:
        alice.delete(f"/identity/api/v2/user/videos/{video_id}")


@pytest.mark.finding("FINDING-014")
@pytest.mark.xfail(reason="FINDING-014: order status is writable by the customer")
def test_order_status_is_not_client_writable(stand: dict[str, Any], alice: CrapiClient) -> None:
    """Fulfilment status is a server-side property; a customer must not set it (mass assignment, CWE-915).

    The order is created inside the test, so the check does not depend on what earlier tests left behind.
    """
    created = alice.post("/workshop/api/shop/orders", json={"product_id": 1, "quantity": 1})
    assert created.status_code == 200, created.text
    order = created.json()["id"]
    before = alice.get(f"/workshop/api/shop/orders/{order}").json()["order"]["status"]
    target = "returned" if before != "returned" else "delivered"
    alice.put(f"/workshop/api/shop/orders/{order}", json={"status": target, "quantity": 1})
    after = alice.get(f"/workshop/api/shop/orders/{order}").json()["order"]["status"]
    assert after == before, f"status changed {before!r} -> {after!r} from the client"
