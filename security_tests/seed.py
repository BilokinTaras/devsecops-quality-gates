"""Idempotent test data for the crAPI stand: users A (Alice) and B (Bob), each with a vehicle, a community
post and a shop order. Running it again changes nothing. Writes the IDs to .generated/stand.json.

Usage: uv run python -m security_tests.seed
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .client import ALICE, BOB, CrapiClient, User, latest_mail

OUT = Path(__file__).resolve().parent.parent / ".generated" / "stand.json"
SEED_TAG = "[qa-seed]"


def _ensure_user(anon: CrapiClient, user: User) -> str:
    res = anon.signup(user)
    if res.status_code == 200:
        return "created"
    if res.status_code == 403 and "already registered" in res.text:
        return "exists"
    raise RuntimeError(f"signup {user.email}: {res.status_code} {res.text}")


def _ensure_vehicle(api: CrapiClient, user: User) -> dict[str, Any]:
    vehicles = api.get("/identity/api/v2/vehicle/vehicles").json()
    if not vehicles:
        mail = latest_mail(user.email, "Welcome")
        found = re.search(r"VIN:\s*(\w+)\s+and Pincode:\s*(\d+)", mail)
        if not found:
            raise RuntimeError(f"no VIN/pincode in the welcome mail of {user.email}")
        res = api.post("/identity/api/v2/vehicle/add_vehicle", json={"vin": found[1], "pincode": found[2]})
        if res.status_code not in (200, 403):
            raise RuntimeError(f"add_vehicle {user.email}: {res.status_code} {res.text}")
        vehicles = api.get("/identity/api/v2/vehicle/vehicles").json()
    vehicle: dict[str, Any] = vehicles[0]
    return {"id": vehicle["uuid"], "vin": vehicle["vin"]}


def _ensure_post(api: CrapiClient, user: User) -> str:
    title = f"{SEED_TAG} {user.name}"
    posts = api.get("/community/api/v2/community/posts/recent", params={"limit": 100}).json()["posts"]
    for post in posts:
        if post["title"] == title and post["author"]["email"] == user.email:
            return str(post["id"])
    res = api.post("/community/api/v2/community/posts", json={"title": title, "content": "Seeded by tests."})
    res.raise_for_status()
    return str(res.json()["id"])


def _ensure_order(api: CrapiClient) -> int:
    orders = api.get("/workshop/api/shop/orders/all").json()["orders"]
    if orders:
        return int(orders[0]["id"])
    res = api.post("/workshop/api/shop/orders", json={"product_id": 1, "quantity": 1})
    res.raise_for_status()
    return int(res.json()["id"])


def seed() -> dict[str, Any]:
    anon = CrapiClient()
    data: dict[str, Any] = {"base_url": anon.base_url, "users": {}}
    for key, user in (("alice", ALICE), ("bob", BOB)):
        status = _ensure_user(anon, user)
        api = anon.as_user(user)
        dashboard = api.get("/identity/api/v2/user/dashboard").json()
        data["users"][key] = {
            "email": user.email,
            "phone": user.number,
            "user_id": dashboard["id"],
            "signup": status,
            "vehicle": _ensure_vehicle(api, user),
            "post_id": _ensure_post(api, user),
            "order_id": _ensure_order(api),
        }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return data


if __name__ == "__main__":
    print(json.dumps(seed(), indent=2))
