"""Fixtures for the API security regression tests against the local crAPI stand.

Each test checks the SECURE behaviour. While crAPI is vulnerable the test is marked
`xfail(strict=True)` with its FINDING ID, so the suite is green today and turns red the day the
behaviour changes (fixed, or the finding no longer reproduces) — either way someone must look.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from .client import ALICE, BOB, CrapiClient
from .seed import seed


@pytest.fixture(scope="session")
def stand() -> dict[str, Any]:
    """Seeds (idempotently) and returns the IDs of users A and B and their objects."""
    try:
        return seed()
    except httpx.ConnectError:
        pytest.exit("crAPI stand is not running: make stand-up", returncode=2)


@pytest.fixture(scope="session")
def anon() -> Iterator[CrapiClient]:
    client = CrapiClient()
    yield client
    client.http.close()


@pytest.fixture(scope="session")
def alice(stand: dict[str, Any], anon: CrapiClient) -> CrapiClient:
    return anon.as_user(ALICE)


@pytest.fixture(scope="session")
def bob(stand: dict[str, Any], anon: CrapiClient) -> CrapiClient:
    return anon.as_user(BOB)
