import pytest

from security_tests.client import CrapiClient, OutOfScopeError, ensure_local


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8888",
        "http://127.0.0.5:8888/identity",
        "http://[::1]:8888",
        "http://localhost:8025",
        "http://crapi-web",
        "http://canary:8080/x",
    ],
)
def test_local_stand_addresses_are_allowed(url: str) -> None:
    assert ensure_local(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "https://crapi.apisec.ai",
        "http://10.0.0.5:8888",
        "http://192.168.1.10",
        "http://example.com",
        "http://localhost.evil.test",
        "http://127.0.0.1.nip.io",
        "",
    ],
)
def test_anything_else_is_refused(url: str) -> None:
    with pytest.raises(OutOfScopeError):
        ensure_local(url)


def test_client_refuses_external_base_url() -> None:
    with pytest.raises(OutOfScopeError):
        CrapiClient("https://crapi.apisec.ai")
