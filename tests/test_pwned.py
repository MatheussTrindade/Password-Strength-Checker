import hashlib

import pytest
import requests

from app.services import pwned


class FakeResponse:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(self.status_code)


@pytest.fixture(autouse=True)
def clear_cache():
    pwned._fetch_range.cache_clear()
    yield
    pwned._fetch_range.cache_clear()


def test_only_hash_prefix_is_sent_and_count_is_parsed(monkeypatch):
    digest = hashlib.sha1(b"hunter2").hexdigest().upper()
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(f"0000000000000000000000000000000000A:0\r\n{digest[5:]}:1337\r\n")

    monkeypatch.setattr(pwned.requests, "get", fake_get)

    assert pwned.check_password_pwned("hunter2") == 1337
    url, kwargs = calls[0]
    assert url.endswith("/range/" + digest[:5])
    assert "hunter2" not in url and digest[5:] not in url
    assert kwargs["headers"]["Add-Padding"] == "true"
    assert kwargs["verify"] is True


def test_not_found_returns_zero(monkeypatch):
    monkeypatch.setattr(pwned.requests, "get", lambda url, **kw: FakeResponse("ABC:1\n"))
    assert pwned.check_password_pwned("something-unique") == 0


def test_network_failure_returns_none(monkeypatch):
    def boom(url, **kwargs):
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(pwned.requests, "get", boom)
    assert pwned.check_password_pwned("anything") is None


def test_insecure_ssl_is_opt_in(monkeypatch):
    monkeypatch.setenv("HIBP_INSECURE_SSL", "1")
    assert pwned._verify_ssl() is False
    monkeypatch.delenv("HIBP_INSECURE_SSL")
    assert pwned._verify_ssl() is True
