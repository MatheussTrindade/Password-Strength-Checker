"""Have I Been Pwned (Pwned Passwords) client using the k-anonymity range API.

Only the first 5 hex characters of the SHA-1 hash leave the server; the
matching against the remaining 35 characters happens locally.
"""

from __future__ import annotations

import hashlib
import logging
import os
from functools import lru_cache

import requests

log = logging.getLogger(__name__)

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "Password-Strength-Checker (+https://github.com/MatheussTrindade/Password-Strength-Checker)"
TIMEOUT_SECONDS = 5


def _verify_ssl() -> bool:
    """TLS verification is on unless HIBP_INSECURE_SSL is explicitly set.

    Behind a corporate proxy, prefer pointing REQUESTS_CA_BUNDLE at the proxy's
    CA certificate instead of disabling verification.
    """
    insecure = os.getenv("HIBP_INSECURE_SSL", "").strip().lower() in {"1", "true", "yes"}
    if insecure:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return not insecure


@lru_cache(maxsize=512)
def _fetch_range(prefix: str) -> dict[str, int]:
    response = requests.get(
        API_URL.format(prefix=prefix),
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
        timeout=TIMEOUT_SECONDS,
        verify=_verify_ssl(),
    )
    response.raise_for_status()

    hashes: dict[str, int] = {}
    for line in response.text.splitlines():
        suffix, _, count = line.strip().partition(":")
        if count:
            hashes[suffix.upper()] = int(count)
    return hashes


def check_password_pwned(password: str) -> int | None:
    """Return how many times the password appears in known breaches.

    Returns ``None`` when the lookup could not be completed, so callers can
    tell "not found" apart from "unknown".
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]

    try:
        return _fetch_range(prefix).get(suffix, 0)
    except (requests.RequestException, ValueError) as exc:
        log.warning("Pwned Passwords lookup failed: %s", exc.__class__.__name__)
        return None
