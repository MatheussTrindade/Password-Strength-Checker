import pytest

from app import checker, create_app


@pytest.fixture(autouse=True)
def offline_hibp(monkeypatch):
    """Never hit the real API in tests; individual tests can override."""
    monkeypatch.setattr(checker, "check_password_pwned", lambda password: 0)


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()
