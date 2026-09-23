"""Characterise authentication contracts before extracting their state owner.

Requests use test-only tokens and no application lifespan, database or network.
"""

from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

import app.dashboard as dashboard
from app.auth_state import AuthenticationState


TOKEN = "test-only-characterisation-operator-token"


@pytest.fixture
def auth_clock(monkeypatch):
    clock = {"wall": 1_800_000_000.0, "monotonic": 1_000.0}
    monkeypatch.setenv("DASH_TOKEN", TOKEN)
    monkeypatch.setenv("NORTHFLUX_ENV", "development")
    monkeypatch.setenv("NORTHFLUX_PUBLIC_ORIGIN", "")
    monkeypatch.setattr(dashboard.app.state, "authentication", AuthenticationState(
        wall_clock=lambda: clock["wall"], monotonic_clock=lambda: clock["monotonic"],
    ))
    return clock


def sign_in(client, route, token=TOKEN):
    if route.startswith("/api/"):
        return client.post(route, json={"token": token}, follow_redirects=False)
    return client.post(route, data={"token": token}, follow_redirects=False)


@pytest.mark.parametrize("route", ["/login", "/api/v1/auth/login"])
@pytest.mark.parametrize("production", [False, True])
def test_login_cookie_and_expiry_contract(auth_clock, monkeypatch, route, production):
    monkeypatch.setenv("NORTHFLUX_ENV", "production" if production else "development")
    client = TestClient(dashboard.app, base_url="https://testserver")
    response = sign_in(client, route)
    assert response.status_code == (200 if route.startswith("/api/") else 303)
    if route == "/login":
        assert response.headers["location"] == "/"
    cookies = SimpleCookie()
    for header in response.headers.get_list("set-cookie"):
        cookies.load(header)
    assert set(cookies) == {"northflux_session", "northflux_csrf"}
    for name, cookie in cookies.items():
        assert cookie["path"] == "/"
        assert cookie["samesite"] == "strict"
        assert cookie["max-age"] == "43200"
        assert bool(cookie["secure"]) is production
        assert bool(cookie["httponly"]) is (name == "northflux_session")
        assert cookie.value and cookie.value != TOKEN
    expected_expiry = datetime.fromtimestamp(auth_clock["wall"] + 43200, tz=timezone.utc)
    session = client.get("/api/v1/auth/session").json()
    assert set(session) == {"required", "authenticated", "expires_at"}
    assert session["required"] is session["authenticated"] is True
    assert datetime.fromisoformat(session["expires_at"].replace("Z", "+00:00")) == expected_expiry
    assert TOKEN not in response.text


@pytest.mark.parametrize("route", ["/login", "/api/v1/auth/login"])
def test_failed_login_window_boundary_and_success_reset(auth_clock, route):
    client = TestClient(dashboard.app)
    # Four failures followed by success must reset the shared failed-login count.
    for _ in range(4):
        response = sign_in(client, route, "wrong")
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid access token"}
    assert sign_in(client, route).status_code in {200, 303}
    for _ in range(5):
        assert sign_in(client, route, "wrong").status_code == 401
    response = sign_in(client, route)
    assert response.status_code == 429
    assert response.json() == {"detail": "Too many failed sign-in attempts"}
    # Window expiry is monotonic; changing wall-clock time does not unlock it.
    auth_clock["wall"] += 100_000
    auth_clock["monotonic"] += 299.999
    assert sign_in(client, route).status_code == 429
    auth_clock["monotonic"] += 0.001
    assert sign_in(client, route).status_code in {200, 303}


def test_legacy_and_json_routes_share_failed_login_budget(auth_clock):
    client = TestClient(dashboard.app)
    for route in ["/login", "/api/v1/auth/login", "/login", "/api/v1/auth/login", "/login"]:
        assert sign_in(client, route, "wrong").status_code == 401
    assert sign_in(client, "/api/v1/auth/login").status_code == 429


def test_session_expiry_boundary_and_defensive_snapshot(auth_clock):
    session_id, csrf = dashboard._create_session(TOKEN)
    session = dashboard._get_session(session_id, TOKEN)
    assert session["csrf_token"] == csrf
    session["expires_at"] = 0
    session["csrf_token"] = "not-the-stored-token"
    assert dashboard._get_session(session_id, TOKEN)["csrf_token"] == csrf
    auth_clock["wall"] += 43199.999
    assert dashboard._get_session(session_id, TOKEN) is not None
    auth_clock["wall"] += 0.001
    assert dashboard._get_session(session_id, TOKEN) is None
    # Invalidated sessions cannot revive if the wall clock later moves back.
    auth_clock["wall"] -= 43200
    assert dashboard._get_session(session_id, TOKEN) is None


def test_dynamic_token_rotation_permanently_revokes_observed_session(auth_clock, monkeypatch):
    client = TestClient(dashboard.app)
    assert sign_in(client, "/api/v1/auth/login").status_code == 200
    monkeypatch.setenv("DASH_TOKEN", "test-only-replacement-token")
    assert client.get("/api/v1/auth/session").json() == {
        "required": True, "authenticated": False, "expires_at": None,
    }
    monkeypatch.setenv("DASH_TOKEN", TOKEN)
    assert client.get("/api/v1/auth/session").json()["authenticated"] is False


@pytest.mark.parametrize("route", ["/logout", "/api/v1/auth/logout"])
def test_dynamic_origin_and_csrf_before_revoke(auth_clock, monkeypatch, route):
    client = TestClient(dashboard.app)
    assert sign_in(client, "/api/v1/auth/login").status_code == 200
    session_id = client.cookies.get("northflux_session")
    csrf = client.cookies.get("northflux_csrf")
    monkeypatch.setenv("NORTHFLUX_PUBLIC_ORIGIN", "https://operator.example")
    headers = {"Origin": "http://testserver", "X-CSRF-Token": csrf}
    response = client.post(route, headers=headers, follow_redirects=False)
    assert response.status_code == 403
    assert response.json() == {"detail": "Invalid request origin"}
    headers["Origin"] = "https://operator.example"
    headers["X-CSRF-Token"] = "wrong"
    response = client.post(route, headers=headers, follow_redirects=False)
    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF validation failed"}
    assert dashboard._get_session(session_id, TOKEN) is not None
    headers["X-CSRF-Token"] = csrf
    response = client.post(route, headers=headers, follow_redirects=False)
    assert response.status_code == (200 if route.startswith("/api/") else 303)
    assert dashboard._get_session(session_id, TOKEN) is None
    assert client.cookies.get("northflux_session") is None
    assert client.cookies.get("northflux_csrf") is None


def test_bearer_logout_does_not_create_or_require_browser_session(auth_clock):
    client = TestClient(dashboard.app)
    response = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 200
    assert response.json() == {"required": True, "authenticated": False, "expires_at": None}
    assert client.get("/api/v1/auth/session").json()["authenticated"] is False


def test_state_owners_do_not_share_sessions_or_failure_budgets():
    first = AuthenticationState(max_failed_logins=1)
    second = AuthenticationState(max_failed_logins=1)
    session_id, _ = first.create_session(TOKEN)
    first.record_login_failure("client-one")
    assert first.get_session(session_id, TOKEN) is not None
    assert second.get_session(session_id, TOKEN) is None
    assert not first.login_allowed("client-one")
    assert second.login_allowed("client-one")


def test_session_token_factory_and_no_plaintext_operator_token():
    factory = Mock(side_effect=["test-session-id", "test-csrf-id"])
    state = AuthenticationState(wall_clock=lambda: 10.0, token_factory=factory)
    session_id, csrf = state.create_session(TOKEN)
    assert (session_id, csrf) == ("test-session-id", "test-csrf-id")
    assert [call.args for call in factory.call_args_list] == [(32,), (32,)]
    snapshot = state.get_session(session_id, TOKEN)
    assert snapshot["expires_at"] == 43210.0
    assert len(snapshot["token_fingerprint"]) == 64
    assert TOKEN not in str(snapshot)


def test_new_session_prunes_expired_records_without_reviving_them():
    clock = [100.0]
    state = AuthenticationState(wall_clock=lambda: clock[0], session_ttl_seconds=10)
    expired, _ = state.create_session(TOKEN)
    clock[0] = 110.0
    current, _ = state.create_session(TOKEN)
    clock[0] = 100.0
    assert state.get_session(expired, TOKEN) is None
    assert state.get_session(current, TOKEN) is not None


def test_revoke_is_idempotent_and_does_not_remove_another_session():
    state = AuthenticationState()
    first, _ = state.create_session(TOKEN)
    second, _ = state.create_session(TOKEN)
    state.revoke_session(first)
    state.revoke_session(first)
    state.revoke_session("unknown")
    assert state.get_session(first, TOKEN) is None
    assert state.get_session("", TOKEN) is None
    assert state.get_session("unknown", TOKEN) is None
    assert state.get_session(second, TOKEN) is not None


def test_failed_login_budgets_are_per_client_and_clear_only_the_selected_client():
    clock = [100.0]
    state = AuthenticationState(monotonic_clock=lambda: clock[0], max_failed_logins=1)
    state.record_login_failure("client-one")
    state.record_login_failure("client-two")
    assert not state.login_allowed("client-one")
    assert not state.login_allowed("client-two")
    assert state.login_allowed("client-three")
    state.clear_login_failures("client-one")
    state.clear_login_failures("unknown")
    assert state.login_allowed("client-one")
    assert not state.login_allowed("client-two")
    clock[0] = 400.0
    assert state.login_allowed("client-two")


def test_concurrent_session_and_failure_operations_keep_one_coherent_owner():
    state = AuthenticationState(max_failed_logins=64)

    def create_and_record(_):
        state.record_login_failure("shared-client")
        session_id, csrf = state.create_session(TOKEN)
        assert state.get_session(session_id, TOKEN)["csrf_token"] == csrf
        return session_id

    with ThreadPoolExecutor(max_workers=8) as executor:
        sessions = list(executor.map(create_and_record, range(64)))
        assert len(set(sessions)) == 64
        assert not state.login_allowed("shared-client")
        list(executor.map(state.revoke_session, sessions))
    assert all(state.get_session(session_id, TOKEN) is None for session_id in sessions)
