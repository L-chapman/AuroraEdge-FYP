from fastapi.testclient import TestClient
import os

import app.dashboard as dashboard


def test_dashboard_token_enforcement(tmp_path, monkeypatch):
    client = TestClient(dashboard.app)

    # Set DASH_TOKEN env var
    monkeypatch.setenv("DASH_TOKEN", "secrettoken")

    # Browser pages redirect unauthenticated operators to the login page.
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"

    # Pass token via query param
    r = client.get("/?token=secrettoken")
    assert r.status_code == 200

    # Pass token via Authorization header
    r = client.get("/", headers={"Authorization": "Bearer secrettoken"})
    assert r.status_code == 200

    # Browser login exchanges the shared token for an HttpOnly session.
    session_client = TestClient(dashboard.app)
    r = session_client.post("/login", data={"token": "secrettoken"}, follow_redirects=False)
    assert r.status_code == 303
    assert "HttpOnly" in r.headers["set-cookie"]
    assert session_client.get("/").status_code == 200


def test_browser_session_requires_csrf_and_logout_revokes(monkeypatch):
    monkeypatch.delenv("NORTHFLUX_ENV", raising=False)
    monkeypatch.setenv("DASH_TOKEN", "browser-session-test-token")
    dashboard._sessions.clear()
    client = TestClient(dashboard.app)

    login_response = client.post(
        "/login",
        data={"token": "browser-session-test-token"},
        follow_redirects=False,
    )
    assert login_response.status_code == 303

    assert client.post("/logout", follow_redirects=False).status_code == 403

    csrf_token = client.cookies.get("northflux_csrf")
    logout_response = client.post(
        "/logout",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": csrf_token,
        },
        follow_redirects=False,
    )
    assert logout_response.status_code == 303
    assert client.get("/", follow_redirects=False).status_code == 303


def test_token_rotation_invalidates_browser_session(monkeypatch):
    monkeypatch.delenv("NORTHFLUX_ENV", raising=False)
    monkeypatch.setenv("DASH_TOKEN", "first-browser-session-token")
    dashboard._sessions.clear()
    client = TestClient(dashboard.app)
    assert client.post(
        "/login",
        data={"token": "first-browser-session-token"},
        follow_redirects=False,
    ).status_code == 303
    assert client.get("/").status_code == 200

    monkeypatch.setenv("DASH_TOKEN", "rotated-browser-session-token")
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_expired_browser_session_is_rejected(monkeypatch):
    monkeypatch.delenv("NORTHFLUX_ENV", raising=False)
    monkeypatch.setenv("DASH_TOKEN", "expiring-browser-session-token")
    dashboard._sessions.clear()
    client = TestClient(dashboard.app)
    assert client.post(
        "/login",
        data={"token": "expiring-browser-session-token"},
        follow_redirects=False,
    ).status_code == 303

    session_id = client.cookies.get("northflux_session")
    with dashboard._session_lock:
        dashboard._sessions[session_id]["expires_at"] = 0

    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
