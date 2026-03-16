from fastapi.testclient import TestClient
import os

import app.dashboard as dashboard


def test_dashboard_token_enforcement(tmp_path, monkeypatch):
    client = TestClient(dashboard.app)

    # Set DASH_TOKEN env var
    monkeypatch.setenv("DASH_TOKEN", "secrettoken")

    # Unauthenticated access to / should be 401
    r = client.get("/")
    assert r.status_code == 401

    # Pass token via query param
    r = client.get("/?token=secrettoken")
    assert r.status_code == 200

    # Pass token via Authorization header
    r = client.get("/", headers={"Authorization": "Bearer secrettoken"})
    assert r.status_code == 200
