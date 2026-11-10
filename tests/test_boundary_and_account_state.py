"""경계 시뮬레이터와 포털 대응 API의 계정 상태 조회."""
import pytest
from conftest import Browser, Control, read_events
from fastapi.testclient import TestClient

from nobugs_boundary.app import create_boundary_app

KEY = "boundary-test-key-0123456789"


def client(ip="127.0.0.1", state_path=None):
    return TestClient(create_boundary_app(KEY, state_path), client=(ip, 50000))


H = {"X-Boundary-Key": KEY}


def test_block_unblock_list_roundtrip_and_idempotent_changes():
    c = client()
    assert c.post("/api/v1/boundary/block", json={"ip": "203.0.113.5"}, headers=H).json()["data"]["changed"] is True
    assert c.post("/api/v1/boundary/block", json={"ip": "203.0.113.5"}, headers=H).json()["data"]["changed"] is False
    assert c.get("/api/v1/boundary/blocked", headers=H).json()["data"]["items"] == ["203.0.113.5"]
    assert c.post("/api/v1/boundary/unblock", json={"ip": "203.0.113.5"}, headers=H).json()["data"]["changed"] is True
    assert c.post("/api/v1/boundary/unblock", json={"ip": "203.0.113.5"}, headers=H).json()["data"]["changed"] is False
    assert c.get("/api/v1/boundary/blocked", headers=H).json()["data"]["items"] == []


def test_every_response_says_it_is_simulated():
    c = client()
    assert c.post("/api/v1/boundary/block", json={"ip": "203.0.113.5"}, headers=H).json()["data"]["simulated"] is True
    assert c.get("/api/v1/boundary/blocked", headers=H).json()["data"]["simulated"] is True


def test_key_and_network_are_enforced():
    assert client().get("/api/v1/boundary/blocked").status_code == 401
    assert client().get("/api/v1/boundary/blocked", headers={"X-Boundary-Key": "wrong"}).status_code == 401
    r = client("203.0.113.9").get("/api/v1/boundary/blocked", headers=H)
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN_NETWORK"


def test_invalid_ip_and_bad_body_are_400():
    c = client()
    assert c.post("/api/v1/boundary/block", json={"ip": "not-an-ip"}, headers=H).status_code == 400
    assert c.post("/api/v1/boundary/block", json={}, headers=H).status_code == 400


def test_short_key_is_refused_at_startup():
    with pytest.raises(ValueError):
        create_boundary_app("short")


def test_state_survives_restart(tmp_path):
    path = str(tmp_path / "boundary.json")
    client(state_path=path).post("/api/v1/boundary/block", json={"ip": "203.0.113.7"}, headers=H)
    assert client(state_path=path).get("/api/v1/boundary/blocked", headers=H).json()["data"]["items"] == ["203.0.113.7"]


def test_boundary_app_serves_nothing_else():
    c = client()
    for path in ("/", "/docs", "/openapi.json", "/api/v1/health"):
        assert c.get(path, headers=H).status_code == 404, path


# ---- 포털 계정 상태 조회 ----


def test_account_state_reports_lock_and_live_sessions(control, make_browser):
    victim = make_browser("203.0.113.71")
    victim.login("citizen1")
    before = control.get("/api/v1/response/accounts/citizen1").json()["data"]
    assert before == {"username": "citizen1", "locked": False, "active_sessions": 1, "role": "citizen"}
    control.post("/api/v1/response/accounts/lock", {"username": "citizen1"})
    after = control.get("/api/v1/response/accounts/citizen1").json()["data"]
    assert after["locked"] is True and after["active_sessions"] == 0


def test_account_state_is_case_insensitive_404_for_unknown_and_needs_the_key(control, control_app):
    assert control.get("/api/v1/response/accounts/CITIZEN2").json()["data"]["username"] == "citizen2"
    assert control.get("/api/v1/response/accounts/nobody").status_code == 404
    assert Control(control_app).get("/api/v1/response/accounts/citizen1", key=None).status_code == 401


def test_account_state_is_not_reachable_on_the_public_app(public_app):
    r = Browser(public_app, "127.0.0.1").get("/api/v1/response/accounts/citizen1")
    assert r.status_code == 404


def test_expired_sessions_are_not_counted(control, make_browser, state):
    import datetime as dt

    from nobugs_portal.models import LoginSession

    make_browser("203.0.113.72").login("citizen1")
    with state.db.session() as db:
        for row in db.query(LoginSession).all():
            row.expires_at = row.expires_at - dt.timedelta(days=1)
        db.commit()
    assert control.get("/api/v1/response/accounts/citizen1").json()["data"]["active_sessions"] == 0


def test_read_endpoint_does_not_emit_response_events(control, settings):
    control.get("/api/v1/response/accounts/citizen1")
    assert [e for e in read_events(settings) if e["event_type"].startswith("response.")] == []
