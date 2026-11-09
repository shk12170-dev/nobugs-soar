"""대응 API(별도 앱): 인증·허용 대역·멱등·차단·계정 잠금, 그리고 일반 앱과의 분리."""
import datetime as dt

from conftest import KEY, PASSWORD, Browser, Control, read_events

from nobugs_portal.app import create_public_app
from nobugs_portal.control import create_control_app
from nobugs_portal.models import BlockedIp, utcnow

ATTACKER = "203.0.113.77"


# ---- 앱 분리 ----

def test_public_app_has_no_response_routes_even_with_a_valid_key(public_app):
    b = Browser(public_app, "127.0.0.1")
    r = b.client.get("/api/v1/response/ips", headers={"X-Response-Key": KEY})
    assert r.status_code == 404


def test_control_app_serves_nothing_but_the_response_api(control_app):
    c = Control(control_app)
    for path in ("/api/v1/health", "/api/v1/auth/me", "/", "/docs", "/openapi.json"):
        assert c.client.get(path, headers=c.headers()).status_code == 404, path


# ---- 인증 ----

def test_disabled_when_key_or_cidrs_are_not_configured(state):
    from dataclasses import replace

    for settings in (replace(state.settings, response_api_key=""), replace(state.settings, response_allowed_cidrs=())):
        app = create_control_app(state=type(state)(settings=settings, db=state.db, events=state.events))
        r = Control(app).get("/api/v1/response/ping")
        assert r.status_code == 403 and r.json()["error"]["code"] == "DISABLED"


def test_source_outside_allowed_networks_is_refused(control_app):
    r = Control(control_app, ip="203.0.113.5").get("/api/v1/response/ping")
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN_NETWORK"


def test_missing_or_wrong_key_is_401(control_app):
    c = Control(control_app)
    assert c.get("/api/v1/response/ping", key=None).status_code == 401
    assert c.get("/api/v1/response/ping", key="wrong-key").status_code == 401
    assert c.get("/api/v1/response/ping").status_code == 200


# ---- 차단 ----

def test_block_makes_the_public_portal_return_403(control, public_app):
    r = control.post("/api/v1/response/ips/block", {"ip": ATTACKER})
    assert r.status_code == 200
    assert r.json()["data"] == {"ip": ATTACKER, "blocked": True, "changed": True, "expires_at": None, "replayed": False}
    assert Browser(public_app, ATTACKER).get("/api/v1/health").status_code == 403
    assert Browser(public_app, "203.0.113.78").get("/api/v1/health").status_code == 200


def test_unblock_restores_access(control, public_app):
    control.post("/api/v1/response/ips/block", {"ip": ATTACKER})
    r = control.post("/api/v1/response/ips/unblock", {"ip": ATTACKER})
    assert r.json()["data"]["changed"] is True and r.json()["data"]["blocked"] is False
    assert Browser(public_app, ATTACKER).get("/api/v1/health").status_code == 200
    assert control.post("/api/v1/response/ips/unblock", {"ip": ATTACKER}).json()["data"]["changed"] is False


def test_list_shows_only_active_blocks(control, state):
    control.post("/api/v1/response/ips/block", {"ip": ATTACKER})
    with state.db.session() as db:
        db.add(BlockedIp(ip="203.0.113.76", expires_at=utcnow() - dt.timedelta(minutes=1)))
        db.commit()
    items = control.get("/api/v1/response/ips").json()["data"]["items"]
    assert [i["ip"] for i in items] == [ATTACKER]


def test_block_with_ttl_sets_expiry(control):
    r = control.post("/api/v1/response/ips/block", {"ip": ATTACKER, "ttl_seconds": 120})
    assert r.json()["data"]["expires_at"] is not None


def test_block_validates_ip_and_ttl(control):
    assert control.post("/api/v1/response/ips/block", {"ip": "not-an-ip"}).status_code == 400
    assert control.post("/api/v1/response/ips/block", {"ip": ATTACKER, "ttl_seconds": 5}).status_code == 400


def test_ipv4_mapped_address_is_blocked_as_ipv4(control, public_app):
    control.post("/api/v1/response/ips/block", {"ip": f"::ffff:{ATTACKER}"})
    assert Browser(public_app, ATTACKER).get("/api/v1/health").status_code == 403


# ---- 멱등 ----

def test_mutation_requires_an_idempotency_key(control):
    assert control.post("/api/v1/response/ips/block", {"ip": ATTACKER}, idem=None).status_code == 400
    assert control.post("/api/v1/response/ips/block", {"ip": ATTACKER}, idem="short").status_code == 400


def test_same_key_and_body_replays_the_stored_result(control):
    first = control.post("/api/v1/response/ips/block", {"ip": ATTACKER}, idem="idem-key-0000000001").json()["data"]
    again = control.post("/api/v1/response/ips/block", {"ip": ATTACKER}, idem="idem-key-0000000001").json()["data"]
    assert first["changed"] is True and again["changed"] is True and again["replayed"] is True


def test_same_key_with_a_different_body_conflicts(control):
    control.post("/api/v1/response/ips/block", {"ip": ATTACKER}, idem="idem-key-0000000002")
    r = control.post("/api/v1/response/ips/block", {"ip": "203.0.113.75"}, idem="idem-key-0000000002")
    assert r.status_code == 409 and r.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"


def test_a_replayed_block_does_not_undo_a_later_unblock(control, public_app):
    control.post("/api/v1/response/ips/block", {"ip": ATTACKER}, idem="idem-key-0000000003")
    control.post("/api/v1/response/ips/unblock", {"ip": ATTACKER})
    control.post("/api/v1/response/ips/block", {"ip": ATTACKER}, idem="idem-key-0000000003")  # 재전송
    assert Browser(public_app, ATTACKER).get("/api/v1/health").status_code == 200


def test_second_block_with_a_new_key_reports_no_change(control):
    control.post("/api/v1/response/ips/block", {"ip": ATTACKER})
    assert control.post("/api/v1/response/ips/block", {"ip": ATTACKER}).json()["data"]["changed"] is False


# ---- 계정 잠금 ----

def test_lock_account_revokes_sessions_and_blocks_login(control, make_browser):
    victim = make_browser("203.0.113.71")
    assert victim.login("citizen1").status_code == 200
    r = control.post("/api/v1/response/accounts/lock", {"username": "Citizen1"})
    data = r.json()["data"]
    assert r.status_code == 200 and data["locked"] is True and data["changed"] is True and data["revoked_sessions"] == 1
    assert victim.get("/api/v1/auth/me").json()["data"]["user"] is None
    assert make_browser("203.0.113.72").login("citizen1").status_code == 401


def test_lock_is_idempotent_and_reports_second_change_false(control):
    control.post("/api/v1/response/accounts/lock", {"username": "citizen1"}, idem="idem-key-0000000010")
    replay = control.post("/api/v1/response/accounts/lock", {"username": "citizen1"}, idem="idem-key-0000000010")
    assert replay.json()["data"]["replayed"] is True
    fresh = control.post("/api/v1/response/accounts/lock", {"username": "citizen1"})
    assert fresh.json()["data"]["changed"] is False


def test_admin_accounts_are_never_locked_automatically(control):
    r = control.post("/api/v1/response/accounts/lock", {"username": "admin1"})
    assert r.status_code == 403


def test_locking_an_unknown_account_is_404(control):
    assert control.post("/api/v1/response/accounts/lock", {"username": "nobody"}).status_code == 404


def test_response_actions_emit_events_but_replays_do_not(control, settings):
    control.post("/api/v1/response/ips/block", {"ip": ATTACKER}, idem="idem-key-0000000020")
    control.post("/api/v1/response/ips/block", {"ip": ATTACKER}, idem="idem-key-0000000020")
    blocked = [e for e in read_events(settings) if e["event_type"] == "response.ip_blocked"]
    assert len(blocked) == 1 and blocked[0]["target_ip"] == ATTACKER


def test_human_recovery_by_admin_after_automatic_lock(control, admin, make_browser, state):
    from nobugs_portal.services import find_user

    control.post("/api/v1/response/accounts/lock", {"username": "citizen2"})
    with state.db.session() as db:
        uid = find_user(db, "citizen2").id
    reset = admin.post(f"/api/v1/admin/users/{uid}/reset-password", {"new_password": "Recovered-Passw0rd-1"})
    assert reset.status_code == 200
    assert make_browser("203.0.113.73").login("citizen2", "Recovered-Passw0rd-1").status_code == 200
    assert make_browser("203.0.113.74").login("citizen2", PASSWORD).status_code == 401


def test_both_apps_share_the_same_database(state):
    public = create_public_app(state=state)
    control_app = create_control_app(state=state)
    Control(control_app).post("/api/v1/response/ips/block", {"ip": ATTACKER})
    assert Browser(public, ATTACKER).get("/api/v1/health").status_code == 403


def test_response_events_record_the_callers_address_not_unknown(control_app, settings):
    Control(control_app, ip="10.1.2.3").post("/api/v1/response/ips/block", {"ip": ATTACKER})
    event = [e for e in read_events(settings) if e["event_type"] == "response.ip_blocked"][0]
    assert event["src_ip"] == "10.1.2.3" and event["target_ip"] == ATTACKER
