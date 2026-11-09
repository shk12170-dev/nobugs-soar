"""차단 IP 처리, 연결 정보 기반 출발지, 웹 요청·스캔 이벤트."""
import datetime as dt

from conftest import Browser, read_events

from nobugs_portal.models import BlockedIp, utcnow


def block(state, ip, expires_at=None):
    with state.db.session() as db:
        db.add(BlockedIp(ip=ip, expires_at=expires_at))
        db.commit()


def test_blocked_ip_gets_403_on_every_route(state, make_browser):
    block(state, "203.0.113.99")
    b = make_browser("203.0.113.99")
    for path in ("/api/v1/health", "/api/v1/auth/me", "/", "/anything"):
        r = b.get(path)
        assert r.status_code == 403 and r.json()["error"]["code"] == "IP_BLOCKED", path


def test_blocked_ip_cannot_log_in_or_post(state, make_browser):
    block(state, "203.0.113.99")
    r = make_browser("203.0.113.99").post("/api/v1/auth/login", {"username": "citizen1", "password": "x"})
    assert r.status_code == 403


def test_other_addresses_are_not_affected(state, make_browser):
    block(state, "203.0.113.99")
    assert make_browser("203.0.113.98").get("/api/v1/health").status_code == 200


def test_expired_block_is_not_enforced_and_future_block_is(state, make_browser):
    block(state, "203.0.113.97", utcnow() - dt.timedelta(minutes=1))
    block(state, "203.0.113.96", utcnow() + dt.timedelta(minutes=5))
    assert make_browser("203.0.113.97").get("/api/v1/health").status_code == 200
    assert make_browser("203.0.113.96").get("/api/v1/health").status_code == 403


def test_forwarded_header_cannot_evade_or_frame_another_address(state, make_browser):
    block(state, "203.0.113.99")
    # 차단된 주소가 다른 주소인 척해도 연결 정보로 판정한다
    spoofing = make_browser("203.0.113.99").get("/api/v1/health", headers={"X-Forwarded-For": "198.51.100.1"})
    assert spoofing.status_code == 403
    # 정상 주소가 차단된 주소인 척해도 영향이 없다
    framed = make_browser("198.51.100.2").get("/api/v1/health", headers={"X-Forwarded-For": "203.0.113.99"})
    assert framed.status_code == 200


def test_ipv4_mapped_ipv6_connection_matches_the_ipv4_block(state, public_app):
    block(state, "203.0.113.95")
    assert Browser(public_app, "::ffff:203.0.113.95").get("/api/v1/health").status_code == 403


def test_blocked_request_emits_a_blocked_event(state, make_browser, settings):
    block(state, "203.0.113.99")
    make_browser("203.0.113.99").get("/secret")
    events = [e for e in read_events(settings) if e["event_type"] == "web.blocked"]
    assert len(events) == 1 and events[0]["src_ip"] == "203.0.113.99" and events[0]["status"] == 403


def test_unknown_path_is_404_json_and_emits_scan_event(make_browser, settings):
    r = make_browser("203.0.113.90").get("/wp-admin.php")
    assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"
    events = read_events(settings)
    scan = [e for e in events if e["event_type"] == "web.not_found"]
    assert len(scan) == 1 and scan[0]["rule"] == "web-scan" and scan[0]["path"] == "/wp-admin.php"
    assert scan[0]["src_ip"] == "203.0.113.90"


def test_every_request_emits_an_observed_event(make_browser, settings):
    b = make_browser("203.0.113.91")
    b.get("/api/v1/health")
    b.get("/api/v1/health")
    observed = [e for e in read_events(settings) if e["event_type"] == "web.request"]
    assert len(observed) == 2 and all(e["rule"] == "request-observed" and e["status"] == 200 for e in observed)


def test_wrong_method_is_405_json(make_browser):
    r = make_browser().client.delete("/api/v1/health")
    assert r.status_code == 405 and r.json()["error"]["code"] == "METHOD_NOT_ALLOWED"


def test_validation_error_is_400_json_without_internal_details(make_browser):
    b = make_browser()
    b.start()
    r = b.post("/api/v1/auth/register", {"username": "ok_name"})
    assert r.status_code == 400 and r.json()["error"]["code"] == "VALIDATION_ERROR"
    assert "pydantic" not in r.text.lower() and "traceback" not in r.text.lower()


def test_docs_are_off_by_default(make_browser):
    b = make_browser()
    assert b.get("/docs").status_code == 404 and b.get("/openapi.json").status_code == 404
