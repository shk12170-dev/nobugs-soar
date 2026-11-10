"""엔진 주변부: 포털 클라이언트, 효과 프로브, 알림 문구, 웹훅 앱, 스케줄러, 그리고 실제 포털과의 통합."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import uvicorn
from conftest import KEY
from fastapi.testclient import TestClient
from test_engine import FakePortal, FakeProbe

from nobugs_engine.app import Scheduler, create_engine_app
from nobugs_engine.config import EngineSettings
from nobugs_engine.engine import Detection, Engine
from nobugs_engine.models import Ticket, utcnow
from nobugs_engine.notify import Notifier, format_message
from nobugs_engine.portal import HttpPortalControl, PortalError, PortalUncertain
from nobugs_engine.probe import LoopbackProbe, NullProbe
from nobugs_engine.store import Store

ENGINE_KEY = "engine-test-key-0123456789"

# ---- 포털 클라이언트(가짜 HTTP 서버) ----


class FakePortalServer(BaseHTTPRequestHandler):
    seen: list = []
    mode = "ok"

    def _reply(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = json.loads(self.rfile.read(length)) if length else None
        type(self).seen.append((self.command, self.path, self.headers.get("X-Response-Key"),
                                self.headers.get("Idempotency-Key"), body))
        mode = type(self).mode
        if mode == "4xx":
            return self._reply(403, {"error": {"code": "FORBIDDEN"}})
        if mode == "5xx":
            return self._reply(500, {"error": {"code": "SERVER_ERROR"}})
        if mode == "slow":
            time.sleep(1.5)
        if mode == "garbage":
            return self._reply(200, {"unexpected": True})
        if self.path.endswith("/ips") and self.command == "GET":
            return self._reply(200, {"data": {"items": [{"ip": "203.0.113.1"}, {"ip": "203.0.113.2"}]}})
        self._reply(200, {"data": {"ip": body["ip"], "blocked": self.path.endswith("/block"), "changed": True}})

    do_GET = do_POST = _handle  # noqa: N815

    def log_message(self, *args):
        pass


@pytest.fixture
def portal_server():
    FakePortalServer.seen, FakePortalServer.mode = [], "ok"
    server = HTTPServer(("127.0.0.1", 0), FakePortalServer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_client_sends_key_and_idempotency_key_and_parses_result(portal_server):
    client = HttpPortalControl(portal_server, "secret-key-value")
    assert client.block_ip("203.0.113.9", "idem-0000000000000001")["blocked"] is True
    method, path, key, idem, body = FakePortalServer.seen[0]
    assert (method, path, key, idem, body) == ("POST", "/api/v1/response/ips/block", "secret-key-value",
                                               "idem-0000000000000001", {"ip": "203.0.113.9"})
    assert client.unblock_ip("203.0.113.9", "idem-0000000000000002")["blocked"] is False
    assert client.blocked_ips() == {"203.0.113.1", "203.0.113.2"}


def test_client_maps_4xx_to_definitive_error_and_5xx_to_uncertain(portal_server):
    client = HttpPortalControl(portal_server, "k")
    FakePortalServer.mode = "4xx"
    with pytest.raises(PortalError):
        client.block_ip("203.0.113.9", "idem-0000000000000003")
    FakePortalServer.mode = "5xx"
    with pytest.raises(PortalUncertain):
        client.block_ip("203.0.113.9", "idem-0000000000000004")


def test_client_treats_timeout_refused_connection_and_garbage_as_uncertain(portal_server):
    FakePortalServer.mode = "slow"
    with pytest.raises(PortalUncertain):
        HttpPortalControl(portal_server, "k", timeout=0.3).block_ip("203.0.113.9", "idem-0000000000000005")
    with pytest.raises(PortalUncertain):
        HttpPortalControl("http://127.0.0.1:1", "k", timeout=0.5).blocked_ips()
    FakePortalServer.mode = "garbage"
    with pytest.raises(PortalUncertain):
        HttpPortalControl(portal_server, "k").blocked_ips()


# ---- 알림 문구 ----


def sample_ticket(**kw):
    return Ticket(id="T-20261110-0007", case_id="S1", group_key="v@1.2.3.4", status="responding", src_ip="203.0.113.50",
                  username="victim", event_ids=[], **kw)


def test_message_is_short_korean_and_free_of_internal_details():
    from nobugs_engine.models import Action

    action = Action(ticket_id="x", kind="ip_block", target="203.0.113.50", result="applied", applied_verified=True,
                    effect_verified=True)
    text = format_message("warn", sample_ticket(), "applied", [action])
    assert text.splitlines()[0] == "⚠️ **[S1] 로그인 반복 실패(무차별 대입)**"
    assert "결과: 조치 적용" in text and "출발지: 203.0.113.50" in text and "계정: victim" in text
    assert "포털 차단 목록에 반영됨" in text and "실제 접근 차단 확인됨" in text and "T-20261110-0007" in text
    assert "http" not in text and "applied" not in text and len(text.splitlines()) <= 7


def test_message_levels_and_restore_wording():
    from nobugs_engine.models import Action

    release = Action(ticket_id="x", kind="ip_release", target="t", result="released", effect_verified=True)
    assert format_message("info", sample_ticket(), "released", [release]).startswith("ℹ️")
    assert "접근 복구 확인됨" in format_message("info", sample_ticket(), "released", [release])
    assert format_message("error", sample_ticket(), "uncertain").startswith("🚨")


def test_discord_is_off_unless_configured(tmp_path):
    store = Store(f"sqlite:///{(tmp_path / 'n.db').as_posix()}")
    Notifier(store, "").send("로컬 수신함에만 저장")
    assert [n.content for n in store.notifications()] == ["로컬 수신함에만 저장"]
    Notifier(store, "http://127.0.0.1:1/unreachable").send("외부 전송 실패해도 계속")   # 예외 없이 끝나야 한다
    assert len(store.notifications()) == 2
    store.dispose()


# ---- 프로브(실제 포털) ----


def test_probe_sees_block_and_restore_from_the_attacker_source(live_portal, state):
    from nobugs_portal.models import BlockedIp

    probe = LoopbackProbe(live_portal)
    assert probe.is_blocked("127.0.0.2") is False and probe.is_reachable("127.0.0.2") is True
    with state.db.session() as db:
        db.add(BlockedIp(ip="127.0.0.2"))
        db.commit()
    assert probe.is_blocked("127.0.0.2") is True and probe.is_reachable("127.0.0.2") is False
    assert probe.is_reachable("127.0.0.3") is True        # 다른 출발지는 영향 없음


def test_probe_cannot_verify_non_loopback_sources_or_dead_servers():
    assert LoopbackProbe("http://127.0.0.1:5100").is_blocked("203.0.113.9") is None
    assert LoopbackProbe("http://127.0.0.1:1", timeout=0.3).is_blocked("127.0.0.2") is None
    assert NullProbe().is_blocked("127.0.0.2") is None and NullProbe().is_reachable("127.0.0.2") is None


# ---- 웹훅 앱 ----


@pytest.fixture
def web(tmp_path):
    store = Store(f"sqlite:///{(tmp_path / 'app.db').as_posix()}")
    portal = FakePortal()
    settings = EngineSettings(engine_key=ENGINE_KEY, default_dry_run=False, scheduler_enabled=False,
                              protected_cidrs=("127.0.0.1/32",))
    engine = Engine(settings, store, portal, FakeProbe(), Notifier(store))
    client = TestClient(create_engine_app(settings, engine=engine))
    yield type("Web", (), {"client": client, "store": store, "portal": portal, "engine": engine})
    store.dispose()


PAYLOAD = {"event_id": "ev-1", "case_id": "S1", "src_ip": "203.0.113.60", "username": "victim", "count": 10}


def hook(web, body=None, key=ENGINE_KEY):
    headers = {"X-Engine-Key": key} if key is not None else {}
    return web.client.post("/webhook/graylog", json=body or PAYLOAD, headers=headers)


def test_webhook_requires_the_engine_key(web):
    assert hook(web, key=None).status_code == 401
    assert hook(web, key="wrong").status_code == 401
    assert web.portal.calls == []


def test_webhook_runs_the_engine_and_returns_the_verdict(web):
    r = hook(web)
    assert r.status_code == 200 and r.json()["data"]["verdict"] == "responded"
    assert web.portal.blocked == {"203.0.113.60"}


def test_webhook_rejects_malformed_payloads_as_400(web):
    assert hook(web, {"case_id": "S1"}).status_code == 400
    assert hook(web, {**PAYLOAD, "event_id": ""}).status_code == 400
    assert hook(web, {**PAYLOAD, "src_ip": "x" * 100}).status_code == 400


def test_webhook_is_disabled_when_no_key_is_configured(tmp_path):
    store = Store(f"sqlite:///{(tmp_path / 'k.db').as_posix()}")
    settings = EngineSettings(engine_key="", scheduler_enabled=False)
    engine = Engine(settings, store, FakePortal(), FakeProbe(), Notifier(store))
    client = TestClient(create_engine_app(settings, engine=engine))
    assert client.post("/webhook/graylog", json=PAYLOAD, headers={"X-Engine-Key": ""}).status_code == 401
    store.dispose()


def test_ticket_endpoints_list_detail_and_404(web):
    ticket_id = hook(web).json()["data"]["ticket_id"]
    listing = web.client.get("/api/v1/tickets").json()["data"]["items"]
    assert [t["id"] for t in listing] == [ticket_id] and listing[0]["status"] == "verified"
    detail = web.client.get(f"/api/v1/tickets/{ticket_id}").json()["data"]
    assert detail["actions"][0]["result"] == "applied" and detail["actions"][0]["effect_verified"] is True
    assert web.client.get("/api/v1/tickets/T-00000000-0000").status_code == 404
    assert web.client.get("/api/v1/tickets?status=closed").json()["data"]["items"] == []


def test_closing_needs_the_key_and_a_restored_ticket(web):
    ticket_id = hook(web).json()["data"]["ticket_id"]
    assert web.client.post(f"/api/v1/tickets/{ticket_id}/close").status_code == 401
    r = web.client.post(f"/api/v1/tickets/{ticket_id}/close", headers={"X-Engine-Key": ENGINE_KEY})
    assert r.status_code == 409 and r.json()["error"]["code"] == "INVALID_TRANSITION"
    assert web.client.post("/api/v1/tickets/T-00000000-0000/close", headers={"X-Engine-Key": ENGINE_KEY}).status_code == 404


def test_notifications_endpoint_and_health(web):
    hook(web)
    items = web.client.get("/api/v1/notifications").json()["data"]["items"]
    assert len(items) == 1 and "조치 적용" in items[0]["content"]
    assert web.client.get("/api/v1/health").json()["data"]["status"] == "ok"


def test_dashboard_escapes_untrusted_values(web):
    hook(web, {**PAYLOAD, "event_id": "ev-x", "username": "<script>alert(1)</script>"})
    html = web.client.get("/").text
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_engine_app_has_no_docs_and_unknown_paths_are_404(web):
    assert web.client.get("/docs").status_code == 404 and web.client.get("/nope").status_code == 404


# ---- 스케줄러 ----


def test_scheduler_calls_release_periodically_and_survives_errors():
    calls = []

    class Flaky:
        def release_due(self):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("일시 오류")

    scheduler = Scheduler(Flaky(), 0.05)
    scheduler.start()
    time.sleep(0.4)
    scheduler.stop()
    assert len(calls) >= 3          # 첫 호출에서 예외가 나도 계속 돈다


# ---- 실제 포털과의 통합 ----


@pytest.fixture
def live_control(state):
    from dataclasses import replace

    from nobugs_portal.control import create_control_app

    app = create_control_app(state=type(state)(settings=replace(state.settings, response_allowed_cidrs=("127.0.0.0/8",)),
                                               db=state.db, events=state.events))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{server.servers[0].sockets[0].getsockname()[1]}"
    server.should_exit = True
    thread.join(timeout=5)


def test_full_cycle_against_real_portal_processes(tmp_path, live_portal, live_control):
    """탐지 → 차단(실제 포털 403) → 효과 확인 → TTL 후 자동 원복(실제 포털 200) → 티켓 restored."""
    from nobugs_tools.attacks import bound_opener

    store = Store(f"sqlite:///{(tmp_path / 'full.db').as_posix()}")
    clock_offset = [0]

    def clock():
        import datetime as dt
        return utcnow() + dt.timedelta(seconds=clock_offset[0])

    settings = EngineSettings(default_dry_run=False, release_ttl_seconds=90, scheduler_enabled=False,
                              protected_cidrs=("127.0.0.1/32",))
    engine = Engine(settings, store, HttpPortalControl(live_control, KEY), LoopbackProbe(live_portal),
                    Notifier(store), clock)

    def portal_status(source):
        import urllib.error
        try:
            return bound_opener(source).open(live_portal + "/api/v1/health").status
        except urllib.error.HTTPError as exc:
            return exc.code

    assert portal_status("127.0.0.2") == 200
    result = engine.handle(Detection(event_id="ev-1", case_id="S1", src_ip="127.0.0.2", username="victim"))
    assert result["verdict"] == "responded" and result["status"] == "verified"
    assert portal_status("127.0.0.2") == 403 and portal_status("127.0.0.3") == 200    # 공격 출발지만 막힌다
    assert engine.release_due() == []
    clock_offset[0] = 100
    assert engine.release_due() == [result["ticket_id"]]
    assert portal_status("127.0.0.2") == 200
    with store.session() as s:
        ticket = store.get(s, result["ticket_id"])
        actions = store.actions_of(s, result["ticket_id"])
    assert ticket.status == "restored" and [a.kind for a in actions] == ["ip_block", "ip_release"]
    assert actions[1].effect_verified is True
    store.dispose()
