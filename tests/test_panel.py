"""실습 제어판(panel.py) 시험: 6단계 환산, 페이지 뼈대, 상태·공격·닫기 핸들러."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from nobugs_tools import panel


def _steps(ticket: dict) -> list[str]:
    return [s["state"] for s in panel.ticket_steps(ticket)]


def test_open_ticket_without_actions_waits_at_response_step():
    # open·액션 없음 → ①②는 완료, ③ 조치가 진행 중, 나머지는 대기
    assert _steps({"status": "open", "actions": []}) == ["done", "done", "active", "pending", "pending", "pending"]


def test_responding_with_applied_action_advances_to_effect_step():
    t = {"status": "responding", "actions": [{"kind": "ip_block", "applied_verified": True, "effect_verified": None}]}
    assert _steps(t) == ["done", "done", "done", "done", "active", "pending"]


def test_verified_ticket_waits_at_restore_step():
    t = {"status": "verified", "actions": [{"kind": "ip_block", "applied_verified": True, "effect_verified": True}]}
    assert _steps(t) == ["done", "done", "done", "done", "done", "active"]


def test_restored_with_release_action_completes_all_six_steps():
    t = {"status": "restored", "actions": [
        {"kind": "ip_block", "applied_verified": True, "effect_verified": True},
        {"kind": "ip_release", "applied_verified": True, "effect_verified": True}]}
    assert _steps(t) == ["done"] * 6


def test_s7_restore_counts_as_recovery_even_without_a_release_action():
    # S7은 복구·격리 자체가 원복이라 해제(release) 액션이 없다 → 상태 restored만으로 ⑥ 완료
    t = {"status": "restored", "actions": [
        {"kind": "file_restore", "applied_verified": True, "effect_verified": True, "active": False}]}
    assert _steps(t)[5] == "done"


def test_closed_ticket_has_all_steps_done():
    assert _steps({"status": "closed", "actions": []}) == ["done"] * 6


def test_render_page_lists_every_attack_button_and_link():
    html = panel.render_page({"민원 포털": "http://127.0.0.1:5100", "Graylog": "http://127.0.0.1:9100"})
    for case in panel.ATTACKS:
        assert f"data-case='{case}'" in html
    assert "http://127.0.0.1:9100" in html
    assert "/api/state" in html


class _StubClient:
    def __init__(self, tickets):
        self._tickets = tickets
        self.closed: list[tuple[str, str]] = []

    def tickets(self, limit=8):
        return self._tickets[:limit]

    def close(self, ticket_id, note):
        self.closed.append((ticket_id, note))
        return 200, {}


@pytest.fixture()
def server(monkeypatch):
    client = _StubClient([{"id": "T-1", "case_id": "S1", "status": "open", "src_ip": "127.44.11.1",
                           "username": "zz", "actions": []}])
    monkeypatch.setattr(panel, "run_attack", lambda *a, **k: "공격 재현함")
    handler = panel.make_handler(client, {"엔진 티켓": "http://x/"}, "http://127.0.0.1:5100", "web/dist", 12301, 8)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base, client
    httpd.shutdown()
    httpd.server_close()


def _post(base: str, path: str, obj: dict) -> tuple[int, dict]:
    req = urllib.request.Request(base + path, method="POST", data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_state_endpoint_attaches_six_steps(server):
    base, _ = server
    with urllib.request.urlopen(base + "/api/state") as r:
        data = json.loads(r.read())
    assert len(data["tickets"]) == 1
    assert len(data["tickets"][0]["steps"]) == 6


def test_attack_endpoint_runs_a_known_case(server):
    base, _ = server
    status, body = _post(base, "/api/attack", {"case": "s1"})
    assert status == 200 and body["message"] == "공격 재현함"


def test_attack_endpoint_rejects_an_unknown_case(server):
    base, _ = server
    status, body = _post(base, "/api/attack", {"case": "nope"})
    assert status == 400


def test_close_endpoint_forwards_to_the_engine(server):
    base, client = server
    status, body = _post(base, "/api/close", {"id": "T-1"})
    assert status == 200 and client.closed and client.closed[0][0] == "T-1"


def test_close_endpoint_needs_a_ticket_id(server):
    base, _ = server
    status, _body = _post(base, "/api/close", {})
    assert status == 400


def test_engine_client_sends_the_key_on_reads(monkeypatch):
    # 엔진이 조회 인증(NB_ENGINE_READ_AUTH)을 켜도 제어판이 티켓을 읽을 수 있어야 한다
    seen: list[dict] = []

    def fake_urlopen(req, timeout=None):
        seen.append(dict(req.header_items()))
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(panel.urllib.request, "urlopen", fake_urlopen)
    assert panel.EngineClient("http://127.0.0.1:1", "ek").tickets() == []
    assert seen and seen[0].get("X-engine-key") == "ek"
    seen.clear()
    panel.EngineClient("http://127.0.0.1:1", "").tickets()
    assert "X-engine-key" not in seen[0]
