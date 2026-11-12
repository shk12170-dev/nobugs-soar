"""N회 반복 측정 도구의 시험. 공격은 실제 소켓으로 도는 가짜 포털에, 티켓 조회는 가짜 엔진 서버에 묻는다."""
import json
import threading
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import uvicorn

from nobugs_portal import baseline
from nobugs_portal.app import create_public_app
from nobugs_tools import measure

# ---- 가짜 엔진(티켓 조회만 흉내) ----


class FakeEngine(BaseHTTPRequestHandler):
    tickets: list = []

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/api/v1/tickets"):
            raw = json.dumps({"data": {"items": type(self).tickets}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_engine():
    FakeEngine.tickets = []
    server = HTTPServer(("127.0.0.1", 0), FakeEngine)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def ticket(case: str, group_key: str, status: str, created_at: str = "2030-01-01T00:00:00Z") -> dict:
    # created_at은 round 함수가 공격 직전에 잡는 since(지금)보다 미래로 둔다 - since 필터에 걸리지 않게.
    return {"case_id": case, "group_key": group_key, "status": status, "created_at": created_at}


# ---- poll_until / confirm_no_ticket ----


def test_poll_until_returns_the_ticket_once_it_reaches_a_terminal_status(fake_engine):
    FakeEngine.tickets = [ticket("S1", "a@1", "responding")]

    def flip_to_verified():
        time.sleep(0.2)
        FakeEngine.tickets = [ticket("S1", "a@1", "verified")]

    threading.Thread(target=flip_to_verified, daemon=True).start()
    found = measure.poll_until(fake_engine, "S1", "a@1", {"verified", "restored"}, timeout=5, interval=0.1)
    assert found is not None and found["status"] == "verified"


def test_poll_until_times_out_when_nothing_matches(fake_engine):
    FakeEngine.tickets = [ticket("S1", "other@2", "verified")]
    assert measure.poll_until(fake_engine, "S1", "a@1", {"verified"}, timeout=0.3, interval=0.1) is None


def test_confirm_no_ticket_is_true_when_nothing_ever_matches(fake_engine):
    FakeEngine.tickets = []
    assert measure.confirm_no_ticket(fake_engine, "S12", "127.0.0.5", wait=0.3, interval=0.1) is True


def test_confirm_no_ticket_is_false_once_a_matching_ticket_appears(fake_engine):
    FakeEngine.tickets = [ticket("S12", "127.0.0.5", "open")]
    assert measure.confirm_no_ticket(fake_engine, "S12", "127.0.0.5", wait=0.3, interval=0.1) is False


# ---- to_markdown ----


def test_to_markdown_lists_every_round():
    rows = {"S1": [measure.Round("S1", 1, "a@1", "verified", 1.5, True)]}
    table = measure.to_markdown(rows)
    assert "S1" in table and "verified" in table and "1.5" in table


# ---- 실제 포털 + 가짜 엔진으로 라운드 함수 시험 ----


@pytest.fixture
def live_portal(state):
    app = create_public_app(state=type(state)(settings=replace(state.settings, login_rate_limit=1000),
                                              db=state.db, events=state.events))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


def test_s1_round_reports_the_matching_ticket(live_portal, fake_engine):
    FakeEngine.tickets = [ticket("S1", "zz_measure_s1_0_1@127.21.0.1", "verified")]
    r = measure._s1_round(1, base=live_portal, engine=fake_engine, timeout=5)
    assert r.ok and r.status == "verified" and r.group_key == "zz_measure_s1_0_1@127.21.0.1"


def test_s12_round_reports_no_action_when_nothing_was_blocked(live_portal, fake_engine):
    r = measure._s12_round(1, base=live_portal, engine=fake_engine, wait=0.3)
    assert r.ok and r.status == "no_action"


def test_s4_round_registers_the_test_account_and_reports_the_ticket(live_portal, fake_engine):
    FakeEngine.tickets = [ticket("S4", "zz_measure_s4_0_1@127.22.0.1", "verified")]
    r = measure._s4_round(1, base=live_portal, engine=fake_engine, timeout=5)
    assert r.ok and r.status == "verified"


def test_register_test_account_does_not_fail_when_already_registered(live_portal):
    measure.register_test_account(live_portal, "zz_measure_dup", "a-long-enough-password")
    measure.register_test_account(live_portal, "zz_measure_dup", "a-long-enough-password")  # 재실행해도 괜찮다


@pytest.fixture
def live_portal_dist(state, tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html>home</html>", encoding="utf-8")
    base_dir = tmp_path / "baseline"
    baseline.snapshot(dist, base_dir)
    new_state = type(state)(settings=replace(state.settings, frontend_dist=str(dist)), db=state.db,
                            events=state.events)
    app = create_public_app(state=new_state)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}", dist, base_dir
    server.should_exit = True
    thread.join(timeout=5)


def test_s7_round_uses_the_baseline_file_for_the_round_number(live_portal_dist, fake_engine):
    base_url, dist, base_dir = live_portal_dist
    FakeEngine.tickets = [ticket("S7", "nobugs-portal@index.html", "restored")]
    r = measure._s7_round(1, base=base_url, engine=fake_engine, web_root=str(dist), baseline_dir=str(base_dir),
                          asset_id="nobugs-portal", timeout=5)
    assert r.ok and r.status == "restored" and r.group_key == "nobugs-portal@index.html"


def test_s7_round_skips_a_file_reused_inside_the_grace_period(live_portal_dist, fake_engine):
    # 기준본 파일이 1개뿐이라 2회차는 1회차와 같은 파일 - Graylog가 재알림하지 않으므로 timeout 대신 grace_skip
    base_url, dist, base_dir = live_portal_dist
    FakeEngine.tickets = [ticket("S7", "nobugs-portal@index.html", "restored")]
    kw = dict(base=base_url, engine=fake_engine, web_root=str(dist), baseline_dir=str(base_dir),
              asset_id="nobugs-portal", timeout=5)
    assert measure._s7_round(1, **kw).ok
    started = time.monotonic()
    r = measure._s7_round(2, **kw)
    assert not r.ok and r.status == "grace_skip" and "묵음" in r.detail
    assert time.monotonic() - started < 2      # 기다리지 않고 바로 넘어간다


def test_s7_round_waits_out_the_grace_period_when_asked(live_portal_dist, fake_engine):
    base_url, dist, base_dir = live_portal_dist
    FakeEngine.tickets = [ticket("S7", "nobugs-portal@index.html", "restored")]
    kw = dict(base=base_url, engine=fake_engine, web_root=str(dist), baseline_dir=str(base_dir),
              asset_id="nobugs-portal", timeout=5, grace_seconds=1.0, s7_wait_grace=True)
    assert measure._s7_round(1, **kw).ok
    started = time.monotonic()
    r = measure._s7_round(2, **kw)
    assert r.ok and r.status == "restored"
    assert time.monotonic() - started >= 0.5   # 묵음이 끝날 때까지 기다린 뒤 잰다


def test_s7_round_reports_missing_baseline_without_crashing(live_portal_dist, fake_engine, tmp_path):
    base_url, dist, _base_dir = live_portal_dist
    empty_baseline = tmp_path / "no-such-baseline"
    r = measure._s7_round(1, base=base_url, engine=fake_engine, web_root=str(dist), baseline_dir=str(empty_baseline),
                          asset_id="nobugs-portal", timeout=5)
    assert not r.ok and r.status == "no_baseline"


def test_measure_case_runs_the_requested_number_of_rounds(live_portal, fake_engine):
    rows = measure.measure_case("S12", 3, base=live_portal, engine=fake_engine, web_root="web/dist",
                                baseline_dir="instance/baseline", asset_id="nobugs-portal", gelf_port=12301,
                                wait=0.1)
    assert [r.round for r in rows] == [1, 2, 3]
    assert all(r.case == "S12" for r in rows)


def test_measure_case_records_a_round_as_an_error_instead_of_crashing_the_batch(fake_engine):
    # 포털 주소가 없어 공격 호출 자체가 예외를 던지는 상황을 흉내낸다(실제로는 429/차단된 IP로 겪은 문제).
    rows = measure.measure_case("S1", 2, base="http://127.0.0.1:1", engine=fake_engine, timeout=0.1)
    assert len(rows) == 2 and all(r.status == "error" and not r.ok for r in rows)


def test_ticket_reads_carry_the_engine_key(monkeypatch):
    # 엔진 조회 인증(NB_ENGINE_READ_AUTH)이 켜져 있어도 측정 도구가 티켓을 읽을 수 있어야 한다
    seen = []
    monkeypatch.setenv("NB_ENGINE_KEY", "ek-measure")
    measure._engine_key.cache_clear()
    monkeypatch.setattr(measure, "_engine_call",
                        lambda base, method, path, key="", body=None: seen.append(key) or {"data": {"items": []}})
    assert measure._tickets("http://127.0.0.1:1") == []
    assert seen == ["ek-measure"]
    measure._engine_key.cache_clear()
