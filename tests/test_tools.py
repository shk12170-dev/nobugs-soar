"""설치·관제 설정·공격 재현 도구의 시험."""
import json
import threading
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import uvicorn
from conftest import PASSWORD, read_events

from nobugs_portal.app import create_public_app
from nobugs_tools import attacks, definitions, graylog, make_env

# ---- 탐지 정의 ----


def test_s1_definition_encodes_the_spec_thresholds():
    d = definitions.s1_login_bruteforce()
    config = d["config"]
    assert config["conditions"]["expression"]["right"]["value"] == 8           # 9회 이상 = count() > 8
    assert config["search_within_ms"] == 30 * 60_000 and config["execute_every_ms"] == 60_000
    assert config["group_by"] == ["username", "src_ip"] and d["key_spec"] == ["username", "src_ip"]
    assert config["series"] == [{"id": "count()", "type": "count"}]
    assert d["notification_settings"]["grace_period_ms"] == 30 * 60_000


def test_s1_query_counts_only_failed_logins_not_rate_limited_ones():
    query = definitions.s1_login_bruteforce()["config"]["query"]
    assert "rule:login-bruteforce" in query and "status:401" in query and "429" not in query


def test_s1_event_fields_carry_what_the_response_engine_needs():
    fields = definitions.s1_login_bruteforce()["field_spec"]
    assert set(fields) == {"username", "src_ip", "case_id"}
    assert fields["case_id"]["providers"][0]["template"] == "S1"
    assert fields["src_ip"]["providers"][0]["template"] == "${source.src_ip}"


def test_stream_and_notifications_are_configurable():
    d = definitions.s1_login_bruteforce("stream-x", ["n1", "n2"])
    assert d["config"]["streams"] == ["stream-x"]
    assert [n["notification_id"] for n in d["notifications"]] == ["n1", "n2"]


def test_definition_rule_names_match_what_the_portal_emits(tmp_path):
    from nobugs_portal.config import Settings
    from nobugs_portal.events import RULES

    assert "rule:login-bruteforce" in definitions.s1_login_bruteforce()["config"]["query"]
    assert RULES["auth.login_failed"] == "login-bruteforce"
    assert Settings().asset_id  # 이벤트 필드 이름은 이벤트 모듈과 같은 값을 쓴다


def test_s4_needs_both_failure_and_success_and_a_count_of_six():
    config = definitions.s4_login_failure_then_success()["config"]
    assert config["group_by"] == ["username", "src_ip"]
    assert "login-bruteforce" in config["query"] and "login-success" in config["query"]
    cond = config["conditions"]["expression"]
    assert cond["left"]["right"]["value"] == 5 and cond["right"]["right"]["value"] == 2   # 합 6회 이상, 2종류


def test_s7_needs_tamper_signal_and_visitor_access_together():
    d = definitions.s7_tamper_then_access()
    config = d["config"]
    assert config["group_by"] == ["asset_id", "file_key"]
    assert "tamper-signal" in config["query"] and "file-access" in config["query"] and "200" in config["query"]
    assert config["conditions"]["expression"]["right"]["right"]["value"] == 2
    assert config["search_within_ms"] == 10 * 60_000
    assert set(d["field_spec"]) >= {"asset_id", "file_key", "case_id"}
    assert d["field_spec"]["case_id"]["providers"][0]["template"] == "S7"


def test_s7_does_not_require_src_ip_since_tamper_signal_alerts_lack_it():
    # tamper-signal 메시지에는 src_ip가 없다. require_values=True면 Graylog가 필드 계산에 실패해
    # 이벤트 알림 자체가 조용히 멈춘다(S1 등 src_ip가 항상 있는 케이스는 그대로 필수로 둔다).
    assert definitions.s7_tamper_then_access()["field_spec"]["src_ip"]["providers"][0]["require_values"] is False
    assert definitions.s1_login_bruteforce()["field_spec"]["src_ip"]["providers"][0]["require_values"] is True


def test_s8_needs_scan_and_login_failure_together():
    config = definitions.s8_scan_then_login()["config"]
    assert config["group_by"] == ["src_ip"]
    assert "web-scan" in config["query"] and "login-bruteforce" in config["query"]
    assert config["conditions"]["expression"]["right"]["right"]["value"] == 2


def test_s10_adds_the_boundary_signal_on_top_of_s8():
    config = definitions.s10_three_layer()["config"]
    assert all(term in config["query"] for term in ("web-scan", "login-bruteforce", "boundary-block"))
    assert config["conditions"]["expression"]["right"]["right"]["value"] == 3              # 세 종류 모두


def test_s12_is_a_simple_request_count_threshold():
    config = definitions.s12_request_flood()["config"]
    assert config["query"] == "rule:request-observed" and config["group_by"] == ["src_ip"]
    assert config["conditions"]["expression"]["right"]["value"] == 94
    assert config["search_within_ms"] == 60_000


def test_engine_notification_body_carries_asset_id_and_file_key():
    # S7은 asset_id/file_key로 조치한다 - 본문에 없으면 엔진이 빈 asset_id를 받아 조용히 거부한다.
    body = definitions.engine_notification("http://engine/webhook/graylog", "key", live=True)["config"][
        "body_template"]
    assert "${event.fields.asset_id}" in body and "${event.fields.file_key}" in body


def test_engine_notification_dry_run_flag_follows_live_argument():
    assert '"dry_run":false' in definitions.engine_notification("http://x", "k", live=True)["config"][
        "body_template"]
    assert '"dry_run":true' in definitions.engine_notification("http://x", "k", live=False)["config"][
        "body_template"]


def test_n8n_relay_notification_uses_its_own_header_and_the_same_body_as_the_engine():
    n8n = definitions.n8n_relay_notification("http://n8n/webhook/s1", "nkey", live=True)
    assert n8n["config"]["url"] == "http://n8n/webhook/s1"
    assert n8n["config"]["headers"] == "X-N8N-Webhook-Key: nkey"
    assert n8n["config"]["body_template"] == definitions.engine_notification("http://x", "k", live=True)[
        "config"]["body_template"]


def test_all_definitions_cover_every_case_and_build_without_error():
    for case, build in definitions.ALL_DEFINITIONS.items():
        d = build()
        assert d["field_spec"]["case_id"]["providers"][0]["template"] == case
    assert set(definitions.ALL_DEFINITIONS) == {"S1", "S4", "S7", "S8", "S10", "S12"}


# ---- .env 생성 ----


def test_make_env_writes_random_secrets_and_a_matching_hash(tmp_path):
    import hashlib

    path = tmp_path / ".env"
    assert make_env.main(["--path", str(path)]) == 0
    values = dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines())
    assert hashlib.sha256(values["NB_GRAYLOG_ADMIN_PASSWORD"].encode()).hexdigest() == values["NB_GRAYLOG_ROOT_SHA2"]
    assert len(values["NB_GRAYLOG_SECRET"]) >= 64 and values["NB_OPENSEARCH_PASSWORD"].startswith("Os!")


def test_make_env_does_not_overwrite_unless_forced(tmp_path, capsys):
    path = tmp_path / ".env"
    make_env.main(["--path", str(path)])
    first = path.read_text(encoding="utf-8")
    make_env.main(["--path", str(path)])
    assert path.read_text(encoding="utf-8") == first and "그대로 둡니다" in capsys.readouterr().out
    make_env.main(["--path", str(path), "--force"])
    assert path.read_text(encoding="utf-8") != first


def test_make_env_never_prints_secrets(tmp_path, capsys):
    path = tmp_path / ".env"
    make_env.main(["--path", str(path)])
    out = capsys.readouterr().out
    secrets_in_file = [v for v in dict(x.split("=", 1) for x in path.read_text(encoding="utf-8").splitlines()).values()
                       if len(v) > 12]
    assert not any(s in out for s in secrets_in_file)


# ---- Graylog 클라이언트(가짜 서버) ----


class FakeGraylog(BaseHTTPRequestHandler):
    inputs: list = []
    definitions: list = []
    notifications: list = []
    whitelist: list = []
    calls: list = []
    _notif_seq = 0

    def _send(self, body, status=200):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0) or b"null")

    def do_GET(self):  # noqa: N802
        type(self).calls.append(("GET", self.path, self.headers.get("X-Requested-By"), self.headers.get("Authorization")))
        if self.path.startswith("/api/system/lbstatus"):
            return self._send({})
        if self.path.startswith("/api/system/inputs"):
            return self._send({"inputs": type(self).inputs})
        if self.path.startswith("/api/events/definitions"):
            return self._send({"event_definitions": type(self).definitions})
        if self.path.startswith("/api/events/notifications"):
            return self._send({"notifications": type(self).notifications})
        if self.path.startswith("/api/system/urlwhitelist"):
            return self._send({"entries": type(self).whitelist, "disabled": False})
        self._send({}, 404)

    def do_POST(self):  # noqa: N802
        body = self._body()
        type(self).calls.append(("POST", self.path, body))
        if self.path == "/api/system/inputs":
            type(self).inputs.append({"title": body["title"]})
            return self._send({"id": "i"}, 201)
        if self.path.startswith("/api/events/definitions"):
            type(self).definitions.append({"id": "def-1", "title": body["title"]})
            return self._send({"id": "def-1"})
        if self.path.startswith("/api/events/notifications"):
            type(self)._notif_seq += 1
            notif_id = f"notif-{type(self)._notif_seq}"
            type(self).notifications.append({"id": notif_id, "title": body["title"]})
            return self._send({"id": notif_id}, 201)
        self._send({}, 404)

    def do_PUT(self):  # noqa: N802
        body = self._body()
        type(self).calls.append(("PUT", self.path, body))
        if self.path.startswith("/api/system/urlwhitelist"):
            type(self).whitelist = body.get("entries", [])
        self._send({})

    def do_DELETE(self):  # noqa: N802
        type(self).calls.append(("DELETE", self.path))
        type(self).notifications = [n for n in type(self).notifications if not self.path.endswith(n["id"])]
        self._send({})

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_graylog():
    FakeGraylog.inputs, FakeGraylog.definitions, FakeGraylog.calls = [], [], []
    FakeGraylog.notifications, FakeGraylog.whitelist, FakeGraylog._notif_seq = [], [], 0
    server = HTTPServer(("127.0.0.1", 0), FakeGraylog)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield graylog.GraylogClient(f"http://127.0.0.1:{server.server_port}", "pw")
    server.shutdown()


def test_ensure_inputs_is_idempotent(fake_graylog):
    assert fake_graylog.ensure_gelf_inputs() == ["portal GELF UDP", "portal GELF TCP"]
    assert fake_graylog.ensure_gelf_inputs() == []


def test_ensure_event_definition_creates_then_updates(fake_graylog):
    definition = definitions.s1_login_bruteforce()
    assert fake_graylog.ensure_event_definition(definition) == ("def-1", True)
    assert fake_graylog.ensure_event_definition(definition) == ("def-1", False)
    methods = [c[0] for c in FakeGraylog.calls if "/events/definitions" in c[1] and c[0] != "GET"]
    assert methods == ["POST", "PUT"]


def test_setup_routes_only_s1_through_n8n_when_an_n8n_url_is_given(fake_graylog):
    graylog.setup(fake_graylog, "http://engine/webhook/graylog", "ekey", live=True,
                  n8n_url="http://n8n/webhook/s1", n8n_key="nkey")
    posted = {c[2]["title"]: c[2] for c in FakeGraylog.calls if c[0] == "POST" and "/events/definitions" in c[1]}
    s1_notifications = posted["S1 로그인 무차별 대입 (username+src_ip)"]["notifications"]
    other_notifications = posted["S4 로그인 실패 뒤 성공 (username+src_ip)"]["notifications"]
    assert len(s1_notifications) == 1 and len(other_notifications) == 1
    assert s1_notifications != other_notifications          # S1은 n8n 알림, 나머지는 엔진 알림(서로 다른 id)
    notif_titles = {n["title"] for n in FakeGraylog.notifications}
    assert "nobugs n8n 웹훅(S1)" in notif_titles and "nobugs 대응 엔진 웹훅" in notif_titles


def test_setup_sends_s1_through_the_engine_when_no_n8n_url_is_given(fake_graylog):
    graylog.setup(fake_graylog, "http://engine/webhook/graylog", "ekey", live=True)
    notif_titles = {n["title"] for n in FakeGraylog.notifications}
    assert notif_titles == {"nobugs 대응 엔진 웹훅"}


def test_client_sends_basic_auth_and_required_header(fake_graylog):
    fake_graylog.ensure_gelf_inputs()
    method, _path, header, auth = FakeGraylog.calls[0]
    assert header == "nobugs-tools" and auth.startswith("Basic ")


def test_client_raises_a_readable_error_on_http_failure(fake_graylog):
    with pytest.raises(graylog.GraylogError, match="404"):
        fake_graylog.call("GET", "/api/nope")


def test_client_from_env_requires_the_admin_password():
    with pytest.raises(graylog.GraylogError, match="make_env"):
        graylog.client_from_env({})


def test_load_env_reads_file_without_overriding_real_environment(tmp_path, monkeypatch):
    file = tmp_path / ".env"
    file.write_text("NB_A=from-file\nNB_B=from-file\n# comment\n", encoding="utf-8")
    monkeypatch.setenv("NB_B", "from-env")
    env = graylog.load_env(file)
    assert env["NB_A"] == "from-file" and env["NB_B"] == "from-env"


# ---- 공격 재현(실제 서버) ----


@pytest.fixture
def live_portal_dist(state, tmp_path):
    """실제 소켓으로 도는 일반 포털, 프론트 루트는 임시 폴더(S7 변조 시험이 실제 저장소 파일을 건드리지 않도록)."""
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html>home</html>", encoding="utf-8")
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
    yield f"http://127.0.0.1:{port}", dist
    server.should_exit = True
    thread.join(timeout=5)


def test_s7_attack_overwrites_the_file_and_records_a_visitor_access(live_portal_dist, settings):
    base_url, dist = live_portal_dist
    out = attacks.s7_deface(base_url, str(dist), "index.html", source="127.0.0.7")
    assert out["written"] is True and out["visit_status"] == 200
    assert "defaced" in (dist / "index.html").read_text(encoding="utf-8")
    access = [e for e in read_events(settings) if e["event_type"] == "web.file_access" and e["src_ip"] == "127.0.0.7"]
    assert len(access) == 1 and access[0]["file_key"] == "index.html"


def test_s7_attack_refuses_a_missing_file(live_portal_dist):
    base_url, dist = live_portal_dist
    with pytest.raises(ValueError, match="대상 파일이 없습니다"):
        attacks.s7_deface(base_url, str(dist), "nope.html", source="127.0.0.7")


def test_s1_attack_sends_failed_logins_seen_as_the_chosen_source(live_portal, settings):
    statuses = attacks.s1_login_bruteforce(live_portal, username="citizen1", count=10, source="127.0.0.2", interval=0)
    assert statuses == [401] * 10
    failures = [e for e in read_events(settings) if e["event_type"] == "auth.login_failed"]
    assert len(failures) == 10
    assert {e["src_ip"] for e in failures} == {"127.0.0.2"} and {e["rule"] for e in failures} == {"login-bruteforce"}
    assert {e["username"] for e in failures} == {"citizen1"} and {e["status"] for e in failures} == {401}


def test_s1_attack_leaves_the_real_password_working_from_another_source(live_portal):
    attacks.s1_login_bruteforce(live_portal, username="citizen1", count=3, source="127.0.0.2", interval=0)
    opener = attacks.bound_opener("127.0.0.1")
    _, me = attacks._call(opener, live_portal, "GET", "/api/v1/auth/me")  # noqa: SLF001
    status, _ = attacks._call(opener, live_portal, "POST", "/api/v1/auth/login",  # noqa: SLF001
                              me["data"]["csrf_token"], {"username": "citizen1", "password": PASSWORD})
    assert status == 200


def test_attack_tool_refuses_non_loopback_targets_and_sources():
    with pytest.raises(ValueError, match="루프백"):
        attacks.s1_login_bruteforce("http://203.0.113.10:5100", username="x", count=1)
    with pytest.raises(ValueError, match="루프백"):
        attacks.bound_opener("203.0.113.9")


def test_s4_attack_logs_failures_then_a_success_for_the_test_account(live_portal, settings):
    statuses = attacks.s4_failure_then_success(live_portal, username="zz_victim", password=PASSWORD, failures=3,
                                               source="127.0.0.3", interval=0)
    assert statuses == [401, 401, 401, 200]
    events = read_events(settings)
    failures = [e for e in events if e["event_type"] == "auth.login_failed" and e["username"] == "zz_victim"]
    success = [e for e in events if e["event_type"] == "auth.login_succeeded" and e["username"] == "zz_victim"]
    assert len(failures) == 3 and len(success) == 1
    assert {e["src_ip"] for e in failures + success} == {"127.0.0.3"}


def test_s8_attack_produces_not_found_scans_then_login_failures(live_portal, settings):
    out = attacks.s8_scan_then_login(live_portal, scans=4, logins=2, source="127.0.0.4", interval=0)
    assert out["scan"] == [404, 404, 404, 404] and out["login"] == [401, 401]
    events = read_events(settings)
    scans = [e for e in events if e["event_type"] == "web.not_found" and e["src_ip"] == "127.0.0.4"]
    assert len(scans) == 4 and {e["rule"] for e in scans} == {"web-scan"}


def test_s10_attack_adds_one_boundary_signal_on_top_of_the_scan(live_portal, settings, monkeypatch):
    sent = []
    monkeypatch.setattr(attacks.socket.socket, "sendto", lambda self, data, addr: sent.append((data, addr)))
    out = attacks.s10_three_layer(live_portal, source="127.0.0.5", gelf_port=19999, scans=4, logins=2, interval=0)
    assert out["boundary_signal"] == 1 and len(sent) == 1
    assert sent[0][1] == ("127.0.0.1", 19999)
    payload = json.loads(sent[0][0])
    assert payload["_rule"] == "boundary-block" and payload["_src_ip"] == "127.0.0.5"


def test_s10_boundary_signal_refuses_non_loopback_addresses():
    with pytest.raises(ValueError, match="루프백"):
        attacks.boundary_signal("203.0.113.9")


def test_s12_attack_sends_repeated_lightweight_health_checks(live_portal):
    statuses = attacks.s12_request_burst(live_portal, requests=5, source="127.0.0.6")
    assert statuses == [200] * 5
