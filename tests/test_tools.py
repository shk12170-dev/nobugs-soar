"""설치·관제 설정·공격 재현 도구의 시험."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from conftest import PASSWORD, read_events

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
    calls: list = []

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
        if self.path.startswith("/api/system/inputs"):
            return self._send({"inputs": type(self).inputs})
        if self.path.startswith("/api/events/definitions"):
            return self._send({"event_definitions": type(self).definitions})
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
        self._send({}, 404)

    def do_PUT(self):  # noqa: N802
        type(self).calls.append(("PUT", self.path, self._body()))
        self._send({})

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_graylog():
    FakeGraylog.inputs, FakeGraylog.definitions, FakeGraylog.calls = [], [], []
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
