"""Graylog -> 엔진 알림 연결 도구의 시험."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from nobugs_tools import definitions, graylog, make_env


def test_engine_notification_body_carries_every_field_the_engine_needs():
    n = definitions.engine_notification("http://host.docker.internal:5200/webhook/graylog", "k-123")
    cfg = n["config"]
    assert cfg["url"].endswith("/webhook/graylog") and cfg["method"] == "POST" and cfg["content_type"] == "JSON"
    assert cfg["headers"] == "X-Engine-Key: k-123"
    for needed in ("event_id", "case_id", "src_ip", "username", "condition_met_at", "detected_at"):
        assert f'"{needed}"' in cfg["body_template"]
    json.loads(cfg["body_template"].replace("${event.id}", "x").replace("${event.fields.case_id}", "S1")
               .replace("${event.fields.src_ip}", "1.2.3.4").replace("${event.fields.username}", "u")
               .replace("${event.timestamp}", "t").replace("${event.timestamp_processing}", "t"))   # 올바른 JSON 모양


def test_notification_defaults_to_dry_run_and_live_flag_switches_it():
    assert '"dry_run":true' in definitions.engine_notification("http://x", "k")["config"]["body_template"]
    assert '"dry_run":false' in definitions.engine_notification("http://x", "k", live=True)["config"]["body_template"]


def test_add_missing_appends_only_new_keys_and_keeps_existing_values(tmp_path):
    path = tmp_path / ".env"
    path.write_text("NB_GRAYLOG_SECRET=keep-me\nNB_GRAYLOG_ADMIN_PASSWORD=also-keep\n", encoding="utf-8")
    added = make_env.add_missing(path)
    text = path.read_text(encoding="utf-8")
    assert "NB_GRAYLOG_SECRET=keep-me" in text and "NB_GRAYLOG_ADMIN_PASSWORD=also-keep" in text
    assert {"NB_ENGINE_KEY", "NB_RESPONSE_API_KEY"} <= set(added) and "NB_GRAYLOG_SECRET" not in added
    assert make_env.add_missing(path) == []        # 두 번째는 아무것도 하지 않는다


def test_engine_and_portal_keys_are_different_values():
    values = make_env.build_values()
    assert values["NB_ENGINE_KEY"] != values["NB_RESPONSE_API_KEY"] and len(values["NB_ENGINE_KEY"]) >= 24


class FakeGraylog(BaseHTTPRequestHandler):
    notifications: list = []
    allowlist: dict = {"entries": [], "disabled": False}
    definitions: list = []
    inputs: list = []
    log: list = []
    next_id: int = 0

    def _send(self, body, status=200):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return json.loads(self.rfile.read(n)) if n else None

    def do_GET(self):  # noqa: N802
        cls = type(self)
        if "urlwhitelist" in self.path:
            return self._send(cls.allowlist)
        if "events/notifications" in self.path:
            return self._send({"notifications": cls.notifications})
        if "events/definitions" in self.path:
            return self._send({"event_definitions": cls.definitions})
        if "system/inputs" in self.path:
            return self._send({"inputs": cls.inputs})
        self._send({}, 404)

    def do_PUT(self):  # noqa: N802
        cls = type(self)
        body = self._body()
        cls.log.append(("PUT", self.path))
        if "urlwhitelist" in self.path:
            cls.allowlist = body
        self._send({})

    def do_POST(self):  # noqa: N802
        cls = type(self)
        body = self._body()
        cls.log.append(("POST", self.path))
        if self.path.startswith("/api/events/notifications"):
            cls.next_id += 1
            item = {"id": f"n{cls.next_id}", "title": body["title"], "config": body["config"]}
            cls.notifications.append(item)
            return self._send({"id": item["id"]})
        if self.path.startswith("/api/events/definitions"):
            cls.definitions.append({"id": "d1", "title": body["title"], "notifications": body["notifications"]})
            return self._send({"id": "d1"})
        if self.path == "/api/system/inputs":
            cls.inputs.append({"title": body["title"]})
            return self._send({"id": "i"}, 201)
        self._send({}, 404)

    def do_DELETE(self):  # noqa: N802
        cls = type(self)
        cls.log.append(("DELETE", self.path))
        cls.notifications = [n for n in cls.notifications if not self.path.endswith(n["id"])]
        self._send({})

    def log_message(self, *args):
        pass


@pytest.fixture
def gl():
    FakeGraylog.notifications, FakeGraylog.definitions, FakeGraylog.inputs, FakeGraylog.log = [], [], [], []
    FakeGraylog.allowlist, FakeGraylog.next_id = {"entries": [], "disabled": False}, 0
    server = HTTPServer(("127.0.0.1", 0), FakeGraylog)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield graylog.GraylogClient(f"http://127.0.0.1:{server.server_port}", "pw")
    server.shutdown()


def test_allowlist_entry_is_added_once(gl):
    url = "http://host.docker.internal:5200/webhook/graylog"
    assert gl.ensure_allowlist(url) is True and gl.ensure_allowlist(url) is False
    assert [e["value"] for e in FakeGraylog.allowlist["entries"]] == [url]


def test_notification_is_replaced_not_duplicated(gl):
    n = definitions.engine_notification("http://x/webhook", "k")
    first = gl.ensure_notification(n)
    second = gl.ensure_notification(n)
    assert first != second and len(FakeGraylog.notifications) == 1
    assert ("DELETE", f"/api/events/notifications/{first}") in FakeGraylog.log


def test_setup_with_engine_url_attaches_the_notification_to_the_s1_definition(gl, capsys, monkeypatch):
    monkeypatch.setattr(gl, "wait_ready", lambda seconds=240: None)
    graylog.setup(gl, "http://host.docker.internal:5200/webhook/graylog", "engine-key", live=True)
    assert FakeGraylog.definitions[0]["notifications"] == [{"notification_id": FakeGraylog.notifications[0]["id"]}]
    assert '"dry_run":false' in FakeGraylog.notifications[0]["config"]["body_template"]
    assert "실제 조치" in capsys.readouterr().out


def test_setup_without_engine_url_leaves_definitions_unattached(gl, monkeypatch):
    monkeypatch.setattr(gl, "wait_ready", lambda seconds=240: None)
    graylog.setup(gl)
    assert FakeGraylog.definitions[0]["notifications"] == [] and FakeGraylog.notifications == []
