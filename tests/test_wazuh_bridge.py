"""Wazuh -> Graylog 다리: 경보 줄 읽기(회전 대응), 웹 루트 밑 syscheck만 고르기, 기준본과 다를 때만 전달."""
import json

import pytest

from nobugs_portal import baseline
from nobugs_tools import wazuh_bridge

PREFIX = "/nobugs/web-root"


def syscheck_alert(path: str, event: str = "modified") -> dict:
    return {"rule": {"id": "550", "level": 7, "groups": ["ossec", "syscheck", event]},
            "syscheck": {"path": path, "event": event}, "agent": {"name": "nobugs-portal"}}


def test_file_key_of_extracts_the_relative_path_under_the_prefix():
    alert = syscheck_alert(f"{PREFIX}/index.html")
    assert wazuh_bridge.file_key_of(alert, PREFIX) == "index.html"


def test_file_key_of_handles_nested_paths():
    alert = syscheck_alert(f"{PREFIX}/assets/app.js")
    assert wazuh_bridge.file_key_of(alert, PREFIX) == "assets/app.js"


def test_file_key_of_ignores_paths_outside_the_prefix():
    alert = syscheck_alert("/etc/passwd")
    assert wazuh_bridge.file_key_of(alert, PREFIX) is None


def test_file_key_of_ignores_non_syscheck_alerts():
    alert = {"rule": {"groups": ["ossec", "pam"]}, "syscheck": {"path": f"{PREFIX}/index.html"}}
    assert wazuh_bridge.file_key_of(alert, PREFIX) is None


def test_file_key_of_ignores_events_that_are_not_file_changes():
    alert = syscheck_alert(f"{PREFIX}/index.html", event="readded")
    assert wazuh_bridge.file_key_of(alert, PREFIX) is None


# ---- AlertTailer: 줄 단위로 따라 읽기, 회전 대응 ----


def test_tailer_reads_only_new_complete_lines(tmp_path):
    log = tmp_path / "alerts.json"
    log.write_text(json.dumps({"a": 1}) + "\n", encoding="utf-8")
    tailer = wazuh_bridge.AlertTailer(log)
    assert tailer.poll() == [{"a": 1}]
    assert tailer.poll() == []     # 다시 불러도 같은 줄을 또 주지 않는다
    with log.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"a": 2}))   # 줄바꿈 없이 쓰는 중(아직 다 안 써짐)
    assert tailer.poll() == []
    with log.open("a", encoding="utf-8") as f:
        f.write("\n")
    assert tailer.poll() == [{"a": 2}]


def test_tailer_skips_malformed_lines(tmp_path):
    log = tmp_path / "alerts.json"
    log.write_text("not json\n" + json.dumps({"ok": True}) + "\n", encoding="utf-8")
    assert wazuh_bridge.AlertTailer(log).poll() == [{"ok": True}]


def test_tailer_restarts_from_the_top_after_rotation(tmp_path):
    log = tmp_path / "alerts.json"
    log.write_text(json.dumps({"n": 1}) + "\n" + json.dumps({"n": 2}) + "\n", encoding="utf-8")
    tailer = wazuh_bridge.AlertTailer(log)
    assert tailer.poll() == [{"n": 1}, {"n": 2}]
    log.write_text(json.dumps({"n": 99}) + "\n", encoding="utf-8")   # 회전: 새 파일이 더 작다
    assert tailer.poll() == [{"n": 99}]


def test_tailer_on_a_missing_file_is_empty(tmp_path):
    assert wazuh_bridge.AlertTailer(tmp_path / "nope.json").poll() == []


# ---- bridge_once: 기준본과 실제로 다를 때만 전달 ----


@pytest.fixture
def web(tmp_path):
    root = tmp_path / "web"
    root.mkdir()
    (root / "index.html").write_text("<html>home</html>", encoding="utf-8")
    return root


@pytest.fixture
def base(tmp_path, web):
    b = tmp_path / "baseline"
    baseline.snapshot(web, b)
    return b


class FakeTailer:
    def __init__(self, batches):
        self.batches = list(batches)

    def poll(self):
        return self.batches.pop(0) if self.batches else []


def test_bridge_forwards_only_when_the_file_actually_differs_from_baseline(web, base):
    (web / "index.html").write_text("<html>defaced</html>", encoding="utf-8")
    tailer = FakeTailer([[syscheck_alert(f"{PREFIX}/index.html")]])
    sent = []
    forwarded = wazuh_bridge.bridge_once(tailer, PREFIX, web, base, sent.append)
    assert forwarded == ["index.html"] and sent == ["index.html"]


def test_bridge_does_not_forward_when_content_already_matches_baseline(web, base):
    tailer = FakeTailer([[syscheck_alert(f"{PREFIX}/index.html")]])   # 알림은 왔지만 내용은 기준본과 같음
    sent = []
    assert wazuh_bridge.bridge_once(tailer, PREFIX, web, base, sent.append) == []
    assert sent == []


def test_bridge_ignores_alerts_outside_the_web_root(web, base):
    tailer = FakeTailer([[syscheck_alert("/etc/shadow")]])
    sent = []
    assert wazuh_bridge.bridge_once(tailer, PREFIX, web, base, sent.append) == []
    assert sent == []


def test_bridge_handles_several_alerts_in_one_poll(web, base):
    (web / "index.html").write_text("<html>defaced</html>", encoding="utf-8")
    (web / "assets").mkdir()
    (web / "assets" / "app.js").write_text("evil()", encoding="utf-8")
    tailer = FakeTailer([[syscheck_alert(f"{PREFIX}/index.html"), syscheck_alert(f"{PREFIX}/assets/app.js")]])
    sent = []
    forwarded = wazuh_bridge.bridge_once(tailer, PREFIX, web, base, sent.append)
    assert sorted(forwarded) == ["assets/app.js", "index.html"]


# ---- GELF 전송: 형식만 확인(실제 소켓으로) ----


def test_gelf_sender_sends_the_expected_fields(tmp_path):
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(2)
    port = sock.getsockname()[1]
    send = wazuh_bridge.make_gelf_sender("127.0.0.1", port, "nobugs-portal")
    send("index.html")
    data, _ = sock.recvfrom(4096)
    payload = json.loads(data)
    assert payload["_rule"] == "tamper-signal" and payload["_asset_id"] == "nobugs-portal"
    assert payload["_file_key"] == "index.html" and payload["_event_type"] == "tamper.signal"
    sock.close()
