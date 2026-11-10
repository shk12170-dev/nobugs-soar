"""S7 대응 API: 파일 상태 조회·복구·격리(실제 서버, 임시 웹 루트·기준본 사용)."""
from dataclasses import replace

import pytest
from conftest import Control, read_events

from nobugs_portal import baseline
from nobugs_portal.control import create_control_app


@pytest.fixture
def web(tmp_path):
    root = tmp_path / "dist"
    root.mkdir()
    (root / "index.html").write_text("<html>home</html>", encoding="utf-8")
    return root


@pytest.fixture
def s7_app(state, web, tmp_path):
    new_settings = replace(state.settings, frontend_dist=str(web), baseline_dir=str(tmp_path / "baseline"),
                           quarantine_dir=str(tmp_path / "quarantine"))
    new_state = type(state)(settings=new_settings, db=state.db, events=state.events)
    baseline.snapshot(web, new_settings.baseline_dir)
    return create_control_app(state=new_state)


@pytest.fixture
def s7(s7_app):
    return Control(s7_app)


def test_file_state_matches_baseline_before_any_tampering(s7):
    out = s7.get("/api/v1/response/files/index.html").json()["data"]
    assert out["matches_baseline"] is True and out["known_to_baseline"] is True


def test_file_state_reflects_tampering(s7, web):
    (web / "index.html").write_text("<html>defaced</html>", encoding="utf-8")
    out = s7.get("/api/v1/response/files/index.html").json()["data"]
    assert out["matches_baseline"] is False and out["known_to_baseline"] is True


def test_restore_puts_the_baseline_content_back_and_emits_an_event(s7, web, settings):
    (web / "index.html").write_text("<html>defaced</html>", encoding="utf-8")
    out = s7.post("/api/v1/response/files/restore", {"file_key": "index.html"}).json()["data"]
    assert out["changed"] is True and out["restored"] is True
    assert web.joinpath("index.html").read_text(encoding="utf-8") == "<html>home</html>"
    events = [e for e in read_events(settings) if e["event_type"] == "response.file_restored"]
    assert len(events) == 1 and events[0]["file_key"] == "index.html"


def test_restore_rejects_a_file_key_outside_the_baseline(s7):
    r = s7.post("/api/v1/response/files/restore", {"file_key": "unexpected.txt"})
    assert r.status_code == 400 and r.json()["error"]["code"] == "NOT_IN_BASELINE"


def test_restore_is_idempotent_by_key(s7, web):
    (web / "index.html").write_text("<html>defaced</html>", encoding="utf-8")
    first = s7.post("/api/v1/response/files/restore", {"file_key": "index.html"}, idem="fixed-key-0000000001")
    second = s7.post("/api/v1/response/files/restore", {"file_key": "index.html"}, idem="fixed-key-0000000001")
    assert first.json()["data"]["replayed"] is False and second.json()["data"]["replayed"] is True


def test_quarantine_moves_an_unexpected_file_out_of_the_web_root(s7, web, settings):
    (web / "unexpected.txt").write_text("stand-in for an attacker-planted file", encoding="utf-8")
    out = s7.post("/api/v1/response/files/quarantine", {"file_key": "unexpected.txt"}).json()["data"]
    assert out["quarantined"] is True and not web.joinpath("unexpected.txt").exists()
    events = [e for e in read_events(settings) if e["event_type"] == "response.file_quarantined"]
    assert len(events) == 1


def test_file_key_path_traversal_is_rejected(s7):
    r = s7.post("/api/v1/response/files/restore", {"file_key": "../../etc/passwd"})
    assert r.status_code == 400 and r.json()["error"]["code"] == "VALIDATION_ERROR"


def test_file_endpoints_need_the_response_key(s7_app):
    bare = Control(s7_app, key=None)
    assert bare.get("/api/v1/response/files/index.html").status_code == 401
    assert bare.post("/api/v1/response/files/restore", {"file_key": "index.html"}).status_code == 401
