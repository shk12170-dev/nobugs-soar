"""S7(홈페이지 변조) 엔진 시험. 가짜 포털의 파일 상태를 직접 조작해 기준본 비교·복구·격리를 시험한다."""
import pytest
from test_engine import Clock, FakePortal
from test_engine_m5 import FakeProbe

from nobugs_engine.config import EngineSettings
from nobugs_engine.engine import Detection, Engine
from nobugs_engine.notify import Notifier
from nobugs_engine.portal import PortalError, PortalUncertain
from nobugs_engine.store import Store

ASSET = "nobugs-portal"


class FilePortal(FakePortal):
    """파일 키 -> 상태(현재 해시, 기준본 해시, 일치 여부, 기준본 존재 여부)."""

    def __init__(self):
        super().__init__()
        self.baseline: dict[str, str] = {"index.html": "base-hash-1"}
        self.current: dict[str, str | None] = {"index.html": "base-hash-1"}
        self.state_mode = "ok"            # ok | down
        self.restore_mode = "ok"          # ok | reject | timeout_applied | timeout_lost
        self.quarantine_mode = "ok"

    def file_state(self, file_key):
        self.calls.append(("state", file_key))
        if self.state_mode == "down":
            raise PortalUncertain("조회 실패")
        current, base = self.current.get(file_key), self.baseline.get(file_key)
        return {"file_key": file_key, "current_hash": current, "baseline_hash": base,
                "matches_baseline": current is not None and current == base, "known_to_baseline": base is not None}

    def restore_file(self, file_key, key):
        self.calls.append(("restore", file_key, key))
        if self.restore_mode == "reject":
            raise PortalError("400 기준본에 없음")
        if self.restore_mode == "timeout_applied":
            self.current[file_key] = self.baseline.get(file_key)
            raise PortalUncertain("응답 없음")
        if self.restore_mode == "timeout_lost":
            raise PortalUncertain("응답 없음")
        changed = self.current.get(file_key) != self.baseline.get(file_key)
        self.current[file_key] = self.baseline.get(file_key)
        return {"file_key": file_key, "changed": changed, "restored": True}

    def quarantine_file(self, file_key, key):
        self.calls.append(("quarantine", file_key, key))
        if self.quarantine_mode == "reject":
            raise PortalError("400")
        changed = file_key in self.current and self.current[file_key] is not None
        self.current[file_key] = None
        return {"file_key": file_key, "changed": changed, "quarantined": True}


@pytest.fixture
def rig(tmp_path):
    store = Store(f"sqlite:///{(tmp_path / 'engine.db').as_posix()}")
    portal, probe, clock = FilePortal(), FakeProbe(), Clock()
    settings = EngineSettings(release_ttl_seconds=90, protected_cidrs=("127.0.0.1/32",), default_dry_run=True,
                              scheduler_enabled=False)
    engine = Engine(settings, store, portal, probe, Notifier(store), clock)
    yield type("Rig", (), {"engine": engine, "store": store, "portal": portal, "clock": clock})
    store.dispose()


def det(rig, file_key="index.html", asset=ASSET, event="e1", dry_run=False):
    return rig.engine.handle(Detection(event_id=event, case_id="S7", asset_id=asset, file_key=file_key,
                                      dry_run=dry_run))


def tk(rig, ticket_id):
    with rig.store.session() as s:
        t = rig.store.get(s, ticket_id)
        return t, rig.store.actions_of(s, ticket_id)


def deface(rig, file_key="index.html", value="tampered-hash"):
    rig.portal.current[file_key] = value


# ---- 입력·보호 ----


def test_requires_a_file_key(rig):
    assert rig.engine.handle(Detection(event_id="e", case_id="S7", asset_id=ASSET, dry_run=False))["verdict"] \
        == "invalid_input"


def test_real_action_is_refused_for_an_asset_outside_the_allow_list(rig):
    deface(rig)
    r = det(rig, asset="someone-elses-site")
    assert r["verdict"] == "protected_asset" and rig.portal.calls == []


def test_dry_run_is_allowed_for_any_asset(rig):
    deface(rig)
    r = det(rig, asset="someone-elses-site", dry_run=True)
    assert r["verdict"] == "dry_run"


def test_no_ticket_when_the_file_already_matches_the_baseline(rig):
    r = det(rig)        # 아직 변조 안 됨
    assert r["verdict"] == "duplicate"
    with rig.store.session() as s:
        assert rig.store.list(s) == []


def test_engine_side_failure_when_file_state_cannot_be_read(rig):
    deface(rig)
    rig.portal.state_mode = "down"
    r = det(rig)
    assert r["verdict"] == "failed"
    with rig.store.session() as s:
        assert rig.store.list(s) == []


# ---- 복구(기준본에 있는 파일) ----


def test_dry_run_records_a_restore_action_without_calling_the_portal(rig):
    deface(rig)
    r = det(rig, dry_run=True)
    assert r["verdict"] == "dry_run"
    _, actions = tk(rig, r["ticket_id"])
    assert actions[0].kind == "file_restore" and actions[0].result == "dry_run"
    assert rig.portal.count("restore") == 0 and rig.portal.current["index.html"] == "tampered-hash"


def test_real_restore_is_applied_and_verified(rig):
    deface(rig)
    r = det(rig)
    assert r["verdict"] == "responded" and r["status"] == "restored"
    assert rig.portal.current["index.html"] == rig.portal.baseline["index.html"]
    _, actions = tk(rig, r["ticket_id"])
    assert (actions[0].kind, actions[0].result, actions[0].applied_verified, actions[0].effect_verified) == \
        ("file_restore", "applied", True, True)
    body = rig.store.notifications()[0].content
    assert "자산: " + ASSET in body and "파일: index.html" in body and "기준본과 일치 확인됨" in body


def test_repeated_detections_do_not_restore_twice(rig):
    deface(rig)
    det(rig)
    second = det(rig, event="e2")   # 이미 복구돼 기준본과 같으므로 애초에 다시 조치할 것이 없다
    assert second["verdict"] == "duplicate"
    assert rig.portal.count("restore") == 1


def test_rejected_restore_is_a_failed_action(rig):
    deface(rig)
    rig.portal.restore_mode = "reject"
    r = det(rig)
    assert r["verdict"] == "failed"
    _, actions = tk(rig, r["ticket_id"])
    assert actions[0].result == "failed" and not actions[0].active


def test_restore_timeout_is_reconciled_by_reading_the_file_back(rig):
    deface(rig)
    rig.portal.restore_mode = "timeout_applied"
    r = det(rig)
    assert r["verdict"] == "responded" and "재조회" in tk(rig, r["ticket_id"])[1][0].detail
    deface(rig, "index.html", "tampered-again")
    rig.portal.restore_mode = "timeout_lost"
    lost = det(rig, event="e2")
    assert lost["verdict"] == "failed" and tk(rig, lost["ticket_id"])[1][0].result == "uncertain"
    assert rig.portal.count("restore") == 2       # 자동 재시도 없음


def test_new_round_after_a_restored_ticket_if_tampered_again(rig):
    deface(rig)
    first = det(rig)
    assert first["status"] == "restored"
    deface(rig, "index.html", "tampered-again")
    again = det(rig, event="e2")
    assert again["ticket_id"] != first["ticket_id"]
    assert tk(rig, first["ticket_id"])[0].status == "closed"


# ---- 격리(기준본에 없는 새 파일) ----


def test_an_unbaselined_file_is_quarantined_not_restored(rig):
    rig.portal.current["shell.txt"] = "whatever"
    r = det(rig, file_key="shell.txt")
    assert r["verdict"] == "responded"
    _, actions = tk(rig, r["ticket_id"])
    assert actions[0].kind == "file_quarantine" and rig.portal.current["shell.txt"] is None


def test_quarantine_effect_is_verified_by_the_file_disappearing(rig):
    rig.portal.current["shell.txt"] = "whatever"
    r = det(rig, file_key="shell.txt")
    _, actions = tk(rig, r["ticket_id"])
    assert actions[0].effect_verified is True
    assert "격리되어 사라짐 확인됨" in rig.store.notifications()[0].content


def test_rejected_quarantine_is_a_failed_action(rig):
    rig.portal.current["shell.txt"] = "whatever"
    rig.portal.quarantine_mode = "reject"
    r = det(rig, file_key="shell.txt")
    assert r["verdict"] == "failed"


# ---- S7은 자동 원복 대상이 아니다(복구/격리 자체가 원복, 사람이 닫는다) ----


def test_s7_tickets_are_never_touched_by_release_due(rig):
    deface(rig)
    r = det(rig)
    rig.clock.advance(100_000)
    assert rig.engine.release_due() == []
    assert tk(rig, r["ticket_id"])[0].status == "restored"


def test_a_human_closes_the_ticket_after_restoration(rig):
    deface(rig)
    r = det(rig)
    with rig.store.session() as s:
        closed = rig.store.close(s, r["ticket_id"], "확인 후 종료")
    assert closed.status == "closed"
