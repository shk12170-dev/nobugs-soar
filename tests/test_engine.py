"""대응 엔진의 안전 규칙 시험(가짜 포털·가짜 프로브 사용)."""
import datetime as dt

import pytest

from nobugs_engine.config import EngineSettings
from nobugs_engine.engine import Detection, Engine
from nobugs_engine.models import utcnow
from nobugs_engine.notify import Notifier
from nobugs_engine.portal import PortalError, PortalUncertain
from nobugs_engine.store import InvalidTransition, Store

ATTACKER = "203.0.113.50"


class FakePortal:
    """차단 목록을 가진 가짜 포털. 실패 방식을 바꿔 가며 시험한다."""

    def __init__(self):
        self.blocked: set[str] = set()
        self.calls: list[tuple] = []
        self.block_mode = "ok"        # ok | reject | timeout_applied | timeout_lost
        self.unblock_mode = "ok"      # ok | reject | silent_fail
        self.list_mode = "ok"         # ok | down

    def block_ip(self, ip, key):
        self.calls.append(("block", ip, key))
        if self.block_mode == "reject":
            raise PortalError("403 거절")
        if self.block_mode == "timeout_applied":
            self.blocked.add(ip)
            raise PortalUncertain("응답 없음: TimeoutError")
        if self.block_mode == "timeout_lost":
            raise PortalUncertain("응답 없음: TimeoutError")
        changed = ip not in self.blocked
        self.blocked.add(ip)
        return {"ip": ip, "blocked": True, "changed": changed}

    def unblock_ip(self, ip, key):
        self.calls.append(("unblock", ip, key))
        if self.unblock_mode == "reject":
            raise PortalError("403 거절")
        if self.unblock_mode != "silent_fail":
            self.blocked.discard(ip)
        return {"ip": ip, "blocked": False}

    def blocked_ips(self):
        if self.list_mode == "down":
            raise PortalUncertain("목록 조회 실패")
        return set(self.blocked)

    def count(self, kind):
        return sum(1 for c in self.calls if c[0] == kind)


class FakeProbe:
    def __init__(self):
        self.blocked: bool | None = True
        self.reachable: bool | None = True

    def is_blocked(self, ip):
        return self.blocked

    def is_reachable(self, ip):
        return self.reachable


class Clock:
    def __init__(self):
        self.offset = dt.timedelta(0)

    def __call__(self):
        return utcnow() + self.offset

    def advance(self, seconds):
        self.offset += dt.timedelta(seconds=seconds)


@pytest.fixture
def rig(tmp_path):
    store = Store(f"sqlite:///{(tmp_path / 'engine.db').as_posix()}")
    portal, probe, clock = FakePortal(), FakeProbe(), Clock()
    settings = EngineSettings(release_ttl_seconds=90, protected_cidrs=("127.0.0.1/32", "10.0.0.0/8"),
                              default_dry_run=True, scheduler_enabled=False)
    engine = Engine(settings, store, portal, probe, Notifier(store), clock)
    yield type("Rig", (), {"engine": engine, "store": store, "portal": portal, "probe": probe, "clock": clock})
    store.dispose()


def detect(rig, user="victim", ip=ATTACKER, event="evt-1", dry_run=False, **kw):
    return rig.engine.handle(Detection(event_id=event, case_id="S1", src_ip=ip, username=user, dry_run=dry_run, **kw))


def ticket(rig, ticket_id):
    with rig.store.session() as s:
        t = rig.store.get(s, ticket_id)
        return t, rig.store.actions_of(s, ticket_id)


# ---- 보호·검증·모의 실행 ----

def test_protected_sources_are_never_blocked_and_get_no_ticket(rig):
    for ip in ("127.0.0.1", "10.1.2.3"):
        assert detect(rig, ip=ip)["verdict"] == "protected_source"
    assert rig.portal.calls == []
    with rig.store.session() as s:
        assert rig.store.list(s) == []


def test_invalid_input_and_unsupported_case_do_nothing(rig):
    assert detect(rig, ip="not-an-ip")["verdict"] == "invalid_input"
    assert rig.engine.handle(Detection(event_id="e", case_id="S99", src_ip=ATTACKER))["verdict"] == "unsupported_case"
    assert rig.portal.calls == []


def test_default_is_dry_run_and_never_calls_the_portal(rig):
    result = rig.engine.handle(Detection(event_id="e1", case_id="S1", src_ip=ATTACKER, username="victim"))
    assert result["verdict"] == "dry_run" and rig.portal.calls == []
    t, actions = ticket(rig, result["ticket_id"])
    assert t.status == "open" and [a.result for a in actions] == ["dry_run"] and not actions[0].active
    assert "모의 실행" in rig.store.notifications()[0].content


def test_explicit_false_overrides_the_dry_run_default(rig):
    assert detect(rig, dry_run=False)["verdict"] == "responded"
    assert rig.portal.count("block") == 1


def test_repeated_dry_run_events_make_one_ticket_and_one_action(rig):
    first = rig.engine.handle(Detection(event_id="e1", case_id="S1", src_ip=ATTACKER, username="victim"))
    second = rig.engine.handle(Detection(event_id="e2", case_id="S1", src_ip=ATTACKER, username="victim"))
    assert second["verdict"] == "duplicate" and second["ticket_id"] == first["ticket_id"]
    assert len(ticket(rig, first["ticket_id"])[1]) == 1


# ---- 실제 차단 ----

def test_real_block_is_applied_verified_and_marked_effective(rig):
    result = detect(rig)
    assert result["verdict"] == "responded" and result["status"] == "verified"
    assert result["applied_verified"] is True and result["effect_verified"] is True
    assert rig.portal.calls == [("block", ATTACKER, f"{result['ticket_id']}-block-{ATTACKER}")]
    t, actions = ticket(rig, result["ticket_id"])
    assert actions[0].active and actions[0].result == "applied" and actions[0].effect_at is not None
    assert t.src_ip == ATTACKER and t.username == "victim"


def test_unverifiable_effect_keeps_the_ticket_responding_not_verified(rig):
    rig.probe.blocked = None
    result = detect(rig)
    assert result["status"] == "responding" and result["effect_verified"] is None


def test_failed_effect_check_is_recorded_and_reported(rig):
    rig.probe.blocked = False   # 목록에는 올랐지만 실제로는 아직 접근된다
    result = detect(rig)
    assert result["status"] == "responding"
    t, actions = ticket(rig, result["ticket_id"])
    assert actions[0].effect_verified is False
    assert "효과 확인 실패" in rig.store.notifications()[0].content


def test_same_key_twice_does_not_call_the_portal_again(rig):
    first = detect(rig, event="e1")
    second = detect(rig, event="e2")
    assert second["verdict"] == "duplicate" and second["ticket_id"] == first["ticket_id"]
    assert rig.portal.count("block") == 1
    assert ticket(rig, first["ticket_id"])[0].event_ids == ["e1", "e2"]


def test_two_accounts_from_one_ip_make_two_tickets_and_the_second_sees_already_applied(rig):
    a = detect(rig, user="alice", event="e1")
    b = detect(rig, user="bob", event="e2")
    assert a["ticket_id"] != b["ticket_id"] and b["result"] == "already_applied"
    assert rig.portal.count("block") == 2   # 키가 달라 호출은 두 번, 포털이 변화 없음을 알려 준다


def test_detection_times_are_parsed_from_graylog_timestamps(rig):
    result = detect(rig, condition_met_at="2026-11-10T01:02:03.000Z", detected_at="2026-11-10T01:02:04.500+00:00")
    t, _ = ticket(rig, result["ticket_id"])
    assert t.condition_met_at == dt.datetime(2026, 11, 10, 1, 2, 3)
    assert t.detected_at == dt.datetime(2026, 11, 10, 1, 2, 4, 500000)


# ---- 실패와 불확실한 결과 ----

def test_portal_rejection_is_recorded_as_failed_without_an_active_action(rig):
    rig.portal.block_mode = "reject"
    result = detect(rig)
    assert result["verdict"] == "failed" and result["result"] == "failed"
    t, actions = ticket(rig, result["ticket_id"])
    assert t.status == "open" and not actions[0].active
    assert "🚨" in rig.store.notifications()[0].content


def test_timeout_but_actually_applied_is_reconciled_by_relisting(rig):
    rig.portal.block_mode = "timeout_applied"
    result = detect(rig)
    assert result["verdict"] == "responded" and result["result"] == "applied"
    t, actions = ticket(rig, result["ticket_id"])
    assert actions[0].active and "재조회" in actions[0].detail
    assert rig.portal.count("block") == 1    # 자동 재시도 없음


def test_timeout_and_not_applied_is_recorded_as_uncertain_without_retry(rig):
    rig.portal.block_mode = "timeout_lost"
    result = detect(rig)
    assert result["verdict"] == "failed" and result["result"] == "uncertain"
    t, actions = ticket(rig, result["ticket_id"])
    assert t.status == "open" and not actions[0].active and actions[0].applied_verified is False
    assert rig.portal.count("block") == 1
    assert "결과 불확실" in rig.store.notifications()[0].content


def test_unreadable_block_list_leaves_applied_verified_unknown(rig):
    rig.portal.list_mode = "down"
    result = detect(rig)
    assert result["applied_verified"] is None
    assert ticket(rig, result["ticket_id"])[1][0].applied_verified is None


def test_a_later_detection_retries_after_a_failed_attempt(rig):
    rig.portal.block_mode = "reject"
    detect(rig, event="e1")
    rig.portal.block_mode = "ok"
    second = detect(rig, event="e2")
    assert second["verdict"] == "responded" and rig.portal.count("block") == 2


def test_real_detection_after_a_dry_run_proceeds_with_the_real_block(rig):
    rig.engine.handle(Detection(event_id="e1", case_id="S1", src_ip=ATTACKER, username="victim"))
    assert detect(rig, event="e2")["verdict"] == "responded"


# ---- 자동 원복 ----

def test_nothing_is_released_before_the_ttl(rig):
    detect(rig)
    rig.clock.advance(60)
    assert rig.engine.release_due() == [] and rig.portal.count("unblock") == 0


def test_release_after_ttl_unblocks_verifies_and_restores(rig):
    result = detect(rig)
    rig.clock.advance(100)
    assert rig.engine.release_due() == [result["ticket_id"]]
    assert ATTACKER not in rig.portal.blocked
    t, actions = ticket(rig, result["ticket_id"])
    assert t.status == "restored" and not any(a.active for a in actions)
    release = [a for a in actions if a.kind == "ip_release"][0]
    assert release.result == "released" and release.effect_verified is True
    assert "원복 완료" in rig.store.notifications()[0].content and "자동 원복" in rig.store.notifications()[0].content


def test_unverifiable_restore_effect_is_recorded_as_unknown(rig):
    detect(rig)
    rig.probe.reachable = None
    rig.clock.advance(100)
    rig.engine.release_due()
    assert [a for a in ticket(rig, "T-" + utcnow().strftime("%Y%m%d") + "-0001")[1] if a.kind == "ip_release"][0].effect_verified is None


def test_shared_ip_tickets_do_not_deadlock_and_release_together(rig):
    a = detect(rig, user="alice", event="e1")
    b = detect(rig, user="bob", event="e2")
    rig.clock.advance(100)
    assert sorted(rig.engine.release_due()) == sorted([a["ticket_id"], b["ticket_id"]])
    assert rig.portal.count("unblock") == 1   # 같은 IP는 한 번만 풀면 된다
    assert ticket(rig, a["ticket_id"])[0].status == ticket(rig, b["ticket_id"])[0].status == "restored"


def test_shared_ip_is_held_while_any_holder_is_still_fresh(rig):
    a = detect(rig, user="alice", event="e1")
    rig.clock.advance(100)
    b = detect(rig, user="bob", event="e2")   # 새 티켓: 아직 TTL이 안 지났다
    assert rig.engine.release_due() == [] and rig.portal.count("unblock") == 0
    rig.clock.advance(100)
    assert sorted(rig.engine.release_due()) == sorted([a["ticket_id"], b["ticket_id"]])


def test_release_rejected_by_portal_keeps_the_block_and_notifies_only_once(rig):
    result = detect(rig)
    rig.portal.unblock_mode = "reject"
    rig.clock.advance(100)
    assert rig.engine.release_due() == [] and rig.engine.release_due() == []
    t, actions = ticket(rig, result["ticket_id"])
    assert t.status == "verified" and t.release_attempts == 2 and any(a.active for a in actions)
    failures = [n for n in rig.store.notifications() if "원복 실패" in n.content]
    assert len(failures) == 1


def test_release_is_not_reported_done_when_the_ip_stays_listed(rig):
    result = detect(rig)
    rig.portal.unblock_mode = "silent_fail"
    rig.clock.advance(100)
    assert rig.engine.release_due() == []
    assert ticket(rig, result["ticket_id"])[0].status == "verified"


def test_dry_run_tickets_are_never_released_or_unblocked(rig):
    rig.engine.handle(Detection(event_id="e1", case_id="S1", src_ip=ATTACKER, username="victim"))
    rig.clock.advance(1000)
    assert rig.engine.release_due() == [] and rig.portal.calls == []


def test_a_new_detection_after_restoration_starts_a_new_round(rig):
    first = detect(rig, event="e1")
    rig.clock.advance(100)
    rig.engine.release_due()
    second = detect(rig, event="e2")
    assert second["verdict"] == "responded" and second["ticket_id"] != first["ticket_id"]
    old, _ = ticket(rig, first["ticket_id"])
    assert old.status == "closed" and "자동 종료" in old.close_note
    assert ATTACKER in rig.portal.blocked


# ---- 닫기와 상태 기계 ----

def test_only_restored_tickets_can_be_closed_by_a_person(rig):
    result = detect(rig)
    with rig.store.session() as s, pytest.raises(InvalidTransition):
        rig.store.close(s, result["ticket_id"], "너무 이름")
    rig.clock.advance(100)
    rig.engine.release_due()
    with rig.store.session() as s:
        closed = rig.store.close(s, result["ticket_id"], "확인 완료")
        assert closed.status == "closed" and closed.close_note == "확인 완료"


def test_status_never_moves_backward(rig):
    result = detect(rig)
    with rig.store.session() as s:
        t = rig.store.get(s, result["ticket_id"])
        with pytest.raises(InvalidTransition):
            rig.store.advance(s, t, "open")


def test_only_one_open_ticket_per_case_and_key_even_with_concurrent_creation(rig):
    with rig.store.session() as s1, rig.store.session() as s2:
        t1, new1 = rig.store.open_or_get(s1, "S1", "k@1.1.1.1", src_ip="1.1.1.1")
        t2, new2 = rig.store.open_or_get(s2, "S1", "k@1.1.1.1", src_ip="1.1.1.1")
    assert t1.id == t2.id and (new1, new2) == (True, False)


def test_notifications_contain_no_internal_addresses_or_secrets(rig):
    detect(rig)
    rig.clock.advance(100)
    rig.engine.release_due()
    for n in rig.store.notifications():
        assert "http" not in n.content and "Idempotency" not in n.content and "key" not in n.content.lower()
