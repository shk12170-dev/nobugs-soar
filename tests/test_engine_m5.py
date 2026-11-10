"""M5 케이스(S4 계정 잠금, S8·S10 스캔 계열, S12 요청 폭주) 엔진 시험. 가짜 포털·경계·건강 검사 사용."""
import pytest
from test_engine import ATTACKER, Clock, FakePortal, FakeProbe

from nobugs_engine.config import EngineSettings
from nobugs_engine.engine import Detection, Engine
from nobugs_engine.health import Sample
from nobugs_engine.notify import Notifier
from nobugs_engine.portal import PortalError, PortalUncertain
from nobugs_engine.store import InvalidTransition, Store


class AccountPortal(FakePortal):
    def __init__(self):
        super().__init__()
        self.locked: set[str] = set()
        self.sessions = 2
        self.lock_mode = "ok"      # ok | reject | timeout_applied | timeout_lost
        self.state_down = False

    def lock_account(self, username, key):
        self.calls.append(("lock", username, key))
        if self.lock_mode == "reject":
            raise PortalError("403")
        if self.lock_mode == "timeout_applied":
            self.locked.add(username)
            raise PortalUncertain("응답 없음")
        if self.lock_mode == "timeout_lost":
            raise PortalUncertain("응답 없음")
        changed = username not in self.locked
        self.locked.add(username)
        self.sessions = 0
        return {"username": username, "locked": True, "changed": changed}

    def account_state(self, username):
        if self.state_down:
            raise PortalUncertain("조회 실패")
        return {"username": username, "locked": username in self.locked, "active_sessions": self.sessions,
                "role": "citizen"}


class FakeBoundary:
    def __init__(self):
        self.ips: set[str] = set()
        self.calls: list[tuple] = []
        self.mode = "ok"            # ok | down | stuck

    def block_ip(self, ip):
        self.calls.append(("block", ip))
        if self.mode == "down":
            raise PortalUncertain("응답 없음")
        changed = ip not in self.ips
        self.ips.add(ip)
        return {"changed": changed}

    def unblock_ip(self, ip):
        self.calls.append(("unblock", ip))
        if self.mode == "down":
            raise PortalUncertain("응답 없음")
        if self.mode != "stuck":
            self.ips.discard(ip)
        return {"changed": True}

    def blocked_ips(self):
        return set(self.ips)


class FakeHealth:
    def __init__(self, samples):
        self.samples = samples
        self.runs = 0

    def run(self):
        self.runs += 1
        return self.samples


SLOW = [Sample(900, 200), Sample(950, 200), Sample(880, 200)]
FAST = [Sample(20, 200), Sample(25, 200), Sample(22, 200)]


@pytest.fixture
def rig(tmp_path):
    store = Store(f"sqlite:///{(tmp_path / 'engine.db').as_posix()}")
    portal, probe, clock, boundary = AccountPortal(), FakeProbe(), Clock(), FakeBoundary()
    health = FakeHealth(SLOW)
    settings = EngineSettings(release_ttl_seconds=90, protected_cidrs=("127.0.0.1/32",), default_dry_run=True,
                              scheduler_enabled=False, health_baseline_ms=200)
    engine = Engine(settings, store, portal, probe, Notifier(store), clock, boundary=boundary, health=health)
    yield type("Rig", (), {"engine": engine, "store": store, "portal": portal, "probe": probe, "clock": clock,
                           "boundary": boundary, "health": health})
    store.dispose()


def det(rig, case, ip=ATTACKER, user=None, event="e1", dry_run=False):
    return rig.engine.handle(Detection(event_id=event, case_id=case, src_ip=ip, username=user, dry_run=dry_run))


def tk(rig, ticket_id):
    with rig.store.session() as s:
        t = rig.store.get(s, ticket_id)
        return t, rig.store.actions_of(s, ticket_id)


# ---- S4: 계정 잠금 ----

def test_s4_locks_only_test_accounts_for_real(rig):
    r = det(rig, "S4", user="citizen1")
    assert r["verdict"] == "protected_account" and rig.portal.calls == []
    with rig.store.session() as s:
        assert rig.store.list(s) == []


def test_s4_dry_run_is_allowed_for_any_account_and_calls_nothing(rig):
    r = det(rig, "S4", user="citizen1", dry_run=True)
    assert r["verdict"] == "dry_run" and rig.portal.calls == []


def test_s4_requires_a_username(rig):
    assert det(rig, "S4")["verdict"] == "invalid_input"


def test_s4_lock_is_verified_and_sessions_are_checked(rig):
    r = det(rig, "S4", user="zz_victim")
    assert r["verdict"] == "responded" and r["status"] == "verified"
    t, actions = tk(rig, r["ticket_id"])
    a = actions[0]
    assert (a.kind, a.target, a.applied_verified, a.effect_verified, a.active) == ("account_lock", "zz_victim",
                                                                                   True, True, True)
    assert "zz_victim" in rig.portal.locked
    body = rig.store.notifications()[0].content
    assert "계정: zz_victim" in body and "세션" in body


def test_s4_is_never_released_automatically(rig):
    det(rig, "S4", user="zz_victim")
    rig.clock.advance(100_000)
    assert rig.engine.release_due() == [] and "zz_victim" in rig.portal.locked


def test_s4_repeated_events_do_not_lock_twice(rig):
    first = det(rig, "S4", user="zz_victim")
    second = det(rig, "S4", user="zz_victim", event="e2")
    assert second["verdict"] == "duplicate" and second["ticket_id"] == first["ticket_id"]
    assert rig.portal.count("lock") == 1


def test_s4_recovery_is_refused_while_still_locked(rig):
    r = det(rig, "S4", user="zz_victim")
    with pytest.raises(InvalidTransition):
        rig.engine.confirm_account_recovered(r["ticket_id"])
    assert tk(rig, r["ticket_id"])[0].status == "verified"


def test_s4_recovery_after_a_human_unlocks(rig):
    r = det(rig, "S4", user="zz_victim")
    rig.portal.locked.discard("zz_victim")        # 관리자가 포털에서 잠금 해제
    out = rig.engine.confirm_account_recovered(r["ticket_id"])
    t, actions = tk(rig, r["ticket_id"])
    assert out["status"] == "restored" and t.status == "restored"
    assert [a.active for a in actions if a.kind == "account_lock"] == [False]
    assert any(a.kind == "account_unlock" and a.effect_verified for a in actions)


def test_s4_recovery_needs_an_active_lock_and_readable_state(rig):
    r = det(rig, "S4", user="zz_victim", dry_run=True)
    with pytest.raises(InvalidTransition):
        rig.engine.confirm_account_recovered(r["ticket_id"])
    live = det(rig, "S4", user="zz_other", event="e9")
    rig.portal.state_down = True
    with pytest.raises(InvalidTransition):
        rig.engine.confirm_account_recovered(live["ticket_id"])


def test_s4_rejected_lock_is_a_failed_action_with_no_active_effect(rig):
    rig.portal.lock_mode = "reject"
    r = det(rig, "S4", user="zz_victim")
    assert r["verdict"] == "failed"
    _, actions = tk(rig, r["ticket_id"])
    assert actions[0].result == "failed" and not actions[0].active


def test_s4_timeout_is_reconciled_by_reading_the_account_back(rig):
    rig.portal.lock_mode = "timeout_applied"
    r = det(rig, "S4", user="zz_victim")
    assert r["verdict"] == "responded" and "재조회" in tk(rig, r["ticket_id"])[1][0].detail
    rig.portal.lock_mode = "timeout_lost"
    lost = det(rig, "S4", user="zz_lost")
    assert lost["verdict"] == "failed" and tk(rig, lost["ticket_id"])[1][0].result == "uncertain"
    assert rig.portal.count("lock") == 2        # 자동 재시도 없음


# ---- S8 → S10: 한 IP, 한 티켓 ----

def test_s8_blocks_the_ip_in_the_app_only(rig):
    r = det(rig, "S8")
    assert r["verdict"] == "responded" and ATTACKER in rig.portal.blocked and rig.boundary.calls == []
    assert tk(rig, r["ticket_id"])[0].case_id == "S8"


def test_s10_after_s8_upgrades_the_same_ticket_and_adds_the_boundary(rig):
    s8 = det(rig, "S8")
    s10 = det(rig, "S10", event="e2")
    assert s10["ticket_id"] == s8["ticket_id"]
    t, actions = tk(rig, s8["ticket_id"])
    assert t.case_id == "S10"
    assert sorted(a.kind for a in actions if a.active) == ["boundary_block", "ip_block"]
    assert rig.portal.count("block") == 1 and ATTACKER in rig.boundary.ips
    with rig.store.session() as s:
        assert len(rig.store.list(s)) == 1


def test_s10_alone_blocks_boundary_first_then_app(rig):
    order = []
    original = rig.portal.block_ip
    rig.portal.block_ip = lambda ip, key: (order.append("app"), original(ip, key))[1]
    original_b = rig.boundary.block_ip
    rig.boundary.block_ip = lambda ip: (order.append("boundary"), original_b(ip))[1]
    det(rig, "S10")
    assert order == ["boundary", "app"]


def test_s10_boundary_down_still_blocks_the_app_and_reports_the_failure(rig):
    rig.boundary.mode = "down"
    r = det(rig, "S10")
    assert r["verdict"] == "responded" and ATTACKER in rig.portal.blocked
    _, actions = tk(rig, r["ticket_id"])
    assert {a.kind: a.result for a in actions} == {"boundary_block": "uncertain", "ip_block": "applied"}
    assert "error" or rig.store.notifications()


def test_s10_release_goes_boundary_then_app_and_marks_boundary_as_simulated(rig):
    order = []
    ub = rig.boundary.unblock_ip
    rig.boundary.unblock_ip = lambda ip: (order.append("boundary"), ub(ip))[1]
    up = rig.portal.unblock_ip
    rig.portal.unblock_ip = lambda ip, key: (order.append("app"), up(ip, key))[1]
    r = det(rig, "S10")
    rig.clock.advance(100)
    assert rig.engine.release_due() == [r["ticket_id"]]
    assert order == ["boundary", "app"]
    t, actions = tk(rig, r["ticket_id"])
    assert t.status == "restored" and not any(a.active for a in actions)
    assert any(a.kind == "boundary_release" for a in actions)
    assert any("시뮬레이션" in n.content for n in rig.store.notifications())


def test_s10_release_stops_if_the_boundary_will_not_let_go(rig):
    r = det(rig, "S10")
    rig.boundary.mode = "stuck"
    rig.clock.advance(100)
    assert rig.engine.release_due() == []
    assert rig.portal.count("unblock") == 0 and ATTACKER in rig.portal.blocked
    assert tk(rig, r["ticket_id"])[0].status != "restored"


def test_s10_release_failure_is_reported_once(rig):
    det(rig, "S10")
    rig.boundary.mode = "down"
    rig.clock.advance(100)
    for _ in range(3):
        rig.engine.release_due()
    assert sum("원복 실패" in n.content for n in rig.store.notifications()) == 1


def test_scan_new_round_after_restoration(rig):
    first = det(rig, "S8")
    rig.clock.advance(100)
    rig.engine.release_due()
    again = det(rig, "S8", event="e2")
    assert again["ticket_id"] != first["ticket_id"] and again["verdict"] == "responded"


def test_s1_and_scan_tickets_sharing_one_ip_are_released_together(rig):
    s1 = det(rig, "S1", user="victim")
    s8 = det(rig, "S8", event="e2")
    rig.clock.advance(100)
    assert set(rig.engine.release_due()) == {s1["ticket_id"], s8["ticket_id"]}
    assert ATTACKER not in rig.portal.blocked


# ---- S12: 폭주해도 멀쩡하면 차단하지 않음 ----

def test_s12_harmless_flood_takes_no_action(rig):
    rig.health.samples = FAST
    r = det(rig, "S12")
    assert r["verdict"] == "within_baseline" and r["no_action"] is True
    assert rig.portal.calls == []
    with rig.store.session() as s:
        assert rig.store.list(s) == []


def test_s12_mixed_samples_are_inconclusive_and_do_nothing(rig):
    rig.health.samples = [Sample(900, 200), Sample(20, 200), Sample(900, 200)]
    assert det(rig, "S12")["verdict"] == "inconclusive" and rig.portal.calls == []


def test_s12_sustained_slowdown_blocks_and_says_why(rig):
    r = det(rig, "S12")
    assert r["verdict"] == "responded" and ATTACKER in rig.portal.blocked
    assert "서비스 지연 확인" in rig.store.notifications()[0].content


def test_s12_timeouts_and_server_errors_count_as_degraded(rig):
    rig.health.samples = [Sample(None, None, error="timeout"), Sample(30, 503), Sample(None, None, error="network")]
    assert det(rig, "S12")["verdict"] == "responded"


def test_s12_dry_run_still_measures_but_changes_nothing(rig):
    r = det(rig, "S12", dry_run=True)
    assert r["verdict"] == "dry_run" and rig.health.runs == 1 and rig.portal.calls == []


def test_s12_is_released_on_ttl_like_s1(rig):
    r = det(rig, "S12")
    rig.clock.advance(100)
    assert rig.engine.release_due() == [r["ticket_id"]] and ATTACKER not in rig.portal.blocked


# ---- 동시 요청: S8·S10이 같은 트래픽에 같은 분에 함께 발동해도 한 번만 조치한다 ----


def test_concurrent_s8_and_s10_detections_block_the_app_only_once(rig):
    import threading

    results = {}

    def run(case, event):
        results[case] = det(rig, case, event=event)

    t1 = threading.Thread(target=run, args=("S8", "e1"))
    t2 = threading.Thread(target=run, args=("S10", "e2"))
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    with rig.store.session() as s:
        tickets = rig.store.list(s)
    assert len(tickets) == 1 and tickets[0].case_id == "S10"
    _, actions = tk(rig, tickets[0].id)
    assert sorted(a.kind for a in actions if a.active) == ["boundary_block", "ip_block"]   # ip_block이 한 번뿐
    assert rig.portal.count("block") == 1
