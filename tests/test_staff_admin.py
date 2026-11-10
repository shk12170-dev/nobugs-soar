"""담당자 처리(배정·상태·답변)와 관리자 계정 관리."""
from conftest import PASSWORD, read_events

PETITION = {"category": "welfare", "title": "복지 문의", "body": "지원 대상인지 확인하고 싶습니다."}


def new_petition(citizen):
    return citizen.post("/api/v1/petitions", PETITION).json()["data"]["id"]


def user_id(state, username):
    from nobugs_portal.services import find_user

    with state.db.session() as db:
        return find_user(db, username).id


def test_staff_routes_require_staff_or_admin(citizen, make_browser):
    assert citizen.get("/api/v1/staff/petitions").status_code == 403
    anon = make_browser()
    anon.start()
    assert anon.get("/api/v1/staff/petitions").status_code == 401


def test_staff_lists_and_filters_by_status(citizen, staff):
    pid = new_petition(citizen)
    assert [p["id"] for p in staff.get("/api/v1/staff/petitions").json()["data"]["items"]] == [pid]
    assert staff.get("/api/v1/staff/petitions?status=done").json()["data"]["items"] == []
    assert staff.get("/api/v1/staff/petitions?status=bogus").status_code == 400


def test_staff_assigns_to_self(citizen, staff, state):
    pid = new_petition(citizen)
    r = staff.post(f"/api/v1/staff/petitions/{pid}/assign", {})
    data = r.json()["data"]
    assert r.status_code == 200 and data["status"] == "assigned" and data["assignee_id"] == user_id(state, "staff1")
    assert data["version"] == 2


def test_staff_cannot_assign_to_someone_else(citizen, staff, state):
    pid = new_petition(citizen)
    r = staff.post(f"/api/v1/staff/petitions/{pid}/assign", {"assignee_id": user_id(state, "staff2")})
    assert r.status_code == 403


def test_admin_can_assign_to_a_staff_but_not_a_citizen(citizen, admin, state):
    pid = new_petition(citizen)
    ok = admin.post(f"/api/v1/staff/petitions/{pid}/assign", {"assignee_id": user_id(state, "staff2")})
    assert ok.status_code == 200
    bad = admin.post(f"/api/v1/staff/petitions/{pid}/assign", {"assignee_id": user_id(state, "citizen2")})
    assert bad.status_code == 400


def test_status_flow_follows_order_and_records_history(citizen, staff):
    pid = new_petition(citizen)
    version = staff.post(f"/api/v1/staff/petitions/{pid}/assign", {}).json()["data"]["version"]
    r = staff.post(f"/api/v1/staff/petitions/{pid}/status", {"status": "processing", "expected_version": version})
    assert r.status_code == 200 and r.json()["data"]["status"] == "processing"
    r = staff.post(f"/api/v1/staff/petitions/{pid}/status",
                   {"status": "done", "expected_version": r.json()["data"]["version"], "note": "안내 완료"})
    assert r.json()["data"]["status"] == "done"
    assert [h["action"] for h in r.json()["data"]["history"]] == ["created", "assigned", "processing", "done"]


def test_cannot_skip_a_status(citizen, staff):
    pid = new_petition(citizen)
    version = staff.post(f"/api/v1/staff/petitions/{pid}/assign", {}).json()["data"]["version"]
    r = staff.post(f"/api/v1/staff/petitions/{pid}/status", {"status": "done", "expected_version": version})
    assert r.status_code == 409 and r.json()["error"]["code"] == "INVALID_TRANSITION"


def test_stale_version_is_rejected(citizen, staff):
    pid = new_petition(citizen)
    version = staff.post(f"/api/v1/staff/petitions/{pid}/assign", {}).json()["data"]["version"]
    staff.post(f"/api/v1/staff/petitions/{pid}/reply", {"note": "확인 중입니다"})
    r = staff.post(f"/api/v1/staff/petitions/{pid}/status", {"status": "processing", "expected_version": version})
    assert r.status_code == 409 and r.json()["error"]["code"] == "VERSION_CONFLICT"


def test_only_the_assignee_can_change_status_or_reply(citizen, staff, make_browser):
    pid = new_petition(citizen)
    version = staff.post(f"/api/v1/staff/petitions/{pid}/assign", {}).json()["data"]["version"]
    other = make_browser("203.0.113.40")
    other.login("staff2")
    assert other.post(f"/api/v1/staff/petitions/{pid}/status",
                      {"status": "processing", "expected_version": version}).status_code == 403
    assert other.post(f"/api/v1/staff/petitions/{pid}/reply", {"note": "제가 답변합니다"}).status_code == 403


def test_reply_adds_history_and_citizen_sees_it(citizen, staff):
    pid = new_petition(citizen)
    staff.post(f"/api/v1/staff/petitions/{pid}/assign", {})
    assert staff.post(f"/api/v1/staff/petitions/{pid}/reply", {"note": "접수되었습니다"}).status_code == 200
    history = citizen.get(f"/api/v1/petitions/{pid}").json()["data"]["history"]
    assert history[-1]["action"] == "reply" and history[-1]["note"] == "접수되었습니다"


def test_started_petition_cannot_be_reassigned(citizen, staff, admin, state):
    pid = new_petition(citizen)
    version = staff.post(f"/api/v1/staff/petitions/{pid}/assign", {}).json()["data"]["version"]
    staff.post(f"/api/v1/staff/petitions/{pid}/status", {"status": "processing", "expected_version": version})
    r = admin.post(f"/api/v1/staff/petitions/{pid}/assign", {"assignee_id": user_id(state, "staff2")})
    assert r.status_code == 409


# ---- 관리자 ----

def test_admin_routes_are_admin_only(citizen, staff):
    assert citizen.get("/api/v1/admin/users").status_code == 403
    assert staff.get("/api/v1/admin/users").status_code == 403


def test_admin_lists_and_filters_users(admin):
    all_users = admin.get("/api/v1/admin/users").json()["data"]
    assert all_users["total"] == 6          # citizen1/2, staff1/2, admin1, zz_victim(S4 시험 계정)
    staff_only = admin.get("/api/v1/admin/users?role=staff").json()["data"]
    assert {u["username"] for u in staff_only["items"]} == {"staff1", "staff2"}
    assert [u["username"] for u in admin.get("/api/v1/admin/users?q=CITIZEN2").json()["data"]["items"]] == ["citizen2"]
    assert admin.get("/api/v1/admin/users?locked=true").json()["data"]["total"] == 0


def test_admin_lock_revokes_sessions_and_blocks_login(admin, make_browser, state, settings):
    victim = make_browser("203.0.113.80")
    victim.login("citizen2")
    uid = user_id(state, "citizen2")
    r = admin.post(f"/api/v1/admin/users/{uid}/lock")
    assert r.json()["data"] == {"user_id": uid, "locked": True, "changed": True, "revoked_sessions": 1}
    assert victim.get("/api/v1/auth/me").json()["data"]["user"] is None
    assert make_browser("203.0.113.81").login("citizen2").status_code == 401
    assert any(e["event_type"] == "auth.account_locked" for e in read_events(settings))
    assert admin.post(f"/api/v1/admin/users/{uid}/lock").json()["data"]["changed"] is False


def test_admin_cannot_lock_self(admin, state):
    assert admin.post(f"/api/v1/admin/users/{user_id(state, 'admin1')}/lock").status_code == 409


def test_admin_unlock_allows_login_again(admin, make_browser, state):
    uid = user_id(state, "citizen2")
    admin.post(f"/api/v1/admin/users/{uid}/lock")
    assert admin.post(f"/api/v1/admin/users/{uid}/unlock").json()["data"]["changed"] is True
    assert make_browser("203.0.113.82").login("citizen2").status_code == 200


def test_reset_password_unlocks_revokes_sessions_and_changes_password(admin, make_browser, state):
    uid = user_id(state, "citizen2")
    victim = make_browser("203.0.113.83")
    victim.login("citizen2")
    admin.post(f"/api/v1/admin/users/{uid}/lock")
    r = admin.post(f"/api/v1/admin/users/{uid}/reset-password", {"new_password": "Brand-New-Passw0rd-9"})
    assert r.status_code == 200 and r.json()["data"]["locked"] is False
    assert make_browser("203.0.113.84").login("citizen2", PASSWORD).status_code == 401  # 옛 비밀번호
    assert make_browser("203.0.113.85").login("citizen2", "Brand-New-Passw0rd-9").status_code == 200


def test_reset_password_validates_length_and_target(admin, state):
    uid = user_id(state, "citizen2")
    assert admin.post(f"/api/v1/admin/users/{uid}/reset-password", {"new_password": "short"}).status_code == 400
    assert admin.post("/api/v1/admin/users/9999/reset-password",
                      {"new_password": "Brand-New-Passw0rd-9"}).status_code == 404
