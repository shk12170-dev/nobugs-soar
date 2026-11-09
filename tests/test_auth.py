"""가입·로그인·로그아웃·세션·CSRF."""
from conftest import PASSWORD, read_events

REGISTER = {"username": "newcomer", "display_name": "새로운사람", "password": PASSWORD}


def test_me_creates_anonymous_session_with_csrf_and_httponly_cookie(make_browser):
    b = make_browser()
    r = b.get("/api/v1/auth/me")
    assert r.status_code == 200
    data = r.json()["data"]
    assert data["user"] is None and len(data["csrf_token"]) >= 40
    assert "httponly" in r.headers["set-cookie"].lower() and "nb_session" in r.headers["set-cookie"]


def test_me_reuses_session_and_returns_same_csrf(make_browser):
    b = make_browser()
    first = b.get("/api/v1/auth/me").json()["data"]["csrf_token"]
    second = b.get("/api/v1/auth/me").json()["data"]["csrf_token"]
    assert first == second


def test_register_creates_citizen(make_browser):
    b = make_browser()
    b.start()
    r = b.post("/api/v1/auth/register", REGISTER)
    assert r.status_code == 201
    assert r.json()["data"]["role"] == "citizen" and r.json()["data"]["username"] == "newcomer"
    assert "password" not in json_text(r)


def json_text(response) -> str:
    return response.text.lower()


def test_register_duplicate_username_conflicts_case_insensitively(make_browser):
    b = make_browser()
    b.start()
    assert b.post("/api/v1/auth/register", {**REGISTER, "username": "CITIZEN1"}).status_code == 409


def test_register_rejects_weak_password_and_bad_username(make_browser):
    b = make_browser()
    b.start()
    assert b.post("/api/v1/auth/register", {**REGISTER, "password": "short"}).status_code == 400
    assert b.post("/api/v1/auth/register", {**REGISTER, "username": "bad name!"}).status_code == 400
    assert b.post("/api/v1/auth/register", {**REGISTER, "display_name": "x"}).status_code == 400


def test_register_is_refused_while_logged_in(citizen):
    assert citizen.post("/api/v1/auth/register", REGISTER).status_code == 409


def test_login_success_returns_user_and_new_csrf(make_browser):
    b = make_browser()
    r = b.login("staff1")
    assert r.status_code == 200
    assert r.json()["data"]["user"]["role"] == "staff"
    assert b.get("/api/v1/auth/me").json()["data"]["user"]["username"] == "staff1"


def test_login_rotates_session(make_browser):
    b = make_browser()
    b.start()
    old_cookie = b.client.cookies.get("nb_session")
    assert b.post("/api/v1/auth/login", {"username": "citizen1", "password": PASSWORD}).status_code == 200
    assert b.client.cookies.get("nb_session") != old_cookie


def test_old_session_cannot_be_reused_after_login(make_browser):
    attacker_view = make_browser("203.0.113.50")
    attacker_view.start()
    fixed_cookie = attacker_view.client.cookies.get("nb_session")
    victim = make_browser("203.0.113.51")
    victim.client.cookies.set("nb_session", fixed_cookie)
    victim.csrf = attacker_view.csrf
    assert victim.post("/api/v1/auth/login", {"username": "citizen1", "password": PASSWORD}).status_code == 200
    # 로그인으로 고정된 쿠키는 폐기됐다
    assert attacker_view.get("/api/v1/auth/me").json()["data"]["user"] is None


def test_wrong_password_and_unknown_user_give_the_same_answer(make_browser):
    b = make_browser()
    b.start()
    wrong = b.post("/api/v1/auth/login", {"username": "citizen1", "password": "wrong-password-1"})
    unknown = b.post("/api/v1/auth/login", {"username": "nobody", "password": "wrong-password-1"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_locked_account_cannot_log_in_even_with_right_password(make_browser, state):
    from nobugs_portal.services import find_user

    with state.db.session() as db:
        find_user(db, "citizen2").locked = True
        db.commit()
    b = make_browser()
    assert b.login("citizen2").status_code == 401


def test_login_without_csrf_token_is_forbidden(make_browser):
    b = make_browser()
    b.start()
    r = b.client.post("/api/v1/auth/login", json={"username": "citizen1", "password": PASSWORD})
    assert r.status_code == 403 and r.json()["error"]["code"] == "CSRF_FAILED"


def test_wrong_csrf_token_is_forbidden(make_browser):
    b = make_browser()
    b.start()
    b.csrf = "x" * 43
    assert b.post("/api/v1/auth/login", {"username": "citizen1", "password": PASSWORD}).status_code == 403


def test_cross_site_origin_is_forbidden(make_browser):
    b = make_browser()
    b.start()
    r = b.post("/api/v1/auth/login", {"username": "citizen1", "password": PASSWORD},
               headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "CSRF_FAILED"


def test_same_origin_header_is_accepted(make_browser):
    b = make_browser()
    b.start()
    r = b.post("/api/v1/auth/login", {"username": "citizen1", "password": PASSWORD},
               headers={"Origin": "http://testserver"})
    assert r.status_code == 200


def test_logout_revokes_session_and_clears_cookie(citizen):
    assert citizen.post("/api/v1/auth/logout").status_code == 200
    assert citizen.get("/api/v1/auth/me").json()["data"]["user"] is None


def test_expired_session_is_treated_as_anonymous(citizen, state):
    import datetime as dt

    from nobugs_portal.models import LoginSession

    with state.db.session() as db:
        for row in db.query(LoginSession).all():
            row.expires_at = row.expires_at - dt.timedelta(days=1)
        db.commit()
    assert citizen.get("/api/v1/auth/me").json()["data"]["user"] is None


def test_login_rate_limit_returns_429_after_repeated_failures(state, public_app):
    from dataclasses import replace

    from conftest import Browser

    from nobugs_portal.app import create_public_app

    limited = create_public_app(state=type(state)(settings=replace(state.settings, login_rate_limit=3),
                                                  db=state.db, events=state.events))
    b = Browser(limited, "203.0.113.60")
    b.start()
    codes = [b.post("/api/v1/auth/login", {"username": "citizen1", "password": "wrong-password-1"}).status_code
             for _ in range(5)]
    assert codes == [401, 401, 401, 429, 429]


def test_failed_and_successful_logins_emit_events(make_browser, settings):
    b = make_browser("203.0.113.70")
    b.start()
    b.post("/api/v1/auth/login", {"username": "citizen1", "password": "wrong-password-1"})
    b.post("/api/v1/auth/login", {"username": "citizen1", "password": PASSWORD})
    types = [(e["event_type"], e["src_ip"], e["username"]) for e in read_events(settings)
             if e["event_type"].startswith("auth.")]
    assert types == [("auth.login_failed", "203.0.113.70", "citizen1"),
                     ("auth.login_succeeded", "203.0.113.70", "citizen1")]


def test_events_never_contain_passwords(make_browser, settings):
    b = make_browser()
    b.start()
    b.post("/api/v1/auth/login", {"username": "citizen1", "password": "Super-Secret-Value-9"})
    assert "Super-Secret-Value-9" not in open(settings.event_log_path, encoding="utf-8").read()
