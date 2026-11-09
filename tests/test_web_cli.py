"""프론트 정적 서빙(파일 접근 이벤트), 보안 헤더, 계정 생성 CLI."""
from dataclasses import replace

import pytest
from conftest import Browser, read_events

from nobugs_portal import cli
from nobugs_portal.app import create_public_app
from nobugs_portal.db import Database


@pytest.fixture
def dist(tmp_path):
    root = tmp_path / "dist"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("<!doctype html><title>nobugs</title><script src='/assets/app.js'></script>",
                                     encoding="utf-8")
    (root / "assets" / "app.js").write_text("console.log('hi')", encoding="utf-8")
    (root / "assets" / "app.css").write_text("body{margin:0}", encoding="utf-8")
    (root / "favicon.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'/>", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("do-not-serve", encoding="utf-8")
    return root


@pytest.fixture
def web_app(state, dist):
    new_state = type(state)(settings=replace(state.settings, frontend_dist=str(dist)), db=state.db, events=state.events)
    return create_public_app(state=new_state)


def file_events(settings):
    return [(e["file_key"], e["status"], e["src_ip"]) for e in read_events(settings) if e["event_type"] == "web.file_access"]


def test_home_and_screen_routes_serve_index_and_record_index_html(web_app, settings):
    b = Browser(web_app, "203.0.113.20")
    for path in ("/", "/login", "/register", "/staff", "/admin", "/petitions", "/petitions/12", "/staff/petitions/3"):
        r = b.get(path)
        assert r.status_code == 200 and "<title>nobugs</title>" in r.text, path
    assert {k for k, _, _ in file_events(settings)} == {"index.html"}
    assert len(file_events(settings)) == 8


def test_assets_and_favicon_are_served_with_their_own_file_keys(web_app, settings):
    b = Browser(web_app, "203.0.113.21")
    js = b.get("/assets/app.js")
    assert js.status_code == 200 and "javascript" in js.headers["content-type"]
    assert b.get("/assets/app.css").status_code == 200 and b.get("/favicon.svg").status_code == 200
    assert [k for k, _, _ in file_events(settings)] == ["assets/app.js", "assets/app.css", "favicon.svg"]


def test_file_access_event_records_caller_and_status(web_app, settings):
    Browser(web_app, "203.0.113.22").get("/assets/app.js")
    assert file_events(settings) == [("assets/app.js", 200, "203.0.113.22")]


def test_missing_asset_is_404_and_counts_as_a_scan_not_a_file_access(web_app, settings):
    r = Browser(web_app, "203.0.113.23").get("/assets/nope.js")
    assert r.status_code == 404
    assert file_events(settings) == []
    assert [e["rule"] for e in read_events(settings) if e["event_type"] == "web.not_found"] == ["web-scan"]


def test_path_traversal_cannot_read_files_outside_the_web_root(web_app, settings):
    b = Browser(web_app, "203.0.113.24")
    for path in ("/assets/../../secret.txt", "/assets/%2e%2e/%2e%2e/secret.txt", "/assets/..%2f..%2fsecret.txt"):
        r = b.get(path)
        assert r.status_code == 404 and "do-not-serve" not in r.text, path
    assert file_events(settings) == []


def test_unlisted_paths_stay_404_even_if_the_file_exists_in_the_web_root(web_app, dist):
    (dist / "private.html").write_text("hidden", encoding="utf-8")
    assert Browser(web_app, "203.0.113.25").get("/private.html").status_code == 404


def test_missing_build_returns_503_json(state, tmp_path):
    app = create_public_app(state=type(state)(settings=replace(state.settings, frontend_dist=str(tmp_path / "none")),
                                              db=state.db, events=state.events))
    r = Browser(app, "203.0.113.26").get("/")
    assert r.status_code == 503 and r.json()["error"]["code"] == "FRONTEND_NOT_BUILT"


def test_blocked_ip_cannot_read_the_frontend(web_app, state):
    from nobugs_portal.models import BlockedIp

    with state.db.session() as db:
        db.add(BlockedIp(ip="203.0.113.99"))
        db.commit()
    assert Browser(web_app, "203.0.113.99").get("/").status_code == 403


def test_security_headers_are_on_pages_and_api_responses(web_app):
    b = Browser(web_app, "203.0.113.27")
    for path in ("/", "/api/v1/health", "/nope"):
        h = b.get(path).headers
        assert "default-src 'self'" in h["content-security-policy"] and "frame-ancestors 'none'" in h["content-security-policy"]
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY", path
    assert b.get("/").headers["cache-control"] == "no-cache"


# ---- CLI ----

def test_cli_creates_a_user_who_can_log_in(tmp_path, settings, monkeypatch, public_app):
    monkeypatch.setenv("NB_TEST_PASSWORD", "Cli-Created-Passw0rd")
    code = cli.main(["create-user", "--username", "clistaff", "--role", "staff", "--password-env", "NB_TEST_PASSWORD"],
                    settings)
    assert code == 0
    assert Browser(public_app, "203.0.113.28").login("clistaff", "Cli-Created-Passw0rd").json()["data"]["user"]["role"] == "staff"


def test_cli_rejects_duplicates_weak_passwords_and_bad_names(settings, monkeypatch, capsys):
    monkeypatch.setenv("NB_TEST_PASSWORD", "Cli-Created-Passw0rd")
    base = ["create-user", "--password-env", "NB_TEST_PASSWORD"]
    assert cli.main([*base, "--username", "dupuser"], settings) == 0
    assert cli.main([*base, "--username", "dupuser"], settings) == 1
    assert "이미 존재" in capsys.readouterr().err
    assert cli.main([*base, "--username", "bad name"], settings) == 1
    monkeypatch.setenv("NB_TEST_PASSWORD", "short")
    assert cli.main([*base, "--username", "weakuser"], settings) == 1


def test_seed_demo_creates_three_accounts_once_with_random_passwords(settings, capsys):
    assert cli.main(["seed-demo"], settings) == 0
    out = capsys.readouterr().out
    lines = [x.split() for x in out.splitlines() if x.startswith(("citizen_demo", "staff_demo", "admin_demo"))]
    assert [x[0] for x in lines] == ["citizen_demo", "staff_demo", "admin_demo"]
    assert len({x[1] for x in lines}) == 3
    assert cli.main(["seed-demo"], settings) == 1  # 빈 DB에서만


def test_seed_demo_refuses_when_users_exist(state, settings):
    db = Database(settings.database_url)
    with pytest.raises(ValueError):
        cli.seed_demo(db)
    db.dispose()
