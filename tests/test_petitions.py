"""민원 신청·조회와 담당자 처리."""
PETITION = {"category": "road", "title": "가로등 고장", "body": "OO로 12번 앞 가로등이 꺼져 있습니다."}


def create(browser, **overrides):
    return browser.post("/api/v1/petitions", {**PETITION, **overrides})


def test_citizen_creates_petition_with_history(citizen):
    r = create(citizen)
    assert r.status_code == 201
    data = r.json()["data"]
    assert data["status"] == "received" and data["version"] == 1
    assert [h["action"] for h in data["history"]] == ["created"]


def test_creation_requires_login(make_browser):
    b = make_browser()
    b.start()
    assert create(b).status_code == 401


def test_staff_and_admin_cannot_create_petitions(staff, admin):
    assert create(staff).status_code == 403
    assert create(admin).status_code == 403


def test_creation_validates_input(citizen):
    assert create(citizen, category="unknown").status_code == 400
    assert create(citizen, title="x").status_code == 400
    assert create(citizen, body="짧음").status_code == 400


def test_creation_requires_csrf(citizen):
    r = citizen.client.post("/api/v1/petitions", json=PETITION)
    assert r.status_code == 403


def test_mine_lists_only_own_petitions(citizen, make_browser):
    create(citizen, title="내 민원 하나")
    other = make_browser("203.0.113.30")
    other.login("citizen2")
    create(other, title="다른 사람 민원")
    titles = [p["title"] for p in citizen.get("/api/v1/petitions/mine").json()["data"]["items"]]
    assert titles == ["내 민원 하나"]


def test_owner_can_read_detail(citizen):
    pid = create(citizen).json()["data"]["id"]
    assert citizen.get(f"/api/v1/petitions/{pid}").status_code == 200


def test_other_citizen_gets_404_not_403(citizen, make_browser):
    pid = create(citizen).json()["data"]["id"]
    other = make_browser("203.0.113.31")
    other.login("citizen2")
    assert other.get(f"/api/v1/petitions/{pid}").status_code == 404


def test_staff_can_read_any_petition(citizen, staff):
    pid = create(citizen).json()["data"]["id"]
    assert staff.get(f"/api/v1/petitions/{pid}").status_code == 200


def test_missing_petition_is_404(citizen):
    assert citizen.get("/api/v1/petitions/9999").status_code == 404


def test_anonymous_cannot_list_mine(make_browser):
    b = make_browser()
    b.start()
    assert b.get("/api/v1/petitions/mine").status_code == 401


def test_petition_body_is_not_in_events(citizen, settings):
    create(citizen, body="민감한 본문 내용입니다 1234")
    text = open(settings.event_log_path, encoding="utf-8").read()
    assert "민감한 본문" not in text
