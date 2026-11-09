"""공용 픽스처. 테스트 클라이언트는 출발지 IP를 직접 지정할 수 있다(연결 정보로 쓰이므로)."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from nobugs_portal.app import create_public_app
from nobugs_portal.config import Settings
from nobugs_portal.control import create_control_app
from nobugs_portal.models import User
from nobugs_portal.security import hash_password
from nobugs_portal.state import AppState

PASSWORD = "Synthetic-Passw0rd-123"
KEY = "test-response-key-0123456789abcd"
USERS = [("citizen1", "citizen"), ("citizen2", "citizen"), ("staff1", "staff"), ("staff2", "staff"),
         ("admin1", "admin")]


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
                    event_log_path=str(tmp_path / "events.jsonl"), login_rate_limit=100,
                    response_api_key=KEY, response_allowed_cidrs=("127.0.0.0/8", "10.0.0.0/8"))


@pytest.fixture
def state(settings):
    st = AppState.build(settings)
    hashed = hash_password(PASSWORD)
    with st.db.session() as db:
        db.add_all([User(username=name, display_name=f"{name} 이름", password_hash=hashed, role=role)
                    for name, role in USERS])
        db.commit()
    yield st
    st.db.dispose()


@pytest.fixture
def public_app(state):
    return create_public_app(state=state)


@pytest.fixture
def control_app(state):
    return create_control_app(state=state)


class Browser:
    """세션 쿠키와 CSRF 토큰을 자동으로 처리하는 테스트용 브라우저."""

    def __init__(self, app, ip: str = "203.0.113.10") -> None:
        self.client = TestClient(app, client=(ip, 50000))
        self.csrf: str | None = None

    def start(self):
        response = self.client.get("/api/v1/auth/me")
        self.csrf = response.json()["data"]["csrf_token"]
        return response

    def get(self, path, **kw):
        return self.client.get(path, **kw)

    def post(self, path, json=None, **kw):
        headers = {"X-CSRF-Token": self.csrf or "", **kw.pop("headers", {})}
        return self.client.post(path, json=json, headers=headers, **kw)

    def login(self, username: str = "citizen1", password: str = PASSWORD):
        self.start()
        response = self.post("/api/v1/auth/login", {"username": username, "password": password})
        if response.status_code == 200:
            self.csrf = response.json()["data"]["csrf_token"]
        return response


@pytest.fixture
def make_browser(public_app):
    def factory(ip: str = "203.0.113.10") -> Browser:
        return Browser(public_app, ip)

    return factory


@pytest.fixture
def citizen(make_browser):
    b = make_browser("203.0.113.11")
    assert b.login("citizen1").status_code == 200
    return b


@pytest.fixture
def staff(make_browser):
    b = make_browser("203.0.113.12")
    assert b.login("staff1").status_code == 200
    return b


@pytest.fixture
def admin(make_browser):
    b = make_browser("203.0.113.13")
    assert b.login("admin1").status_code == 200
    return b


class Control:
    def __init__(self, app, ip: str = "127.0.0.1", key: str | None = KEY) -> None:
        self.client = TestClient(app, client=(ip, 50000))
        self.key = key
        self.counter = 0

    def headers(self, idem: str | None = None, key: str | None = "default"):
        headers = {}
        use_key = self.key if key == "default" else key
        if use_key is not None:
            headers["X-Response-Key"] = use_key
        if idem:
            headers["Idempotency-Key"] = idem
        return headers

    def get(self, path, **kw):
        return self.client.get(path, headers=self.headers(key=kw.pop("key", "default")))

    def post(self, path, body, idem: str | None = "auto", key: str | None = "default"):
        if idem == "auto":
            self.counter += 1
            idem = f"test-idem-key-{self.counter:08d}"
        return self.client.post(path, content=json.dumps(body), headers={**self.headers(idem, key),
                                                                         "Content-Type": "application/json"})


@pytest.fixture
def control(control_app):
    return Control(control_app)


def read_events(settings: Settings) -> list[dict]:
    try:
        with open(settings.event_log_path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []
