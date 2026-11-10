"""Graylog REST API 클라이언트와 설정 도구(멱등). 표준 라이브러리만 쓴다.

사용: python -m nobugs_tools.graylog setup      # 입력(GELF) + 탐지 정의 올리기
      python -m nobugs_tools.graylog events     # 최근 발동한 이벤트 보기
.env의 NB_GRAYLOG_URL, NB_GRAYLOG_ADMIN_PASSWORD 를 읽는다.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .definitions import ALL_DEFINITIONS, engine_notification, n8n_relay_notification

ROOT = Path(__file__).resolve().parents[2]
GELF_UDP = ("portal GELF UDP", "org.graylog2.inputs.gelf.udp.GELFUDPInput")
GELF_TCP = ("portal GELF TCP", "org.graylog2.inputs.gelf.tcp.GELFTCPInput")


class GraylogError(RuntimeError):
    pass


def load_env(path: Path | None = None) -> dict[str, str]:
    env = dict(os.environ)
    file = path or ROOT / ".env"
    if file.exists():
        for line in file.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                env.setdefault(key.strip(), value.strip())
    return env


class GraylogClient:
    def __init__(self, base_url: str, password: str, user: str = "admin", timeout: float = 20) -> None:
        self.base = base_url.rstrip("/")
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.timeout = timeout

    def call(self, method: str, path: str, body: Any = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, method=method, data=data, headers={
            "Authorization": self.auth, "X-Requested-By": "nobugs-tools",
            "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raise GraylogError(f"{method} {path} -> {exc.code} {exc.read()[:300].decode('utf-8', 'replace')}") from exc

    def wait_ready(self, seconds: int = 240) -> None:
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                urllib.request.urlopen(self.base + "/api/system/lbstatus", timeout=5).read()
                return
            except (urllib.error.URLError, OSError):
                time.sleep(3)
        raise GraylogError("Graylog가 시간 안에 준비되지 않았습니다.")

    # ---- 입력 ----
    def ensure_gelf_inputs(self) -> list[str]:
        have = {i["title"] for i in self.call("GET", "/api/system/inputs")["inputs"]}
        created = []
        for title, kind in (GELF_UDP, GELF_TCP):
            if title in have:
                continue
            self.call("POST", "/api/system/inputs", {
                "title": title, "type": kind, "global": True,
                "configuration": {"bind_address": "0.0.0.0", "port": 12201, "recv_buffer_size": 262144}})
            created.append(title)
        return created

    # ---- 탐지 정의 ----
    def ensure_event_definition(self, definition: dict[str, Any]) -> tuple[str, bool]:
        """같은 제목의 정의가 있으면 내용을 갱신하고, 없으면 만든다. (id, 새로 만들었는지)"""
        listing = self.call("GET", "/api/events/definitions?per_page=200")["event_definitions"]
        existing = next((d for d in listing if d["title"] == definition["title"]), None)
        if existing is None:
            return self.call("POST", "/api/events/definitions?schedule=true", definition)["id"], True
        self.call("PUT", f"/api/events/definitions/{existing['id']}?schedule=true",
                  {**definition, "id": existing["id"]})
        return existing["id"], False

    # ---- 알림 ----
    def ensure_allowlist(self, url: str) -> bool:
        """Graylog는 허용 목록에 없는 주소로 알림을 보내지 않는다. 없으면 추가한다. 추가했는지 돌려준다.

        id는 url에서 만든다 - 고정 id를 쓰면 엔진·n8n처럼 서로 다른 주소를 둘 다 등록할 때 "중복 id" 오류가
        난다(실제로 겪은 문제).
        """
        current = self.call("GET", "/api/system/urlwhitelist")
        if any(e.get("value") == url for e in current.get("entries", [])):
            return False
        entry_id = "nobugs-" + hashlib.sha256(url.encode()).hexdigest()[:12]
        current.setdefault("entries", []).append({"id": entry_id, "title": f"nobugs 알림 ({url})", "value": url,
                                                  "type": "literal"})
        self.call("PUT", "/api/system/urlwhitelist", current)
        return True

    def ensure_notification(self, notification: dict[str, Any]) -> str:
        """같은 제목의 알림이 있으면 지우고 새로 만든다(수정 API가 형식에 까다로워 교체 방식). 알림 id를 돌려준다."""
        for existing in self.call("GET", "/api/events/notifications?per_page=200")["notifications"]:
            if existing["title"] == notification["title"]:
                self.call("DELETE", f"/api/events/notifications/{existing['id']}")
        return self.call("POST", "/api/events/notifications", notification)["id"]

    def recent_events(self, minutes: int = 15, per_page: int = 50) -> list[dict[str, Any]]:
        body = {"query": "", "filter": {"alerts": "include"}, "page": 1, "per_page": per_page,
                "timerange": {"type": "relative", "range": minutes * 60}}
        return [e["event"] for e in self.call("POST", "/api/events/search", body)["events"]]


def client_from_env(env: dict[str, str] | None = None) -> GraylogClient:
    env = load_env() if env is None else env
    if "NB_GRAYLOG_ADMIN_PASSWORD" not in env:
        raise GraylogError(
            ".env에 NB_GRAYLOG_ADMIN_PASSWORD가 없습니다. python -m nobugs_tools.make_env 를 먼저 실행하세요.")
    return GraylogClient(env.get("NB_GRAYLOG_URL", "http://127.0.0.1:9100"), env["NB_GRAYLOG_ADMIN_PASSWORD"])


def setup(client: GraylogClient, engine_url: str | None = None, engine_key: str = "", live: bool = False,
         n8n_url: str | None = None, n8n_key: str = "") -> None:
    """n8n_url을 주면 S1만 n8n 웹훅으로 보내고(n8n이 엔진 웹훅으로 넘긴다), 나머지 케이스는 그대로 엔진 직결이다."""
    client.wait_ready()
    created = client.ensure_gelf_inputs()
    print("입력:", ", ".join(created) if created else "이미 있음")
    notification_ids: list[str] = []
    if engine_url:
        client.ensure_allowlist(engine_url)
        notification_ids = [client.ensure_notification(engine_notification(engine_url, engine_key, live))]
        print(f"알림: 엔진 웹훅 연결 ({'실제 조치' if live else '모의 실행'} 모드)")
    s1_notification_ids = notification_ids
    if n8n_url:
        client.ensure_allowlist(n8n_url)
        s1_notification_ids = [client.ensure_notification(n8n_relay_notification(n8n_url, n8n_key, live))]
        print("알림: S1만 n8n 웹훅 경유로 연결")
    for case, build in ALL_DEFINITIONS.items():
        ids = s1_notification_ids if case == "S1" else notification_ids
        definition_id, is_new = client.ensure_event_definition(build(notification_ids=ids))
        print(f"탐지 정의 {case}: {'생성' if is_new else '갱신'} ({definition_id})")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nobugs_tools.graylog")
    parser.add_argument("command", choices=["setup", "events"])
    parser.add_argument("--minutes", type=int, default=15)
    parser.add_argument("--engine-url", help="엔진 웹훅 주소(예: http://host.docker.internal:5200/webhook/graylog)")
    parser.add_argument("--live", action="store_true", help="실제 조치 모드(기본은 모의 실행)")
    parser.add_argument("--n8n-url", help="S1만 이 n8n 웹훅 주소로 보낸다(예: http://n8n:5678/webhook/s1)")
    args = parser.parse_args(argv)
    try:
        client = client_from_env()
        if args.command == "setup":
            env = load_env()
            setup(client, args.engine_url, env.get("NB_ENGINE_KEY", ""), args.live, args.n8n_url,
                 env.get("NB_N8N_WEBHOOK_KEY", ""))
        else:
            events = client.recent_events(args.minutes)
            print(f"최근 {args.minutes}분 이벤트 {len(events)}건")
            for e in events[:20]:
                print(e["timestamp"], e["message"][:80], e.get("fields"))
    except GraylogError as exc:
        print(f"오류: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
