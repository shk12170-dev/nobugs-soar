"""공격 재현 스크립트(자기 포털·루프백 전용). 탐지·대응 시험용 입력을 만든다.

사용: python -m nobugs_tools.attacks s1 --source 127.0.0.2 --user victim_a --count 10
      s4 | s8 | s10 | s12 도 같은 방식(--help 참고)
출발지는 127.x 주소만, 대상은 루프백만 허용한다(실수로 다른 서버를 공격하지 않도록).
"""
from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar


def _assert_loopback(host: str, what: str) -> None:
    try:
        ok = ipaddress.ip_address(host).is_loopback
    except ValueError:
        ok = host == "localhost"
    if not ok:
        raise ValueError(f"{what}은(는) 루프백 주소만 허용합니다: {host}")


def bound_opener(source: str) -> urllib.request.OpenerDirector:
    """지정한 출발지 주소(127.x)로 나가는 연결을 쓰는 opener. 포털이 보는 src_ip가 이 값이 된다."""
    _assert_loopback(source, "출발지")

    class Conn(http.client.HTTPConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, source_address=(source, 0), **kwargs)

    class Handler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(Conn, req)

    return urllib.request.build_opener(Handler, urllib.request.HTTPCookieProcessor(CookieJar()))


def _call(opener, base: str, method: str, path: str, csrf: str | None = None, body: dict | None = None):
    headers = {"Content-Type": "application/json"}
    if csrf:
        headers["X-CSRF-Token"] = csrf
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(base + path, method=method, data=data, headers=headers)
    def _body(raw: bytes) -> dict:
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return {}

    try:
        with opener.open(request) as response:
            return response.status, _body(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _body(exc.read())


def s1_login_bruteforce(base_url: str, *, username: str, count: int = 10, source: str = "127.0.0.2",
                        interval: float = 0.3) -> list[int]:
    """한 계정에 틀린 비밀번호로 로그인을 `count`번 시도한다. 응답 상태 코드 목록을 돌려준다."""
    _assert_loopback(urllib.parse.urlparse(base_url).hostname or "", "대상")
    opener = bound_opener(source)
    _, me = _call(opener, base_url, "GET", "/api/v1/auth/me")
    csrf = me["data"]["csrf_token"]
    statuses = []
    for i in range(count):
        status, _ = _call(opener, base_url, "POST", "/api/v1/auth/login", csrf,
                          {"username": username, "password": f"wrong-password-{i}"})
        statuses.append(status)
        if i < count - 1:
            time.sleep(interval)
    return statuses


def _csrf(opener, base: str) -> str:
    return _call(opener, base, "GET", "/api/v1/auth/me")[1]["data"]["csrf_token"]


def s4_failure_then_success(base_url: str, *, username: str, password: str, failures: int = 5,
                            source: str = "127.0.0.2", interval: float = 0.3) -> list[int]:
    """같은 계정에 틀린 비밀번호로 몇 번 실패한 뒤 맞는 비밀번호로 로그인에 성공한다(계정 탈취 재현).

    `password`는 시험용 `zz_` 계정의 실제 비밀번호를 넘긴다(일반 계정에는 쓰지 않는다).
    """
    _assert_loopback(urllib.parse.urlparse(base_url).hostname or "", "대상")
    opener = bound_opener(source)
    csrf = _csrf(opener, base_url)
    statuses = []
    for i in range(failures):
        statuses.append(_call(opener, base_url, "POST", "/api/v1/auth/login", csrf,
                              {"username": username, "password": f"wrong-password-{i}"})[0])
        time.sleep(interval)
    statuses.append(_call(opener, base_url, "POST", "/api/v1/auth/login", csrf,
                          {"username": username, "password": password})[0])
    return statuses


SCAN_PATHS = ("/.env", "/wp-login.php", "/phpmyadmin", "/backup.zip", "/config.php", "/.git/config",
              "/server-status", "/.ssh/id_rsa")      # 포털에 없는 경로만(실제 SPA 라우트는 피한다)


def s8_scan_then_login(base_url: str, *, username: str = "scanner_probe", scans: int = 8, logins: int = 3,
                       source: str = "127.0.0.2", interval: float = 0.2) -> dict[str, list[int]]:
    """존재하지 않는 경로를 몇 번 조회한 뒤(웹 스캔 재현) 로그인 실패를 몇 번 낸다."""
    _assert_loopback(urllib.parse.urlparse(base_url).hostname or "", "대상")
    opener = bound_opener(source)
    csrf = _csrf(opener, base_url)
    scan = []
    for i in range(scans):
        scan.append(_call(opener, base_url, "GET", SCAN_PATHS[i % len(SCAN_PATHS)])[0])
        time.sleep(interval)
    login = [_call(opener, base_url, "POST", "/api/v1/auth/login", csrf,
                   {"username": username, "password": f"wrong-{i}"})[0] for i in range(logins)]
    return {"scan": scan, "login": login}


def boundary_signal(source: str, gelf_host: str = "127.0.0.1", gelf_port: int = 12301) -> None:
    """경계 방화벽이 보냈을 법한 차단 신호 한 건을 GELF로 보낸다(기록상의 신호일 뿐, 실제 차단은 하지 않는다)."""
    _assert_loopback(source, "출발지")
    _assert_loopback(gelf_host, "GELF 대상")
    message = {"version": "1.1", "host": "boundary-sim", "short_message": "boundary.block_signal",
               "_rule": "boundary-block", "_src_ip": source, "_event_type": "boundary.block_signal",
               "_outcome": "simulated", "_asset_id": "boundary-sim"}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(json.dumps(message).encode(), (gelf_host, gelf_port))


def s10_three_layer(base_url: str, *, source: str = "127.0.0.2", gelf_port: int = 12301, **kwargs) -> dict:
    """S8과 같은 시퀀스를 보내고, 경계 차단 신호를 한 건 더한다(세 종류 신호 재현)."""
    result = s8_scan_then_login(base_url, source=source, **kwargs)
    boundary_signal(source, gelf_port=gelf_port)
    return {**result, "boundary_signal": 1}


def s12_request_burst(base_url: str, *, requests: int = 120, interval: float = 0.0,
                      source: str = "127.0.0.2") -> list[int]:
    """같은 출발지에서 가벼운 상태 조회(`/api/v1/health`)를 순서대로 여러 번 보낸다(요청 수 임계값 재현용).

    엔진은 횟수만으로는 차단하지 않고 서비스가 실제로 느려졌는지 건강 검사로 다시 확인한다(S12 설계).
    """
    _assert_loopback(urllib.parse.urlparse(base_url).hostname or "", "대상")
    opener = bound_opener(source)
    statuses = []
    for _ in range(requests):
        statuses.append(_call(opener, base_url, "GET", "/api/v1/health")[0])
        if interval:
            time.sleep(interval)
    return statuses


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nobugs_tools.attacks")
    sub = parser.add_subparsers(dest="case", required=True)

    def common(p, user=False):
        p.add_argument("--base", default="http://127.0.0.1:5100")
        p.add_argument("--source", default="127.0.0.2")
        if user:
            p.add_argument("--user", required=True)

    s1 = sub.add_parser("s1", help="로그인 무차별 대입")
    common(s1, True)
    s1.add_argument("--count", type=int, default=10)
    s1.add_argument("--interval", type=float, default=0.3)

    s4 = sub.add_parser("s4", help="로그인 실패 뒤 성공(계정 탈취 재현, 시험 계정 전용)")
    common(s4, True)
    s4.add_argument("--password", required=True, help="시험 계정의 실제 비밀번호")
    s4.add_argument("--failures", type=int, default=5)

    s8 = sub.add_parser("s8", help="웹 스캔 뒤 로그인 시도")
    common(s8)

    s10 = sub.add_parser("s10", help="스캔·로그인·경계 신호 연쇄")
    common(s10)
    s10.add_argument("--gelf-port", type=int, default=12301)

    s12 = sub.add_parser("s12", help="같은 출발지의 요청 횟수 임계값 재현(가벼운 상태 조회 반복)")
    common(s12)
    s12.add_argument("--requests", type=int, default=120)
    s12.add_argument("--interval", type=float, default=0.0)

    a = parser.parse_args(argv)
    if a.case == "s1":
        out = s1_login_bruteforce(a.base, username=a.user, count=a.count, source=a.source, interval=a.interval)
        print(f"S1 공격 {len(out)}회 전송, 응답: {sorted(set(out))} (출발지 {a.source}, 계정 {a.user})")
    elif a.case == "s4":
        out = s4_failure_then_success(a.base, username=a.user, password=a.password, failures=a.failures,
                                      source=a.source)
        print(f"S4 실패 {a.failures}회 뒤 성공 시도, 응답: {out} (출발지 {a.source}, 계정 {a.user})")
    elif a.case == "s8":
        print(f"S8 스캔·로그인 시도 응답: {s8_scan_then_login(a.base, source=a.source)} (출발지 {a.source})")
    elif a.case == "s10":
        print(f"S10 연쇄 시도 응답: {s10_three_layer(a.base, source=a.source, gelf_port=a.gelf_port)}")
    else:
        out = s12_request_burst(a.base, requests=a.requests, interval=a.interval, source=a.source)
        print(f"S12 요청 {len(out)}건 전송, 응답: {sorted(set(out))} (출발지 {a.source})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
