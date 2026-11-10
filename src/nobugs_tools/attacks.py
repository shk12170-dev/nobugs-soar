"""공격 재현 스크립트(자기 포털·루프백 전용). 탐지·대응 시험용 입력을 만든다.

사용: python -m nobugs_tools.attacks s1 --source 127.0.0.2 --user victim_a --count 10
출발지는 127.x 주소만, 대상은 루프백만 허용한다(실수로 다른 서버를 공격하지 않도록).
"""
from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
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
    try:
        with opener.open(request) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nobugs_tools.attacks")
    sub = parser.add_subparsers(dest="case", required=True)
    s1 = sub.add_parser("s1", help="로그인 무차별 대입")
    s1.add_argument("--base", default="http://127.0.0.1:5100")
    s1.add_argument("--source", default="127.0.0.2")
    s1.add_argument("--user", required=True)
    s1.add_argument("--count", type=int, default=10)
    s1.add_argument("--interval", type=float, default=0.3)
    args = parser.parse_args(argv)
    statuses = s1_login_bruteforce(args.base, username=args.user, count=args.count, source=args.source,
                                   interval=args.interval)
    print(f"S1 공격 {len(statuses)}회 전송, 응답: {sorted(set(statuses))} (출발지 {args.source}, 계정 {args.user})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
