"""실습 제어판: 한 화면에서 공격을 재현하고, 엔진 티켓이 6단계(공격 → 탐지 → 조치 →
반영 확인 → 효과 확인 → 원복)를 밟는 과정을 5초마다 자동 갱신으로 본다.

이 제어판은 스스로 상태를 만들지 않는다. 엔진 REST API(기본 http://127.0.0.1:5200)를 읽어
티켓·액션을 6단계로 환산해 보여줄 뿐이고, 공격 버튼은 nobugs_tools.attacks(자기 포털·루프백 전용)를
그대로 부른다. 사람이 닫는 단계(⑥ 원복 뒤 확인)는 엔진 close API로 넘긴다(엔진 키는 .env에서 읽어 서버가 쥔다).

사용: python -m nobugs_tools.panel            # http://127.0.0.1:5102
포트는 포털(5100)·대응 API(5101)·엔진(5200)과 겹치지 않게 5102를 기본으로 쓴다.
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import attacks

# 6단계의 이름. 팀 제어판 UX와 같은 순서로 맞춘다.
STEP_LABELS = ("① 공격", "② 탐지", "③ 조치", "④ 반영 확인", "⑤ 효과 확인", "⑥ 원복")
RELEASE_KINDS = {"ip_release", "boundary_release", "account_unlock"}


def ticket_steps(ticket: dict) -> list[dict]:
    """티켓 하나(액션 포함)를 6단계 상태로 환산한다. 각 단계는 done/active/pending 중 하나다.

    - ① 공격·② 탐지: 티켓이 있다는 것은 탐지가 들어왔다는 뜻이므로 늘 완료.
    - ③ 조치: 액션이 하나라도 요청됐거나 상태가 open을 벗어났으면 완료.
    - ④ 반영 확인: 액션 중 applied_verified=True가 있으면 완료(차단·잠금이 실제로 걸렸다).
    - ⑤ 효과 확인: 액션 중 effect_verified=True가 있으면 완료(공격자 403·서비스 정상 등 재확인).
    - ⑥ 원복: 해제 액션이 있거나 상태가 restored/closed면 완료(TTL 자동 원복 또는 복구).
    첫 번째 미완료 단계를 active로, 나머지를 pending으로 표시한다.
    """
    status = ticket.get("status", "")
    actions = ticket.get("actions") or []
    # 엔진 상태기계는 조치 → 반영·효과 확인을 거쳐야만 verified/restored/closed로 올라가므로,
    # 액션 증거가 없더라도 상태만으로 그 단계까지 끝났음을 인정한다(액션 증거가 있으면 그대로 완료).
    applied = any(a.get("applied_verified") is True for a in actions) or status in ("verified", "restored", "closed")
    effect = any(a.get("effect_verified") is True for a in actions) or status in ("verified", "restored", "closed")
    released = any(a.get("kind") in RELEASE_KINDS for a in actions)
    flags = (
        True,
        True,
        bool(actions) or status not in ("", "open"),
        applied,
        effect,
        released or status in ("restored", "closed"),
    )
    steps: list[dict] = []
    active_taken = False
    for label, ok in zip(STEP_LABELS, flags, strict=True):
        if ok:
            state = "done"
        elif not active_taken:
            state, active_taken = "active", True
        else:
            state = "pending"
        steps.append({"label": label, "state": state})
    return steps


class EngineClient:
    """엔진 REST API를 읽고, 사람이 닫는 단계만 쓰기(close)로 넘기는 얇은 클라이언트."""

    def __init__(self, base_url: str, engine_key: str, timeout: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.engine_key = engine_key
        self.timeout = timeout

    def _get(self, path: str) -> dict:
        # 엔진이 조회 인증(NB_ENGINE_READ_AUTH)을 켰을 때도 읽을 수 있게 키를 함께 보낸다
        headers = {"X-Engine-Key": self.engine_key} if self.engine_key else {}
        req = urllib.request.Request(self.base_url + path, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read() or b"{}")

    def tickets(self, limit: int = 8) -> list[dict]:
        """최근 티켓을 액션까지 붙여 돌려준다. 엔진이 안 떠 있으면 빈 목록."""
        try:
            items = self._get(f"/api/v1/tickets?limit={limit}")["data"]["items"]
        except (urllib.error.URLError, OSError, KeyError, json.JSONDecodeError):
            return []
        full: list[dict] = []
        for t in items:
            try:
                full.append(self._get(f"/api/v1/tickets/{t['id']}")["data"])
            except (urllib.error.URLError, OSError, KeyError, json.JSONDecodeError):
                full.append(t)
        return full

    def close(self, ticket_id: str, note: str) -> tuple[int, dict]:
        url = f"{self.base_url}/api/v1/tickets/{ticket_id}/close?note={urllib.parse.quote(note)}"
        req = urllib.request.Request(url, method="POST", headers={"X-Engine-Key": self.engine_key})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, {}


# 제어판이 바로 쏠 수 있는 공격(비밀값이 필요 없는 것만). S4는 시험 계정 비밀번호가 필요해 버튼에서 뺀다.
ATTACKS = {
    "s1": "S1 로그인 무차별 대입",
    "s8": "S8 웹 스캔→로그인",
    "s10": "S10 스캔·로그인·경계 신호",
    "s7": "S7 홈페이지 변조(Wazuh 필요)",
}


def run_attack(case: str, portal_url: str, web_root: str, gelf_port: int) -> str:
    """제어판 버튼 → 공격 재현. 출발지는 매번 다른 127.x로 잡아 재시도끼리 겹치지 않게 한다."""
    salt = int(time.time()) % 240 + 11
    source = f"127.44.{salt}.1"
    if case == "s1":
        out = attacks.s1_login_bruteforce(portal_url, username=f"zz_panel_{salt}", count=10, source=source)
        return f"S1 {len(out)}회 전송(출발지 {source}) 응답 {sorted(set(out))}"
    if case == "s8":
        out = attacks.s8_scan_then_login(portal_url, source=source)
        return f"S8 스캔·로그인(출발지 {source}) {out}"
    if case == "s10":
        out = attacks.s10_three_layer(portal_url, source=source, gelf_port=gelf_port)
        return f"S10 연쇄(출발지 {source}) {out}"
    if case == "s7":
        out = attacks.s7_deface(portal_url, web_root, "index.html", source=source)
        return f"S7 변조 재현 index.html, 방문 응답 {out['visit_status']}(출발지 {source})"
    return f"알 수 없는 케이스: {case}"


def render_page(links: dict[str, str]) -> str:
    """정적 뼈대(링크·공격 버튼·자리). 티켓 6단계는 /api/state를 받아 JS가 5초마다 채운다."""
    link_row = " · ".join(f"<a href='{escape(u)}' target=_blank>{escape(name)}</a>" for name, u in links.items())
    buttons = "".join(f"<button data-case='{c}'>{escape(label)}</button>" for c, label in ATTACKS.items())
    return f"""<!doctype html><html lang=ko><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>실습 제어판</title>
<style>
:root{{color-scheme:light dark}}
body{{font:15px system-ui,Segoe UI,sans-serif;max-width:1100px;margin:20px auto;padding:0 16px}}
h1{{font-size:20px;margin:0 0 4px}}
.links{{margin:8px 0 16px;font-size:14px}}
.bar{{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0 0 8px}}
button{{font:14px system-ui;padding:7px 12px;border:1px solid #888;border-radius:8px;background:#f4f4f4;cursor:pointer}}
button:hover{{background:#e8e8e8}}
#msg{{font-size:13px;color:#555;min-height:18px;margin:4px 0 12px}}
.ticket{{border:1px solid #bbb;border-radius:10px;padding:10px 12px;margin:10px 0}}
.head{{display:flex;gap:10px;flex-wrap:wrap;align-items:baseline;font-size:14px}}
.head b{{font-size:15px}}
.badge{{font-size:12px;padding:1px 8px;border-radius:10px;border:1px solid #999}}
.steps{{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0 0}}
.step{{flex:1;min-width:120px;border:1px solid #ccc;border-radius:8px;padding:6px 8px;font-size:13px;text-align:center}}
.done{{background:#e7f6e9;border-color:#4a9a5a}}
.active{{background:#fff4d6;border-color:#d6a52a;font-weight:600}}
.pending{{background:#f2f2f2;color:#888}}
.closebtn{{font-size:12px;padding:3px 8px}}
time{{color:#777;font-size:12px}}
@media (prefers-color-scheme:dark){{
 button{{background:#2a2a2a;border-color:#666;color:#eee}} button:hover{{background:#333}}
 .ticket{{border-color:#555}} .step{{border-color:#444}}
 .done{{background:#17341c;border-color:#3f7a4c}} .active{{background:#3a3112;border-color:#b58f2a}}
 .pending{{background:#262626;color:#999}} #msg{{color:#aaa}}
}}
</style>
<h1>실습 제어판 — 공격 → 탐지 → 조치 → 반영 확인 → 효과 확인 → 원복</h1>
<div class=links>{link_row}</div>
<div class=bar>{buttons}
<span style="font-size:13px;color:#777">공격을 누르면 Graylog가 탐지한 뒤(보통 1분 안) 티켓이 올라온다</span></div>
<div id=msg></div>
<div id=tickets><p style="color:#888">불러오는 중…</p></div>
<script>
async function act(ev){{
  const b=ev.target.closest('button[data-case]'); if(!b) return;
  b.disabled=true; msg.textContent=b.textContent+' 실행 중…';
  try{{
    const r=await fetch('/api/attack',{{method:'POST',headers:{{'content-type':'application/json'}},
      body:JSON.stringify({{case:b.dataset.case}})}});
    const j=await r.json(); msg.textContent=j.message||'';
  }}catch(e){{ msg.textContent='실패: '+e; }}
  b.disabled=false; setTimeout(load, 1500);
}}
async function close(id){{
  msg.textContent=id+' 닫는 중…';
  const r=await fetch('/api/close',{{method:'POST',headers:{{'content-type':'application/json'}},
    body:JSON.stringify({{id}})}});
  const j=await r.json(); msg.textContent=j.message||''; load();
}}
function stepHtml(s){{return `<div class="step ${{s.state}}">${{s.label}}</div>`}}
function ticketHtml(t){{
  const steps=t.steps.map(stepHtml).join('');
  const canClose=(t.status==='restored');
  const btn=canClose?`<button class=closebtn onclick="close('${{t.id}}')">⑥ 사람 확인(닫기)</button>`:'';
  return `<div class=ticket><div class=head><b>${{t.id}}</b>
    <span class=badge>${{t.case_id}}</span>
    <span>출발지 ${{t.src_ip||'-'}}</span><span>계정 ${{t.username||'-'}}</span>
    <span class=badge>${{t.status}}</span>${{btn}}</div>
    <div class=steps>${{steps}}</div>
    ${{t.close_note?`<div><time>${{t.close_note}}</time></div>`:''}}</div>`;
}}
async function load(){{
  try{{
    const r=await fetch('/api/state'); const j=await r.json();
    const empty='<p style="color:#888">티켓이 아직 없습니다. 위 버튼으로 공격을 재현해 보세요.</p>';
    tickets.innerHTML=j.tickets.length?j.tickets.map(ticketHtml).join(''):empty;
  }}catch(e){{ tickets.innerHTML='<p style="color:#c00">엔진(5200)에 닿지 못했습니다: '+e+'</p>'; }}
}}
document.querySelector('.bar').addEventListener('click', act);
load(); setInterval(load, 5000);
</script>
"""


def make_handler(client: EngineClient, links: dict[str, str], portal_url: str, web_root: str,
                 gelf_port: int, limit: int):
    page = render_page(links)

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, obj: dict) -> None:
            self._send(status, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                return json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return {}

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/" or self.path.startswith("/index"):
                self._send(200, page.encode(), "text/html; charset=utf-8")
            elif self.path.startswith("/api/state"):
                tickets = [{**t, "steps": ticket_steps(t)} for t in client.tickets(limit)]
                self._json(200, {"tickets": tickets})
            else:
                self._json(404, {"message": "없는 경로"})

        def do_POST(self) -> None:  # noqa: N802
            body = self._read_json()
            if self.path == "/api/attack":
                case = str(body.get("case", ""))
                if case not in ATTACKS:
                    self._json(400, {"message": f"알 수 없는 공격: {case}"})
                    return
                try:
                    msg = run_attack(case, portal_url, web_root, gelf_port)
                    self._json(200, {"message": msg})
                except Exception as exc:  # noqa: BLE001 - 제어판은 죽지 않고 실패 사유만 돌려준다
                    self._json(200, {"message": f"{case} 실패: {exc}"})
            elif self.path == "/api/close":
                tid = str(body.get("id", ""))
                if not tid:
                    self._json(400, {"message": "티켓 번호가 없습니다."})
                    return
                code, _ = client.close(tid, "제어판에서 사람이 확인하고 종료")
                self._json(200, {"message": f"{tid} 닫기 응답 {code}" + (" (완료)" if code == 200 else "")})
            else:
                self._json(404, {"message": "없는 경로"})

        def log_message(self, *_args) -> None:  # 콘솔을 조용히
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    env = os.environ
    parser = argparse.ArgumentParser(prog="nobugs_tools.panel")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5102)
    parser.add_argument("--engine-url", default=env.get("NB_ENGINE_URL", "http://127.0.0.1:5200"))
    parser.add_argument("--portal-url", default=env.get("NB_PORTAL_URL", "http://127.0.0.1:5100"))
    parser.add_argument("--web-root", default=env.get("NB_WEB_ROOT", "web/dist"))
    parser.add_argument("--gelf-port", type=int, default=int(env.get("NB_GELF_PORT", "12301")))
    parser.add_argument("--limit", type=int, default=8)
    args = parser.parse_args(argv)

    links = {
        "민원 포털": args.portal_url,
        "Graylog": env.get("NB_GRAYLOG_URL", "http://127.0.0.1:9100"),
        "n8n": env.get("NB_N8N_URL", "http://127.0.0.1:5678"),
        "엔진 티켓": args.engine_url + "/",
        "pfSense": env.get("NB_PFSENSE_URL", "http://172.16.50.2/"),
    }
    client = EngineClient(args.engine_url, env.get("NB_ENGINE_KEY", ""))
    handler = make_handler(client, links, args.portal_url, args.web_root, args.gelf_port, args.limit)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"실습 제어판: http://{args.host}:{args.port}  (엔진 {args.engine_url}, 포털 {args.portal_url})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
