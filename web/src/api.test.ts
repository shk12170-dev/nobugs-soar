import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as api from "./api";

type Call = { url: string; init: RequestInit };

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

let calls: Call[];
let queue: Response[];

beforeEach(() => {
  api.resetCsrf();
  calls = [];
  queue = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const next = queue.shift();
    if (!next) throw new Error(`예상하지 못한 요청: ${url}`);
    return next;
  }));
});
afterEach(() => vi.unstubAllGlobals());

const me = (token = "csrf-1") => jsonResponse({ data: { user: null, csrf_token: token } });
const header = (call: Call, name: string) => (call.init.headers as Record<string, string>)[name];

describe("CSRF", () => {
  it("변경 요청 전에 토큰을 받아 헤더에 싣는다", async () => {
    queue.push(me("tok-A"), jsonResponse({ data: { id: 1 } }, 201));
    await api.register("newuser", "새사용자", "long-enough-pw");
    expect(calls.map((c) => c.url)).toEqual(["/api/v1/auth/me", "/api/v1/auth/register"]);
    expect(header(calls[1], "X-CSRF-Token")).toBe("tok-A");
    expect(calls[1].init.credentials).toBe("same-origin");
  });

  it("GET 요청에는 CSRF 헤더를 붙이지 않는다", async () => {
    queue.push(jsonResponse({ data: { items: [] } }));
    await api.petitions.mine();
    expect((calls[0].init.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
  });

  it("토큰을 받은 뒤에는 다시 받지 않는다", async () => {
    queue.push(me(), jsonResponse({ data: {} }), jsonResponse({ data: {} }));
    await api.staff.assign(1);
    await api.staff.assign(2);
    expect(calls.filter((c) => c.url.endsWith("/auth/me"))).toHaveLength(1);
  });

  it("CSRF 거절이면 새 토큰을 받아 한 번만 다시 시도한다", async () => {
    queue.push(me("old"), jsonResponse({ error: { code: "CSRF_FAILED", message: "만료" } }, 403), me("fresh"),
      jsonResponse({ data: { ok: true } }));
    await api.staff.assign(1);
    expect(header(calls[1], "X-CSRF-Token")).toBe("old");
    expect(header(calls[3], "X-CSRF-Token")).toBe("fresh");
  });

  it("재시도해도 거절되면 오류로 끝낸다(무한 반복 없음)", async () => {
    const reject = () => jsonResponse({ error: { code: "CSRF_FAILED", message: "만료" } }, 403);
    queue.push(me("a"), reject(), me("b"), reject());
    await expect(api.staff.assign(1)).rejects.toMatchObject({ status: 403, code: "CSRF_FAILED" });
    expect(calls).toHaveLength(4);
  });

  it("로그인 응답의 새 토큰을 이후 요청에 쓴다", async () => {
    queue.push(me("before"), jsonResponse({ data: { user: { id: 1, username: "u", display_name: "u", role: "citizen" },
      csrf_token: "after-login" } }), jsonResponse({ data: { id: 9 } }, 201));
    await api.login("u", "pw");
    await api.petitions.create({ category: "road", title: "제목", body: "내용입니다" });
    expect(header(calls[2], "X-CSRF-Token")).toBe("after-login");
  });
});

describe("오류 처리", () => {
  it("서버 오류 형식을 ApiError로 바꾼다", async () => {
    queue.push(jsonResponse({ error: { code: "INVALID_CREDENTIALS", message: "확인해 주세요" } }, 401));
    await expect(api.refreshSession()).rejects.toMatchObject({
      name: "Error", status: 401, code: "INVALID_CREDENTIALS", message: "확인해 주세요",
    });
  });

  it("JSON이 아닌 응답도 안전한 메시지로 처리한다", async () => {
    queue.push(new Response("<html>bad gateway</html>", { status: 502 }));
    await expect(api.refreshSession()).rejects.toMatchObject({ status: 502, code: "HTTP_ERROR" });
  });
});

describe("요청 형태", () => {
  it("관리자 목록 조회는 필터를 쿼리로 보낸다", async () => {
    queue.push(jsonResponse({ data: { total: 0, items: [] } }));
    await api.admin.users({ q: "kim", role: "staff", locked: false });
    expect(calls[0].url).toBe("/api/v1/admin/users?q=kim&role=staff&locked=false");
  });

  it("상태 변경은 기대 버전을 함께 보낸다", async () => {
    queue.push(me(), jsonResponse({ data: {} }));
    await api.staff.status(5, "processing", 3);
    expect(JSON.parse(calls[1].init.body as string)).toEqual({ status: "processing", expected_version: 3, note: "" });
  });

  it("토큰·비밀번호를 localStorage에 저장하지 않는다", async () => {
    queue.push(me("secret-token"), jsonResponse({ data: { user: { id: 1, username: "u", display_name: "u", role: "citizen" },
      csrf_token: "secret-token-2" } }));
    await api.login("u", "pw-pw-pw-pw-pw");
    expect(JSON.stringify({ ...localStorage })).not.toContain("secret-token");
    expect(JSON.stringify({ ...sessionStorage })).not.toContain("secret-token");
  });
});
