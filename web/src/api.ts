// 포털 API 클라이언트. CSRF 토큰은 메모리에만 둔다(localStorage에 저장하지 않는다).

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export type Role = "citizen" | "staff" | "admin";
export interface User { id: number; username: string; display_name: string; role: Role; locked?: boolean }
export interface HistoryItem { action: string; note: string; actor_id: number; created_at: string }
export interface Petition {
  id: number; owner_id: number; category: string; title: string; body: string;
  status: "received" | "assigned" | "processing" | "done"; assignee_id: number | null; version: number;
  created_at: string; updated_at: string; history?: HistoryItem[];
}

let csrfToken: string | null = null;

/** 테스트에서 상태를 초기화할 때 쓴다. */
export function resetCsrf(): void {
  csrfToken = null;
}

async function send<T>(method: string, path: string, body?: unknown, retried = false): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") {
    if (csrfToken === null) await refreshSession();
    headers["X-CSRF-Token"] = csrfToken ?? "";
  }
  const response = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const error = payload?.error ?? {};
    // 세션이 바뀌었거나 만료돼 CSRF 토큰이 어긋나면 새 토큰을 받아 한 번만 다시 시도한다
    if (error.code === "CSRF_FAILED" && !retried && method !== "GET") {
      await refreshSession();
      return send<T>(method, path, body, true);
    }
    throw new ApiError(response.status, error.code ?? "HTTP_ERROR", error.message ?? "요청을 처리하지 못했습니다.");
  }
  return payload.data as T;
}

/** 현재 사용자와 CSRF 토큰을 가져온다(세션이 없으면 서버가 새로 만든다). */
export async function refreshSession(): Promise<User | null> {
  const data = await send<{ user: User | null; csrf_token: string }>("GET", "/api/v1/auth/me");
  csrfToken = data.csrf_token;
  return data.user;
}

export async function register(username: string, displayName: string, password: string): Promise<User> {
  return send<User>("POST", "/api/v1/auth/register", { username, display_name: displayName, password });
}

export async function login(username: string, password: string): Promise<User> {
  const data = await send<{ user: User; csrf_token: string }>("POST", "/api/v1/auth/login", { username, password });
  csrfToken = data.csrf_token; // 로그인하면 세션과 함께 토큰도 새로 발급된다
  return data.user;
}

export async function logout(): Promise<void> {
  await send("POST", "/api/v1/auth/logout", {});
  csrfToken = null;
}

export const petitions = {
  create: (input: { category: string; title: string; body: string }) => send<Petition>("POST", "/api/v1/petitions", input),
  mine: () => send<{ items: Petition[] }>("GET", "/api/v1/petitions/mine").then((d) => d.items),
  get: (id: number) => send<Petition>("GET", `/api/v1/petitions/${id}`),
};

export const staff = {
  list: (status?: string) =>
    send<{ items: Petition[] }>("GET", `/api/v1/staff/petitions${status ? `?status=${encodeURIComponent(status)}` : ""}`)
      .then((d) => d.items),
  assign: (id: number, assigneeId?: number) =>
    send<Petition>("POST", `/api/v1/staff/petitions/${id}/assign`, assigneeId === undefined ? {} : { assignee_id: assigneeId }),
  status: (id: number, status: "processing" | "done", expectedVersion: number, note = "") =>
    send<Petition>("POST", `/api/v1/staff/petitions/${id}/status`, { status, expected_version: expectedVersion, note }),
  reply: (id: number, note: string) => send<Petition>("POST", `/api/v1/staff/petitions/${id}/reply`, { note }),
};

export interface UserQuery { q?: string; role?: string; locked?: boolean }
export const admin = {
  users: (query: UserQuery = {}) => {
    const params = new URLSearchParams();
    if (query.q) params.set("q", query.q);
    if (query.role) params.set("role", query.role);
    if (query.locked !== undefined) params.set("locked", String(query.locked));
    const suffix = params.toString() ? `?${params}` : "";
    return send<{ total: number; items: User[] }>("GET", `/api/v1/admin/users${suffix}`);
  },
  lock: (id: number) => send<{ locked: boolean; revoked_sessions: number }>("POST", `/api/v1/admin/users/${id}/lock`, {}),
  unlock: (id: number) => send<{ locked: boolean }>("POST", `/api/v1/admin/users/${id}/unlock`, {}),
  resetPassword: (id: number, newPassword: string) =>
    send<{ locked: boolean }>("POST", `/api/v1/admin/users/${id}/reset-password`, { new_password: newPassword }),
};

export const STATUS_LABEL: Record<Petition["status"], string> = {
  received: "접수", assigned: "배정", processing: "처리 중", done: "완료",
};
export const CATEGORY_LABEL: Record<string, string> = {
  road: "도로·시설", environment: "환경", welfare: "복지", traffic: "교통", etc: "기타",
};
