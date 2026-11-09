import { useState, type FormEvent, type ReactNode } from "react";
import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { ApiError, STATUS_LABEL, type Petition } from "./api";
import { homePathFor, useAuth } from "./auth";

export function errorText(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return "알 수 없는 오류가 발생했습니다.";
}

export function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  return (
    <>
      <a className="skip-link" href="#main">본문으로 건너뛰기</a>
      <header className="site-header">
        <Link to={user ? homePathFor(user) : "/"} className="brand">누리시청 <span>민원 포털</span></Link>
        <nav aria-label="주 메뉴">
          {!user && <NavLink to="/login">로그인</NavLink>}
          {!user && <NavLink to="/register">가입</NavLink>}
          {user?.role === "citizen" && <NavLink to="/" end>내 민원</NavLink>}
          {user?.role === "staff" && <NavLink to="/staff">민원 처리</NavLink>}
          {user?.role === "admin" && <NavLink to="/staff">민원 처리</NavLink>}
          {user?.role === "admin" && <NavLink to="/admin">계정 관리</NavLink>}
          {user && (
            <button type="button" className="link-button"
              onClick={async () => { await logout(); navigate("/login"); }}>
              로그아웃 ({user.display_name})
            </button>
          )}
        </nav>
      </header>
      <main id="main" className="container"><Outlet /></main>
      <footer className="site-footer">가상 기관 시연용 포털입니다. 실제 민원을 접수하지 않습니다.</footer>
    </>
  );
}

export function StatusBadge({ status }: { status: Petition["status"] }) {
  return <span className={`badge badge-${status}`}>{STATUS_LABEL[status]}</span>;
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className="field"><span>{label}</span>{children}</label>;
}

/** 오류·안내 문구. 스크린리더가 바로 읽도록 role을 둔다. */
export function Notice({ kind, children }: { kind: "error" | "info" | "success"; children: ReactNode }) {
  return <p role={kind === "error" ? "alert" : "status"} className={`notice ${kind}`}>{children}</p>;
}

/** 폼 제출 중 중복 전송을 막고 오류를 보여 주는 작은 도우미. */
export function useSubmit(action: () => Promise<void>) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try { await action(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  return { busy, error, onSubmit };
}

export function formatTime(iso: string): string {
  return new Date(iso + "Z").toLocaleString("ko-KR", { dateStyle: "short", timeStyle: "short" });
}
