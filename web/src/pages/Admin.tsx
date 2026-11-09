import { useCallback, useEffect, useState, type FormEvent } from "react";
import * as api from "../api";
import { type User } from "../api";
import { Field, Notice, errorText } from "../components";

const ROLE_LABEL: Record<string, string> = { citizen: "시민", staff: "담당자", admin: "관리자" };

export function AdminUsersPage() {
  const [q, setQ] = useState("");
  const [role, setRole] = useState("");
  const [locked, setLocked] = useState("");
  const [data, setData] = useState<{ total: number; items: User[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [resetting, setResetting] = useState<User | null>(null);

  const load = useCallback(() => {
    api.admin.users({ q: q || undefined, role: role || undefined, locked: locked === "" ? undefined : locked === "true" })
      .then(setData).catch((e) => setError(errorText(e)));
  }, [q, role, locked]);
  useEffect(() => { load(); }, [load]);

  async function toggle(user: User) {
    setError(null); setMessage(null);
    try {
      if (user.locked) { await api.admin.unlock(user.id); setMessage(`${user.username} 계정의 잠금을 풀었습니다.`); }
      else { await api.admin.lock(user.id); setMessage(`${user.username} 계정을 잠그고 세션을 모두 끊었습니다.`); }
      load();
    } catch (e) { setError(errorText(e)); }
  }

  return (
    <>
      <h1>계정 관리</h1>
      <div className="filters">
        <Field label="검색"><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="아이디·이름" /></Field>
        <Field label="권한">
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="">전체</option>
            {Object.entries(ROLE_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </Field>
        <Field label="이용 상태">
          <select value={locked} onChange={(e) => setLocked(e.target.value)}>
            <option value="">전체</option><option value="false">정상</option><option value="true">잠김</option>
          </select>
        </Field>
      </div>
      {error && <Notice kind="error">{error}</Notice>}
      {message && <Notice kind="success">{message}</Notice>}
      {data === null ? <p role="status">불러오는 중…</p> : (
        <table className="table">
          <caption>총 {data.total}명</caption>
          <thead><tr><th>아이디</th><th>이름</th><th>권한</th><th>상태</th><th>작업</th></tr></thead>
          <tbody>
            {data.items.map((u) => (
              <tr key={u.id}>
                <td>{u.username}</td><td>{u.display_name}</td><td>{ROLE_LABEL[u.role]}</td>
                <td>{u.locked ? <span className="badge badge-locked">잠김</span> : "정상"}</td>
                <td className="actions">
                  <button type="button" className="secondary" onClick={() => toggle(u)}>{u.locked ? "잠금 해제" : "잠금"}</button>
                  <button type="button" className="secondary" onClick={() => setResetting(u)}>비밀번호 재설정</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {resetting && (
        <ResetForm user={resetting} onClose={() => setResetting(null)}
          onDone={(text) => { setMessage(text); setResetting(null); load(); }} />
      )}
    </>
  );
}

function ResetForm({ user, onClose, onDone }: { user: User; onClose: () => void; onDone: (text: string) => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      await api.admin.resetPassword(user.id, password);
      onDone(`${user.username} 계정의 비밀번호를 재설정했습니다(잠금 해제, 기존 세션 종료).`);
    } catch (e) { setError(errorText(e)); }
  }
  return (
    <form className="card" onSubmit={submit} aria-label={`${user.username} 비밀번호 재설정`}>
      <h2>{user.username} 비밀번호 재설정</h2>
      <p className="muted">소유자 확인 후 진행하세요. 잠금이 풀리고 기존 로그인은 모두 끊깁니다.</p>
      <Field label="새 비밀번호 (10자 이상)">
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
      </Field>
      {error && <Notice kind="error">{error}</Notice>}
      <button type="submit" disabled={password.length < 10}>재설정</button>{" "}
      <button type="button" className="secondary" onClick={onClose}>취소</button>
    </form>
  );
}
