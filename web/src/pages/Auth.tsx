import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import * as api from "../api";
import { homePathFor, useAuth } from "../auth";
import { Field, Notice, useSubmit } from "../components";

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const registered = (location.state as { registered?: boolean } | null)?.registered;
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const { busy, error, onSubmit } = useSubmit(async () => {
    const user = await login(username.trim(), password);
    const from = (location.state as { from?: string } | null)?.from;
    navigate(from ?? homePathFor(user), { replace: true });
  });
  return (
    <section className="card narrow">
      <h1>로그인</h1>
      {registered && <Notice kind="success">가입이 완료되었습니다. 로그인해 주세요.</Notice>}
      <form onSubmit={onSubmit} noValidate>
        <Field label="아이디">
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
        </Field>
        <Field label="비밀번호">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password" required />
        </Field>
        {error && <Notice kind="error">{error}</Notice>}
        <button type="submit" disabled={busy || !username || !password}>{busy ? "확인 중…" : "로그인"}</button>
      </form>
      <p className="muted">계정이 없나요? <Link to="/register">가입하기</Link></p>
    </section>
  );
}

export function RegisterPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);
  const { busy, error, onSubmit } = useSubmit(async () => {
    setLocalError(null);
    if (password.length < 10) { setLocalError("비밀번호는 10자 이상이어야 합니다."); return; }
    if (password !== confirm) { setLocalError("비밀번호 확인이 일치하지 않습니다."); return; }
    await api.register(username.trim(), displayName.trim(), password);
    navigate("/login", { state: { registered: true } });
  });
  return (
    <section className="card narrow">
      <h1>가입</h1>
      <form onSubmit={onSubmit} noValidate>
        <Field label="아이디 (영문·숫자·밑줄 3~40자)">
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
        </Field>
        <Field label="표시 이름 (2~30자)">
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="name" required />
        </Field>
        <Field label="비밀번호 (10자 이상)">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password" required />
        </Field>
        <Field label="비밀번호 확인">
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password" required />
        </Field>
        {(localError || error) && <Notice kind="error">{localError ?? error}</Notice>}
        <button type="submit" disabled={busy}>{busy ? "처리 중…" : "가입"}</button>
      </form>
      <p className="muted">이미 계정이 있나요? <Link to="/login">로그인</Link></p>
    </section>
  );
}
