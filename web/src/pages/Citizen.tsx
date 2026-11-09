import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import * as api from "../api";
import { CATEGORY_LABEL, type Petition } from "../api";
import { useAuth } from "../auth";
import { Field, formatTime, Notice, StatusBadge, errorText, useSubmit } from "../components";

export function HomePage() {
  const { user } = useAuth();
  if (!user) {
    return (
      <section className="card">
        <h1>누리시청 민원 포털</h1>
        <p>시민의 목소리를 듣는 가상 기관의 민원 시스템입니다. 민원을 접수하려면 로그인해 주세요.</p>
        <p><Link className="button" to="/login">로그인</Link> <Link className="button secondary" to="/register">가입</Link></p>
      </section>
    );
  }
  if (user.role !== "citizen") {
    return <Notice kind="info">담당자·관리자는 상단 메뉴에서 업무 화면으로 이동해 주세요.</Notice>;
  }
  return <MyPetitions />;
}

function MyPetitions() {
  const [items, setItems] = useState<Petition[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => api.petitions.mine().then(setItems).catch((e) => setError(errorText(e))), []);
  useEffect(() => { void load(); }, [load]);
  return (
    <>
      <h1>내 민원</h1>
      <NewPetitionForm onCreated={load} />
      {error && <Notice kind="error">{error}</Notice>}
      {items === null ? <p role="status">불러오는 중…</p> : items.length === 0 ? (
        <p className="muted">접수한 민원이 없습니다.</p>
      ) : (
        <ul className="list">
          {items.map((p) => (
            <li key={p.id}>
              <Link to={`/petitions/${p.id}`}>{p.title}</Link>
              <span className="muted"> · {CATEGORY_LABEL[p.category] ?? p.category} · {formatTime(p.created_at)}</span>
              <StatusBadge status={p.status} />
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

function NewPetitionForm({ onCreated }: { onCreated: () => void }) {
  const [category, setCategory] = useState("road");
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [done, setDone] = useState(false);
  const { busy, error, onSubmit } = useSubmit(async () => {
    setDone(false);
    await api.petitions.create({ category, title: title.trim(), body: body.trim() });
    setTitle(""); setBody(""); setDone(true);
    onCreated();
  });
  return (
    <form className="card" onSubmit={onSubmit} aria-label="새 민원 신청" noValidate>
      <h2>새 민원 신청</h2>
      <Field label="분류">
        <select value={category} onChange={(e) => setCategory(e.target.value)}>
          {Object.entries(CATEGORY_LABEL).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </Field>
      <Field label="제목 (2~100자)"><input value={title} onChange={(e) => setTitle(e.target.value)} required /></Field>
      <Field label="내용 (5~2000자)">
        <textarea rows={4} value={body} onChange={(e) => setBody(e.target.value)} required />
      </Field>
      {error && <Notice kind="error">{error}</Notice>}
      {done && <Notice kind="success">민원이 접수되었습니다.</Notice>}
      <button type="submit" disabled={busy || title.trim().length < 2 || body.trim().length < 5}>
        {busy ? "접수 중…" : "접수"}
      </button>
    </form>
  );
}

export function PetitionDetailPage() {
  const { id } = useParams();
  const [petition, setPetition] = useState<Petition | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.petitions.get(Number(id)).then(setPetition).catch((e) => setError(errorText(e)));
  }, [id]);
  if (error) return <Notice kind="error">{error}</Notice>;
  if (!petition) return <p role="status">불러오는 중…</p>;
  return <PetitionView petition={petition} />;
}

export function PetitionView({ petition }: { petition: Petition }) {
  return (
    <article className="card">
      <h1>{petition.title} <StatusBadge status={petition.status} /></h1>
      <p className="muted">{CATEGORY_LABEL[petition.category] ?? petition.category} · {formatTime(petition.created_at)}</p>
      <p className="pre">{petition.body}</p>
      <h2>처리 이력</h2>
      <ol className="timeline">
        {(petition.history ?? []).map((h, i) => (
          <li key={i}><strong>{ACTION_LABEL[h.action] ?? h.action}</strong>
            <span className="muted"> · {formatTime(h.created_at)}</span>{h.note && <p className="pre">{h.note}</p>}</li>
        ))}
      </ol>
    </article>
  );
}

const ACTION_LABEL: Record<string, string> = {
  created: "접수", assigned: "담당자 배정", processing: "처리 시작", done: "처리 완료", reply: "답변",
};
