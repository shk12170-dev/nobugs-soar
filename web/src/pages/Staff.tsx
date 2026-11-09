import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import * as api from "../api";
import { CATEGORY_LABEL, STATUS_LABEL, type Petition } from "../api";
import { useAuth } from "../auth";
import { Field, formatTime, Notice, StatusBadge, errorText, useSubmit } from "../components";
import { PetitionView } from "./Citizen";

export function StaffBoardPage() {
  const [status, setStatus] = useState("");
  const [items, setItems] = useState<Petition[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setItems(null);
    api.staff.list(status || undefined).then(setItems).catch((e) => setError(errorText(e)));
  }, [status]);
  return (
    <>
      <h1>민원 처리</h1>
      <Field label="상태 필터">
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">전체</option>
          {Object.entries(STATUS_LABEL).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </Field>
      {error && <Notice kind="error">{error}</Notice>}
      {items === null ? <p role="status">불러오는 중…</p> : items.length === 0 ? (
        <p className="muted">해당하는 민원이 없습니다.</p>
      ) : (
        <table className="table">
          <thead><tr><th>번호</th><th>제목</th><th>분류</th><th>접수</th><th>상태</th></tr></thead>
          <tbody>
            {items.map((p) => (
              <tr key={p.id}>
                <td>{p.id}</td>
                <td><Link to={`/staff/petitions/${p.id}`}>{p.title}</Link></td>
                <td>{CATEGORY_LABEL[p.category] ?? p.category}</td>
                <td>{formatTime(p.created_at)}</td>
                <td><StatusBadge status={p.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

export function StaffPetitionPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const [petition, setPetition] = useState<Petition | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(
    () => api.petitions.get(Number(id)).then(setPetition).catch((e) => setError(errorText(e))), [id]);
  useEffect(() => { void load(); }, [load]);
  if (error) return <Notice kind="error">{error}</Notice>;
  if (!petition || !user) return <p role="status">불러오는 중…</p>;

  const mine = petition.assignee_id === user.id || user.role === "admin";
  return (
    <>
      <p><Link to="/staff">← 목록으로</Link></p>
      <PetitionView petition={petition} />
      <Actions petition={petition} mine={mine} canTake={user.role === "staff"} onChange={setPetition} />
    </>
  );
}

function Actions({ petition, mine, canTake, onChange }:
  { petition: Petition; mine: boolean; canTake: boolean; onChange: (p: Petition) => void }) {
  const [note, setNote] = useState("");
  const [reply, setReply] = useState("");
  const run = (action: () => Promise<Petition>) => async () => { onChange(await action()); };
  const take = useSubmit(run(() => api.staff.assign(petition.id)));
  const start = useSubmit(run(() => api.staff.status(petition.id, "processing", petition.version)));
  const finish = useSubmit(run(async () => {
    const result = await api.staff.status(petition.id, "done", petition.version, note.trim());
    setNote("");
    return result;
  }));
  const answer = useSubmit(async () => {
    onChange(await api.staff.reply(petition.id, reply.trim()));
    setReply("");
  });
  const failure = take.error ?? start.error ?? finish.error ?? answer.error;
  return (
    <section className="card" aria-label="처리 작업">
      <h2>처리 작업</h2>
      {failure && <Notice kind="error">{failure}</Notice>}
      {petition.status === "received" && canTake && (
        <form onSubmit={take.onSubmit}><button type="submit" disabled={take.busy}>내가 맡기</button></form>
      )}
      {petition.status === "assigned" && mine && (
        <form onSubmit={start.onSubmit}><button type="submit" disabled={start.busy}>처리 시작</button></form>
      )}
      {petition.status === "processing" && mine && (
        <form onSubmit={finish.onSubmit}>
          <Field label="완료 메모 (선택)"><input value={note} onChange={(e) => setNote(e.target.value)} /></Field>
          <button type="submit" disabled={finish.busy}>완료 처리</button>
        </form>
      )}
      {petition.status !== "received" && mine && (
        <form onSubmit={answer.onSubmit}>
          <Field label="시민에게 보낼 답변">
            <textarea rows={3} value={reply} onChange={(e) => setReply(e.target.value)} />
          </Field>
          <button type="submit" className="secondary" disabled={answer.busy || !reply.trim()}>답변 등록</button>
        </form>
      )}
      {petition.status === "done" && <Notice kind="info">완료된 민원입니다.</Notice>}
    </section>
  );
}
