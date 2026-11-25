import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Award, CheckCircle2, Circle, Lock, Play } from "lucide-react";
import { get, post } from "../api/client";
import { ErrorBox, PageHeader, Section, Spinner, SyntheticBanner } from "../components/ui";
import { fmtDate } from "../lib/format";
import { useAuth } from "../lib/auth";
import { useSelection } from "../lib/selection";

interface Mission { id: string; title: string; difficulty: string; xp: number; briefing: string; objectives: number; status: string; paired_captures: boolean; uses_bigip_metadata: boolean }
interface Objective { index: number; prompt: string; completed: boolean; attempts: number }
interface Run { id: string; mission_id: string; title: string; status: string; capture_id: string; secondary_capture_id: string | null; config_id: string | null; objectives: Objective[]; started_at: string }
interface Result { correct: boolean; objective?: number; explanation?: string | null; hint?: string; mission_completed?: boolean; xp_awarded?: number; achievements?: string[]; already_completed?: boolean }

const DIFF_CLS: Record<string, string> = { beginner: "text-ok", intermediate: "text-warn", advanced: "text-bad" };

function ObjectiveRow({ o, onResult }: { o: Objective; onResult: (r: Result) => void }) {
  const [answer, setAnswer] = useState("");
  const [res, setRes] = useState<Result | null>(null);
  const submit = useMutation({
    mutationFn: () => post<Result>("/missions/active/submit", { objective: o.index, answer }),
    onSuccess: (r) => { setRes(r); onResult(r); if (r.correct) setAnswer(""); },
  });
  return (
    <li className="rounded-md border border-line p-3">
      <div className="flex items-start gap-2">
        {o.completed ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-ok" aria-label="completed" /> : <Circle className="mt-0.5 h-4 w-4 shrink-0 text-muted" aria-label="open" />}
        <div className="min-w-0 flex-1">
          <p className="text-sm"><span className="font-semibold">{o.index}.</span> {o.prompt}</p>
          {!o.completed && (
            <form className="mt-2 flex gap-2" onSubmit={(e) => { e.preventDefault(); if (answer.trim()) submit.mutate(); }}>
              <input className="input mono max-w-sm" value={answer} onChange={(e) => setAnswer(e.target.value)} aria-label={`Answer for objective ${o.index}`} placeholder="Your answer" maxLength={200} />
              <button className="btn" disabled={submit.isPending || !answer.trim()}>Submit</button>
            </form>
          )}
          {submit.error && <div className="mt-2"><ErrorBox error={submit.error} /></div>}
          {res && !res.correct && <p className="mt-2 text-sm text-warn" role="status">Not quite. Hint: {res.hint}</p>}
          {res?.correct && res.explanation && <p className="mt-2 text-sm text-ok" role="status">Correct. {res.explanation}</p>}
          {o.attempts > 0 && <p className="mt-1 text-xs text-muted">{o.attempts} attempt(s)</p>}
        </div>
      </div>
    </li>
  );
}

function ActiveMission({ run, briefing, onCompleted }: { run: Run; briefing?: string; onCompleted: (r: Result & { title: string }) => void }) {
  const qc = useQueryClient();
  const nav = useNavigate();
  const { setCaptureId } = useSelection();
  const onResult = (r: Result) => {
    if (r.mission_completed) { onCompleted({ ...r, title: run.title }); qc.invalidateQueries(); }
    else if (r.correct) qc.invalidateQueries({ queryKey: ["mission-active"] });
  };
  const open = (id: string, to: string) => { setCaptureId(id); nav(to); };
  const complete = run.objectives.filter((o) => o.completed).length;
  return (
    <Section title={`Active mission: ${run.title}`} actions={<span className="text-xs text-muted">{complete}/{run.objectives.length} objectives · started {fmtDate(run.started_at)}</span>}>
      <SyntheticBanner />
      {briefing && <p className="mb-3 text-sm">{briefing}</p>}
      <div className="mb-3 flex flex-wrap gap-2 text-sm">
        <button className="btn" onClick={() => open(run.capture_id, "/console")}>Investigate in Command Deck</button>
        <button className="btn" onClick={() => open(run.capture_id, "/workbench")}>Open capture in Workbench</button>
        <button className="btn" onClick={() => open(run.capture_id, "/findings")}>Findings</button>
        {run.secondary_capture_id && <button className="btn" onClick={() => open(run.secondary_capture_id!, "/workbench")}>Server-side capture</button>}
        {run.config_id && <Link className="btn" to="/f5">BIG-IP metadata</Link>}
      </div>
      <ol className="space-y-2">{run.objectives.map((o) => <ObjectiveRow key={o.index} o={o} onResult={onResult} />)}</ol>
      <p className="mt-3 text-xs text-muted">Answers are checked against the analysed training capture, not against stored strings. Use console commands such as <code className="mono">tcp handshakes</code>, <code className="mono">flow list</code> and <code className="mono">f5 correlate</code> to find them.</p>
    </Section>
  );
}

export default function Missions() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const missions = useQuery({ queryKey: ["missions"], queryFn: () => get<Mission[]>("/missions") });
  const active = useQuery({ queryKey: ["mission-active"], queryFn: () => get<Run | null>("/missions/active") });
  const progress = useQuery({ queryKey: ["progress"], queryFn: () => get<any>("/me/progress") });
  const [done, setDone] = useState<(Result & { title: string }) | null>(null);
  const start = useMutation({
    mutationFn: (id: string) => post(`/missions/${id}/start`),
    onSuccess: () => { setDone(null); qc.invalidateQueries(); },
  });
  if (missions.isLoading || progress.isLoading) return <Spinner />;
  if (missions.error) return <ErrorBox error={missions.error} />;
  const p = progress.data;
  const run = active.data;
  const pct = p?.next_level_xp ? Math.min(100, ((p.xp - p.xp_floor) / (p.next_level_xp - p.xp_floor)) * 100) : 100;
  return (
    <div className="space-y-4">
      <PageHeader title="Training missions" subtitle="Guided investigations on synthetic captures. Each mission runs the same analysis engine as real evidence." />
      {p && (
        <div className="grid gap-4 lg:grid-cols-3">
          <Section title="Progress">
            <div className="text-2xl font-semibold">Lv {p.level} · {p.title}</div>
            <div className="mt-2 h-2 overflow-hidden rounded bg-panel2" role="progressbar" aria-valuenow={Math.round(pct)} aria-valuemin={0} aria-valuemax={100}><div className="h-full bg-accent" style={{ width: `${pct}%` }} /></div>
            <div className="mt-1 text-sm text-muted">{p.xp} XP{p.next_level_xp ? ` · ${p.next_level_xp - p.xp} XP to ${p.next_title}` : " · top level"}</div>
            <div className="mt-1 text-xs text-muted">{p.xp_training} XP from training</div>
            <p className="mt-3 text-xs text-muted">{p.level_note}</p>
          </Section>
          <Section title={`Achievements (${p.achievements.filter((a: any) => a.earned).length}/${p.achievements.length})`}>
            <ul className="space-y-1.5 text-sm">
              {p.achievements.map((a: any) => (
                <li key={a.id} className={`flex items-start gap-2 ${a.earned ? "" : "text-muted"}`} title={a.criteria}>
                  {a.earned ? <Award className="mt-0.5 h-4 w-4 shrink-0 text-accent" aria-label="earned" /> : <Lock className="mt-0.5 h-4 w-4 shrink-0" aria-label="locked" />}
                  <span><span className="font-medium">{a.name}</span> <span className="text-xs text-muted">· {a.criteria}</span></span>
                </li>
              ))}
            </ul>
          </Section>
          <Section title="Recent XP">
            {p.recent_xp.length ? (
              <ul className="space-y-1 text-sm">{p.recent_xp.slice(0, 10).map((e: any) => (
                <li key={e.id} className="flex justify-between gap-2"><span className="truncate">{e.event.replace(/_/g, " ")}{e.mode === "training" ? " (training)" : ""}</span><span className="tabular-nums text-ok">+{e.xp}</span></li>
              ))}</ul>
            ) : <p className="text-sm text-muted">No XP yet. Upload a capture or start a mission.</p>}
          </Section>
        </div>
      )}
      {done && (
        <div className="rounded-md border border-ok/40 bg-ok/10 p-3 text-sm" role="status">
          <div className="flex items-center gap-2 font-semibold text-ok"><Award className="h-4 w-4" />Mission complete: {done.title}. +{done.xp_awarded ?? 0} XP</div>
          {done.explanation && <p className="mt-1">{done.explanation}</p>}
          {done.achievements?.length ? <p className="mt-1">New achievement(s): {done.achievements.join(", ")}</p> : null}
        </div>
      )}
      {run && <ActiveMission run={run} briefing={missions.data?.find((m) => m.id === run.mission_id)?.briefing} onCompleted={setDone} />}
      {start.error && <ErrorBox error={start.error} />}
      <Section title="Mission catalogue">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {missions.data?.map((m) => (
            <div key={m.id} className="flex flex-col rounded-md border border-line p-3">
              <div className="flex items-start justify-between gap-2">
                <h3 className="font-semibold">{m.title}</h3>
                <span className="shrink-0 text-xs tabular-nums text-muted">{m.xp} XP</span>
              </div>
              <div className="mt-0.5 flex flex-wrap gap-2 text-xs">
                <span className={DIFF_CLS[m.difficulty] ?? ""}>{m.difficulty}</span>
                <span className="text-muted">{m.objectives} objectives</span>
                {m.paired_captures && <span className="text-muted">client + server captures</span>}
                {m.uses_bigip_metadata && <span className="text-muted">BIG-IP metadata</span>}
              </div>
              <p className="mt-2 flex-1 text-sm text-muted">{m.briefing}</p>
              <div className="mt-3 flex items-center justify-between">
                <span className={`text-xs ${m.status === "completed" ? "text-ok" : m.status === "in progress" ? "text-warn" : "text-muted"}`}>{m.status}</span>
                {can("mission:play") && (
                  <button className="btn" onClick={() => start.mutate(m.id)} disabled={start.isPending || (run?.mission_id === m.id)}>
                    <Play className="h-3.5 w-3.5" />{run?.mission_id === m.id ? "Active" : m.status === "completed" ? "Replay" : "Start"}
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </Section>
    </div>
  );
}
