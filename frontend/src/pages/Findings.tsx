import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { Copy, Download, Sparkles } from "lucide-react";
import { download, get, patch, post, type Finding, type Page } from "../api/client";
import { ConfidenceBadge, Empty, ErrorBox, PageHeader, Section, SeverityBadge, Spinner, StatusPill, SyntheticBanner } from "../components/ui";
import { useAuth } from "../lib/auth";
import { ep, fmtTsNs } from "../lib/format";
import { useSelection } from "../lib/selection";

const STATUSES = ["open", "investigating", "confirmed", "dismissed", "resolved"];

function Part({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <section className="border-t border-line py-3 first:border-t-0">
      <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">{n}. {title}</h3>
      <div className="text-sm">{children}</div>
    </section>
  );
}

function Frames({ frames }: { frames: number[] }) {
  if (!frames?.length) return null;
  return <span className="ml-1 text-xs">[{frames.slice(0, 12).map((f, i) => <span key={f}>{i ? ", " : ""}<Link className="link mono" to={`/workbench?filter=${encodeURIComponent(`frame.number == ${f}`)}`}>#{f}</Link></span>)}{frames.length > 12 ? " …" : ""}]</span>;
}

function Triage({ f }: { f: Finding }) {
  const qc = useQueryClient();
  const [status, setStatus] = useState(f.status);
  const [note, setNote] = useState("");
  const m = useMutation({
    mutationFn: () => patch(`/findings/${f.id}`, { status: status !== f.status ? status : undefined, note: note || undefined }),
    onSuccess: () => { setNote(""); qc.invalidateQueries({ queryKey: ["finding"] }); qc.invalidateQueries({ queryKey: ["findings"] }); qc.invalidateQueries({ queryKey: ["progress"] }); },
  });
  const needsNote = status === "confirmed" && f.status !== "confirmed" && note.trim().length < 20;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-end gap-2">
        <label><span className="label">Status</span>
          <select className="input mt-1" value={status} onChange={(e) => setStatus(e.target.value)}>{STATUSES.map((s) => <option key={s}>{s}</option>)}</select></label>
        <label className="min-w-[16rem] flex-1"><span className="label">Note {status === "confirmed" ? "(required to confirm: how did you verify it?)" : ""}</span>
          <input className="input mt-1" value={note} onChange={(e) => setNote(e.target.value)} maxLength={5000} placeholder="e.g. Verified with tmsh show ltm pool: member 10.2.2.21 down" /></label>
        <button className="btn-primary" disabled={m.isPending || needsNote || (status === f.status && !note)} onClick={() => m.mutate()}>Save</button>
      </div>
      {needsNote && <p className="text-xs text-muted">Confirming requires a verification note of at least 20 characters. Confirmation does not change severity or confidence.</p>}
      {m.error && <ErrorBox error={m.error} />}
      {f.notes?.length ? <ul className="space-y-1 text-sm">{f.notes.map((n, i) => <li key={i} className="rounded bg-panel2 px-2 py-1">{n.text} <span className="text-xs text-muted">— {n.author_email}, {new Date(n.at).toLocaleString()}</span></li>)}</ul> : null}
    </div>
  );
}

function FindingDetail({ id }: { id: string }) {
  const { can } = useAuth();
  const { data: ev, error } = useQuery({ queryKey: ["finding", id], queryFn: () => get<any>(`/findings/${id}/evidence`) });
  if (error) return <ErrorBox error={error} />;
  if (!ev) return <Spinner />;
  const f: Finding = ev.finding;
  const copy = (t: string) => navigator.clipboard?.writeText(t);
  return (
    <div className="card p-4">
      {f.training && <SyntheticBanner />}
      <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={f.severity} /><ConfidenceBadge level={f.confidence.level} /><StatusPill status={f.status} />
        <span className="text-xs text-muted">{f.rule_id} v{f.rule_version} · {f.category}</span></div>
      <h2 className="mt-2 text-lg font-semibold">{f.short_id} · {f.title}</h2>
      <Part n={1} title="Summary">{f.summary}</Part>
      <Part n={2} title="Observed facts"><ul className="list-disc space-y-1 pl-5">{f.observations?.map((o, i) => <li key={i}>{o.text}<Frames frames={o.frames} /></li>)}</ul></Part>
      <Part n={3} title="Interpretation">{f.assessment}</Part>
      <Part n={4} title="Probable cause (hypothesis)">{f.probable_cause}</Part>
      <Part n={5} title="Confidence">{f.confidence.level} ({f.confidence.score}) — {f.confidence.rationale}</Part>
      <Part n={6} title="Alternative explanations"><ul className="list-disc pl-5">{f.alternatives?.map((a, i) => <li key={i}>{a}</li>)}</ul></Part>
      <Part n={7} title={`Evidence (${ev.packets.length} packets)`}>
        <div className="max-h-64 overflow-auto"><table className="tbl mono">
          <thead><tr><th>Frame</th><th>Time</th><th>Source</th><th>Destination</th><th>Role</th><th>Info</th></tr></thead>
          <tbody>{ev.packets.map((p: any) => <tr key={p.number}><td><Link className="link" to={`/workbench?filter=${encodeURIComponent(`frame.number == ${p.number}`)}`}>#{p.number}</Link></td>
            <td>{fmtTsNs(p.ts_ns).slice(11)}</td><td>{ep(p.src, p.sport)}</td><td>{ep(p.dst, p.dport)}</td><td>{p.role}</td><td className="max-w-[30ch] truncate">{p.info}</td></tr>)}</tbody>
        </table></div>
        {ev.flows?.length > 0 && <p className="mt-2">Conversations: {ev.flows.map((fl: any) => <Link key={fl.local_id} className="link mr-2 mono" to={`/flows?flow=${fl.local_id}`}>{fl.local_id}</Link>)}</p>}
      </Part>
      <Part n={8} title="Verification steps (run these yourself; PacketOps never executes them)">
        {f.verification?.map((v, i) => (
          <div key={i} className="mb-2"><p className="text-muted">{v.purpose} — <em>{v.where}</em></p>
            <div className="flex items-start gap-2"><pre className="mono flex-1 overflow-x-auto rounded bg-panel2 p-2">{v.command}</pre>
              <button className="btn px-2" onClick={() => copy(v.command)} aria-label="Copy command"><Copy className="h-3.5 w-3.5" /></button></div></div>))}
      </Part>
      <Part n={9} title="Remediation options"><ul className="list-disc pl-5">{f.remediation?.map((r, i) => <li key={i}>{r.action} <span className="text-muted">Risk: {r.risk}</span></li>)}</ul></Part>
      <Part n={10} title="Missing evidence">{f.missing_evidence?.length ? <ul className="list-disc pl-5">{f.missing_evidence.map((m, i) => <li key={i}>{m}</li>)}</ul> : "None identified."}</Part>
      <Part n={11} title="Limitations"><ul className="list-disc pl-5">{f.limitations?.map((l, i) => <li key={i}>{l}</li>)}</ul></Part>
      {f.f5_relevance && <Part n={12} title="BIG-IP relevance">{f.f5_relevance}</Part>}
      {can("finding:update") && <div className="mt-3 border-t border-line pt-3"><h3 className="mb-2 text-sm font-semibold">Triage</h3><Triage f={f} /></div>}
      {ev.rule && <details className="mt-3 text-sm"><summary className="cursor-pointer text-muted">How {ev.rule.rule_id} works</summary>
        <p className="mt-1">{ev.rule.detection_logic}</p><p className="mt-1 text-muted">Severity rationale: {ev.rule.severity_rationale}</p>
        <p className="mt-1 text-muted">Known false positives: {ev.rule.false_positives?.join("; ")}</p></details>}
    </div>
  );
}

function Copilot({ captureId }: { captureId: string }) {
  const m = useMutation({ mutationFn: () => post<any>(`/captures/${captureId}/copilot`) });
  return (
    <Section title="Copilot synthesis" actions={<button className="btn" onClick={() => m.mutate()} disabled={m.isPending}><Sparkles className="h-4 w-4" />{m.isPending ? "Working…" : "Synthesise findings"}</button>}>
      {m.error ? <ErrorBox error={m.error} /> : m.data ? (
        <div className="text-sm">
          <p className="mb-2 text-xs text-muted">{m.data.provider === "deterministic" ? `Deterministic synthesis (${m.data.fallback?.reason})` : `Generated by ${m.data.provider} ${m.data.model ?? ""}; every address, frame and finding it cites was checked against the evidence${m.data.redacted ? "; identifiers were redacted before sending" : ""}.`}</p>
          {m.data.synthesis.split("\n").map((l: string, i: number) => l.trim() ? <p key={i} className="mb-1.5">{l}</p> : null)}
        </div>) : <p className="text-sm text-muted">Connects the findings of this capture into ranked hypotheses and a verification order. It only uses the evidence shown here.</p>}
    </Section>
  );
}

export default function Findings() {
  const { captureId } = useSelection();
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const [sev, setSev] = useState(""); const [status, setStatus] = useState("");
  const [scope, setScope] = useState<"capture" | "all">(captureId ? "capture" : "all");
  const { data, error, isLoading } = useQuery({
    queryKey: ["findings", scope, captureId, sev, status],
    queryFn: () => get<Page<Finding>>("/findings", { capture_id: scope === "capture" ? captureId ?? undefined : undefined, severity: sev || undefined, status: status || undefined, limit: 200 }),
  });
  const short = params.get("f");
  const selected = params.get("id") ?? (short && captureId ? `${captureId}-${short}` : null);
  const pick = (f: Finding) => setParams({ id: f.id });
  return (
    <div className="space-y-4">
      <PageHeader title="Findings" subtitle="Deterministic, evidence-backed findings. Severity (impact) and confidence (evidence strength) are separate."
        actions={scope === "capture" && captureId && can("export:data") ? <>
          <button className="btn" onClick={() => download(`/api/v1/captures/${captureId}/findings/export?format=json`, "findings.json")}><Download className="h-4 w-4" />JSON</button>
          <button className="btn" onClick={() => download(`/api/v1/captures/${captureId}/findings/export?format=csv`, "findings.csv")}><Download className="h-4 w-4" />CSV</button></> : null} />
      <div className="flex flex-wrap gap-2">
        <select className="input w-auto" value={scope} onChange={(e) => setScope(e.target.value as any)} aria-label="Scope">
          <option value="capture" disabled={!captureId}>Selected capture</option><option value="all">All captures</option></select>
        <select className="input w-auto" value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Severity"><option value="">any severity</option>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</select>
        <select className="input w-auto" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status"><option value="">any status</option>{STATUSES.map((s) => <option key={s}>{s}</option>)}</select>
      </div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <div className="space-y-4">
          <div className="card max-h-[70vh] overflow-auto">
            {isLoading ? <Spinner /> : error ? <ErrorBox error={error} /> : !data!.items.length ? <div className="p-4"><Empty title="No findings match" /></div> : (
              <ul>{data!.items.map((f) => (
                <li key={f.id}><button onClick={() => pick(f)} className={`w-full border-b border-line px-3 py-2 text-left hover:bg-panel2 ${selected === f.id ? "bg-accent/10" : ""}`}>
                  <div className="flex items-center gap-2"><SeverityBadge severity={f.severity} /><ConfidenceBadge level={f.confidence.level} /><span className="ml-auto text-xs text-muted">{f.status}</span></div>
                  <div className="mt-1 text-sm font-medium">{f.short_id} · {f.title}</div>
                  <div className="text-xs text-muted">{f.rule_id}{scope === "all" ? ` · ${f.capture_id}` : ""}{f.training ? " · training" : ""}</div>
                </button></li>))}</ul>)}
          </div>
          {scope === "capture" && captureId && <Copilot captureId={captureId} />}
        </div>
        {selected ? <FindingDetail id={selected} /> : <Empty title="Select a finding" />}
      </div>
    </div>
  );
}
