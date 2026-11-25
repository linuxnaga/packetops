import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { Download, Play, Trash2, Upload, XCircle } from "lucide-react";
import { ApiError, del, download, get, post, uploadCapture, type Capture, type Packet } from "../api/client";
import { JobProgress } from "../components/JobProgress";
import { Empty, ErrorBox, PageHeader, Section, Spinner, Stat, StatusPill, SyntheticBanner } from "../components/ui";
import { useAuth } from "../lib/auth";
import { fmtBytes, fmtNum, fmtTsNs } from "../lib/format";
import { useSelection } from "../lib/selection";

function UploadPanel({ onUploaded }: { onUploaded: (c: Capture) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [point, setPoint] = useState("");
  const [pct, setPct] = useState<number | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const abort = useRef<AbortController | null>(null);
  const start = async () => {
    if (!file) return;
    setErr(null); setPct(0);
    abort.current = new AbortController();
    try {
      const r = await uploadCapture(file, { capture_point: point || undefined }, setPct, abort.current.signal);
      onUploaded(r.capture);
      setFile(null);
    } catch (e) { setErr(e); } finally { setPct(null); }
  };
  return (
    <Section title="Upload evidence">
      <div className="flex flex-wrap items-end gap-3">
        <label className="min-w-[16rem] flex-1">
          <span className="label">PCAP or PCAPNG file</span>
          <input type="file" accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap" className="input mt-1" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        </label>
        <label>
          <span className="label">Capture point</span>
          <select className="input mt-1" value={point} onChange={(e) => setPoint(e.target.value)}>
            <option value="">not stated</option><option value="client-side">client-side (in front of the VIP)</option>
            <option value="server-side">server-side (behind the BIG-IP)</option><option value="on-box">on the BIG-IP (tcpdump -i 0.0)</option><option value="other">other</option>
          </select>
        </label>
        {pct === null ? <button className="btn-primary" disabled={!file} onClick={start}><Upload className="h-4 w-4" />Upload and analyse</button>
          : <button className="btn" onClick={() => abort.current?.abort()}><XCircle className="h-4 w-4" />Cancel ({pct}%)</button>}
      </div>
      <p className="mt-2 text-xs text-muted">The file is streamed, hashed (SHA-256) and structurally validated before it is stored as write-once evidence. Archives and non-capture files are rejected.</p>
      {err != null && <div className="mt-2"><ErrorBox error={err} /></div>}
    </Section>
  );
}

const PAGE = 200;

function PacketTable({ cap, onSelect, selected }: { cap: Capture; onSelect: (n: number) => void; selected: number | null }) {
  const [params, setParams] = useSearchParams();
  const [draft, setDraft] = useState(params.get("filter") ?? "");
  const filter = params.get("filter") ?? "";
  const [offset, setOffset] = useState(0);
  useEffect(() => setOffset(0), [filter, cap.id]);
  const { data, error, isFetching } = useQuery({
    queryKey: ["packets", cap.id, filter, offset],
    queryFn: () => get<{ items: Packet[]; total: number | null; has_more?: boolean }>(`/captures/${cap.id}/packets`, { filter: filter || undefined, limit: PAGE, offset }),
    placeholderData: (p) => p,
  });
  const apply = (e: React.FormEvent) => { e.preventDefault(); const p = new URLSearchParams(params); if (draft) p.set("filter", draft); else p.delete("filter"); setParams(p); };
  return (
    <Section title="Packets" actions={<span className="text-xs text-muted">{isFetching ? "loading…" : data ? `${fmtNum(data.total ?? data.items.length)} match` : ""}</span>}>
      <form onSubmit={apply} className="mb-2 flex gap-2" role="search">
        <input className="input mono" value={draft} onChange={(e) => setDraft(e.target.value)} placeholder='Display filter, e.g. tcp.flags.reset == 1 || dns.qry.name contains "api"' aria-label="Display filter" />
        <button className="btn" type="submit">Apply</button>
      </form>
      {error ? <ErrorBox error={error} /> : (
        <div className="max-h-[52vh] overflow-auto rounded border border-line">
          <table className="tbl mono">
            <thead><tr><th>No.</th><th>Time (s)</th><th>Source</th><th>Destination</th><th>Proto</th><th>Len</th><th>Info</th></tr></thead>
            <tbody>
              {data?.items.map((p) => (
                <tr key={p.number} onClick={() => onSelect(p.number)} className={`cursor-pointer ${selected === p.number ? "!bg-accent/15" : ""} ${p.analysis ? "text-warn" : ""} ${p.tcp_flags?.includes("R") ? "text-bad" : ""}`}
                  tabIndex={0} onKeyDown={(e) => e.key === "Enter" && onSelect(p.number)} aria-selected={selected === p.number}>
                  <td>{p.number}</td><td>{p.rel_s.toFixed(6)}</td><td>{p.src}{p.sport != null ? `:${p.sport}` : ""}</td>
                  <td>{p.dst}{p.dport != null ? `:${p.dport}` : ""}</td><td>{p.protocol}</td><td>{p.len}</td>
                  <td className="max-w-[40ch] truncate" title={p.info}>{p.analysis ? `[${p.analysis}] ` : ""}{p.info}</td>
                </tr>))}
            </tbody>
          </table>
        </div>)}
      <div className="mt-2 flex items-center gap-2 text-sm">
        <button className="btn" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
        <button className="btn" disabled={!data || data.items.length < PAGE} onClick={() => setOffset(offset + PAGE)}>Next</button>
        <span className="text-muted">rows {offset + 1}–{offset + (data?.items.length ?? 0)}</span>
      </div>
    </Section>
  );
}

function Tree({ nodes, depth = 0 }: { nodes: any[]; depth?: number }) {
  return (
    <ul className={depth ? "ml-4 border-l border-line pl-2" : ""}>
      {nodes.map((n, i) => n.children?.length ? (
        <li key={i}><details open={depth < 1}><summary className="cursor-pointer select-text">{n.name}</summary><Tree nodes={n.children} depth={depth + 1} /></details></li>
      ) : <li key={i} className="select-text"><span className="text-muted">{n.name}</span>{n.value !== undefined && <>: {n.value}</>}</li>)}
    </ul>
  );
}

export function hexdump(hex: string): string {
  const bytes = hex.match(/../g) ?? [];
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const ascii = chunk.map((b) => { const c = parseInt(b, 16); return c >= 32 && c < 127 ? String.fromCharCode(c) : "."; }).join("");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${chunk.slice(0, 8).join(" ").padEnd(23)}  ${chunk.slice(8).join(" ").padEnd(23)}  ${ascii}`);
  }
  return lines.join("\n");
}

function PacketDetail({ cap, frame }: { cap: Capture; frame: number }) {
  const { data, error, isLoading } = useQuery({ queryKey: ["packet", cap.id, frame], queryFn: () => get<any>(`/captures/${cap.id}/packets/${frame}`) });
  if (isLoading) return <Spinner label="Dissecting frame" />;
  if (error) return <ErrorBox error={error} />;
  return (
    <Section title={`Frame #${frame}`} actions={<span className="text-xs text-muted">{fmtTsNs(data.summary.ts_ns)}</span>}>
      {data.cited_by?.length > 0 && <p className="mb-2 text-sm">Evidence for: {data.cited_by.map((c: any) => { const short = String(c.finding_id).split("-").pop(); return <Link key={c.finding_id} className="link mr-2" to={`/findings?f=${short}`}>{short}{c.label ? ` (${c.label})` : ""}</Link>; })}</p>}
      <div className="grid gap-3 xl:grid-cols-2">
        <div className="mono max-h-[40vh] overflow-auto rounded border border-line p-2 text-[12px]"><Tree nodes={data.tree ?? []} /></div>
        <pre className="mono max-h-[40vh] overflow-auto rounded border border-line p-2 text-[12px] leading-5">{data.hex ? hexdump(data.hex) : ""}</pre>
      </div>
    </Section>
  );
}

export default function Workbench() {
  const { captureId, setCaptureId } = useSelection();
  const { can } = useAuth();
  const qc = useQueryClient();
  const [frame, setFrame] = useState<number | null>(null);
  const [actionErr, setActionErr] = useState<unknown>(null);
  const { data: cap, error, isLoading } = useQuery({ queryKey: ["capture", captureId], queryFn: () => get<Capture>(`/captures/${captureId}`), enabled: !!captureId,
    refetchInterval: (q) => (["queued", "analyzing", "uploaded"].includes((q.state.data as Capture | undefined)?.status ?? "") ? 2000 : false) });
  const [params] = useSearchParams();
  // A link of the form ?filter=frame.number == N opens that frame directly.
  const linked = /^frame\.number == (\d+)$/.exec(params.get("filter") ?? "")?.[1];
  useEffect(() => setFrame(linked ? Number(linked) : null), [captureId, linked]);
  const stats = cap?.stats;
  const busy = cap && ["queued", "analyzing"].includes(cap.status);
  const act = async (fn: () => Promise<unknown>) => { setActionErr(null); try { await fn(); qc.invalidateQueries(); } catch (e) { setActionErr(e); } };
  const meta = cap?.metadata;
  const limitations = useMemo(() => cap?.limitations ?? [], [cap]);
  return (
    <div className="space-y-4">
      <PageHeader title="PCAP Workbench" subtitle="Upload evidence, follow analysis, filter packets and inspect any frame." />
      {can("capture:upload") && <UploadPanel onUploaded={(c) => { setCaptureId(c.id); qc.invalidateQueries({ queryKey: ["captures"] }); }} />}
      {!captureId ? <Empty title="No capture selected">Upload a file or choose one from the capture selector above.</Empty>
        : isLoading ? <Spinner /> : error ? <ErrorBox error={error} /> : cap && (
          <>
            {cap.training && <SyntheticBanner />}
            <Section title={cap.filename} actions={
              <div className="flex gap-2">
                {can("analysis:run") && !busy && <button className="btn" onClick={() => act(() => post(`/captures/${cap.id}/analyze`, { force: true }))}><Play className="h-4 w-4" />Re-analyse</button>}
                {can("analysis:run") && busy && <button className="btn" onClick={() => act(() => post(`/captures/${cap.id}/cancel`))}><XCircle className="h-4 w-4" />Cancel</button>}
                {can("export:data") && cap.status === "analyzed" && <button className="btn" onClick={() => act(() => download(`/api/v1/captures/${cap.id}/packets/export?format=csv`, "packets.csv"))}><Download className="h-4 w-4" />Packets CSV</button>}
                {can("capture:delete") && <button className="btn text-bad" onClick={() => { if (confirm(`Delete ${cap.filename} and all derived data? This cannot be undone.`)) act(async () => { await del(`/captures/${cap.id}`); setCaptureId(null); }); }}><Trash2 className="h-4 w-4" />Delete</button>}
              </div>}>
              <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm">
                <StatusPill status={cap.status} />
                <span className="mono text-muted" title="SHA-256">{cap.sha256.slice(0, 16)}…</span>
                <span>{fmtBytes(cap.size_bytes)} · {cap.format}</span>
                {meta && <span>{fmtTsNs(meta.first_ts_ns)} → {fmtTsNs(meta.last_ts_ns)}</span>}
                {cap.capture_point && <span>capture point: {cap.capture_point}</span>}
                {cap.duplicate_of && <span className="text-warn">identical file already uploaded ({cap.duplicate_of})</span>}
              </div>
              {busy && <div className="mt-3"><JobProgress captureId={cap.id} /></div>}
              {cap.error && <div className="mt-3"><ErrorBox error={new ApiError(0, "analysis", cap.error)} /></div>}
              {actionErr != null && <div className="mt-3"><ErrorBox error={actionErr} /></div>}
            </Section>
            {stats && (
              <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
                <Stat label="Packets" value={fmtNum(stats.packets)} /><Stat label="Duration" value={`${stats.duration_s.toFixed(2)} s`} />
                <Stat label="TCP / UDP" value={`${stats.tcp_conversations} / ${stats.udp_conversations}`} />
                <Stat label="Retransmissions" value={fmtNum(stats.retransmissions)} tone={stats.retransmissions ? "warn" : undefined} />
                <Stat label="Resets" value={fmtNum(stats.resets)} tone={stats.resets ? "warn" : undefined} />
                <Stat label="TLS handshakes" value={fmtNum(stats.tls_handshakes)} /><Stat label="HTTP requests" value={fmtNum(stats.http_requests)} />
                <Stat label="Findings" value={fmtNum(stats.findings)} tone={stats.findings ? "bad" : "ok"} />
              </div>)}
            {limitations.length > 0 && (
              <Section title="Analysis limitations"><ul className="list-disc space-y-1 pl-5 text-sm">{limitations.map((l) => <li key={l.code}>{l.text}</li>)}</ul></Section>)}
            {cap.status === "analyzed" && (
              <div className="grid gap-4 2xl:grid-cols-2">
                <PacketTable cap={cap} onSelect={setFrame} selected={frame} />
                {frame ? <PacketDetail cap={cap} frame={frame} /> : <Empty title="Select a packet">Click a row to see the full dissection tree and bytes.</Empty>}
              </div>)}
          </>)}
    </div>
  );
}
