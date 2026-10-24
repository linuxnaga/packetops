import { Fragment, useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, Terminal } from "lucide-react";
import { download, get, post, uploadCapture, type ConsoleBlock, type ConsoleResponse } from "../api/client";
import { JobProgress } from "../components/JobProgress";
import { ErrorBox, PageHeader } from "../components/ui";
import { useSelection } from "../lib/selection";

// The Command Deck: a terminal for the real analysis engine. Every command runs server-side
// against stored evidence; the browser only renders the structured blocks it returns.

interface Entry { id: number; input: string; prompt: string; blocks: ConsoleBlock[]; error?: boolean; ask?: ConsoleResponse["prompt"] }
interface CommandInfo { name: string; usage: string; summary: string; category: string; allowed: boolean }

const HISTORY_KEY = "packetops.console.history";
const loadHistory = (): string[] => { try { return JSON.parse(sessionStorage.getItem(HISTORY_KEY) ?? "[]"); } catch { return []; } };
const saveHistory = (h: string[]) => { try { sessionStorage.setItem(HISTORY_KEY, JSON.stringify(h.slice(-200))); } catch { /* ignore */ } };

const LEVEL_CLS: Record<string, string> = {
  ok: "text-ok", info: "text-fg", warn: "text-warn", error: "text-bad", muted: "text-muted", head: "font-bold text-accent",
};

// #123 = frame, t12 / u3 = TCP/UDP conversation, F7 = finding short id, cap_… = capture id.
const TOKEN_RE = /(#\d+\b|\b[tu]\d+\b|\bF\d+\b|\bcap_[0-9a-f]{20}\b)/g;

export function linkify(text: string, onCapture: (id: string) => void): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  for (const m of text.matchAll(TOKEN_RE)) {
    const tok = m[0]; const i = m.index ?? 0;
    if (i > last) out.push(text.slice(last, i));
    if (tok.startsWith("#")) out.push(<Link key={i} className="link" to={`/workbench?filter=${encodeURIComponent(`frame.number == ${tok.slice(1)}`)}`}>{tok}</Link>);
    else if (tok.startsWith("F")) out.push(<Link key={i} className="link" to={`/findings?f=${tok}`}>{tok}</Link>);
    else if (tok.startsWith("cap_")) out.push(<button key={i} className="link" onClick={() => onCapture(tok)}>{tok}</button>);
    else out.push(<Link key={i} className="link" to={`/flows?flow=${tok}`}>{tok}</Link>);
    last = i + tok.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function Block({ b, onCapture, onRun }: { b: ConsoleBlock; onCapture: (id: string) => void; onRun: (line: string) => void }) {
  if (b.type === "line") return <div className={`whitespace-pre-wrap break-words ${LEVEL_CLS[b.level ?? "info"] ?? ""}`}>{linkify(b.text ?? "", onCapture)}</div>;
  if (b.type === "kv") {
    return (
      <dl className="my-1 grid grid-cols-[max-content_1fr] gap-x-4">
        {b.items?.map(([k, v], i) => <Fragment key={i}><dt className="text-muted">{k}</dt><dd className="whitespace-pre-wrap break-words">{linkify(v, onCapture)}</dd></Fragment>)}
      </dl>
    );
  }
  if (b.type === "table") {
    return (
      <div className="my-1 max-w-full overflow-x-auto">
        <table className="border-collapse">
          <thead><tr>{b.columns?.map((c) => <th key={c} className="border-b border-line pr-4 text-left font-semibold text-muted">{c}</th>)}</tr></thead>
          <tbody>{b.rows?.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j} className="whitespace-nowrap pr-4 align-top">{linkify(c, onCapture)}</td>)}</tr>)}</tbody>
        </table>
        {b.total !== undefined && b.total > (b.rows?.length ?? 0) && <div className="text-muted">… {b.rows?.length} of {b.total} shown</div>}
      </div>
    );
  }
  if (b.type === "action" && b.action === "download" && b.url) {
    return <button className="link inline-flex items-center gap-1" onClick={() => download(b.url!, b.label ?? "download")}><Download className="h-3.5 w-3.5" />Download {b.label}</button>;
  }
  if (b.type === "action" && b.action === "open_evidence") {
    const a = b as any;
    return <Link className="link" to={`/findings?f=${a.finding}`}>Open evidence for {a.finding} in Findings →</Link>;
  }
  if (b.type === "action" && b.action === "watch_job" && b.capture_id) {
    const then = (b as any).then as string | undefined;
    return <div className="my-1 max-w-md"><JobProgress captureId={b.capture_id} onDone={(s) => { if (then && s.status === "analyzed") onRun(then); }} /></div>;
  }
  return null;
}

export default function Console() {
  const { captureId, setCaptureId } = useSelection();
  const qc = useQueryClient();
  const [entries, setEntries] = useState<Entry[]>([]);
  const [line, setLine] = useState("");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<string[]>(loadHistory);
  const [hIdx, setHIdx] = useState<number | null>(null);
  const [suggest, setSuggest] = useState<string[]>([]);
  const [pending, setPending] = useState<ConsoleResponse["prompt"] | null>(null);
  const [uploadErr, setUploadErr] = useState<unknown>(null);
  const [uploadPct, setUploadPct] = useState<number | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const endRef = useRef<HTMLDivElement>(null);
  const afterUpload = useRef<string | undefined>(undefined);
  const seq = useRef(0);
  const { data: commands } = useQuery({ queryKey: ["console-commands"], queryFn: () => get<CommandInfo[]>("/console/commands"), staleTime: 300_000 });
  const { data: cap } = useQuery({ queryKey: ["capture", captureId], queryFn: () => get<any>(`/captures/${captureId}`), enabled: !!captureId });

  const promptText = `operator@packetops${cap ? `:${cap.filename}` : ""}$`;

  useEffect(() => { endRef.current?.scrollIntoView({ block: "end" }); }, [entries]);
  useEffect(() => { inputRef.current?.focus(); }, []);

  const run = async (raw: string, opts: { echo?: boolean } = {}) => {
    const input = raw.trim();
    if (!input) return;
    setBusy(true); setSuggest([]); setHIdx(null);
    if (opts.echo !== false) { const h = [...history.filter((x) => x !== input), input]; setHistory(h); saveHistory(h); }
    // Keep the server's selected capture in step with the capture picker.
    const id = ++seq.current;
    try {
      const r = await post<ConsoleResponse>("/console/execute", { line: input });
      const blocks = r.blocks ?? [];
      if (blocks.some((b) => b.type === "action" && b.action === "clear")) { setEntries([]); }
      else setEntries((e) => [...e, { id, input, prompt: promptText, blocks, error: r.error, ask: r.prompt }]);
      setPending(r.prompt ?? null);
      const upload = blocks.find((b) => b.type === "action" && b.action === "open_upload") as any;
      if (upload) { afterUpload.current = upload.then; fileRef.current?.click(); }
      if (r.capture_id !== undefined && r.capture_id !== captureId) setCaptureId(r.capture_id);
      if (r.command && !["help", "status", "whoami", "history", "clear"].includes(r.command)) {
        qc.invalidateQueries({ queryKey: ["progress"] });
        qc.invalidateQueries({ queryKey: ["mission-active"] });
      }
    } catch (err) {
      setEntries((e) => [...e, { id, input, prompt: promptText, blocks: [{ type: "line", level: "error", text: `[-] ${err instanceof Error ? err.message : String(err)}` }], error: true }]);
    } finally {
      setBusy(false);
      inputRef.current?.focus();
    }
  };

  // When the analyst picks a capture elsewhere, tell the console session.
  const synced = useRef<string | null>(null);
  useEffect(() => {
    if (!captureId || synced.current === captureId) return;
    synced.current = captureId;
    post<ConsoleResponse>("/console/execute", { line: `pcap use ${captureId}` }).catch(() => undefined);
  }, [captureId]);

  const onUpload = async (f: File | undefined) => {
    if (!f) return;
    setUploadErr(null); setUploadPct(0);
    try {
      const r = await uploadCapture(f, {}, setUploadPct);
      setUploadPct(null);
      setCaptureId(r.capture.id); synced.current = r.capture.id;
      await run(`pcap use ${r.capture.id}`, { echo: false });
      setEntries((e) => [...e, { id: ++seq.current, input: "", prompt: "", blocks: [
        { type: "line", level: "ok", text: `[+] Uploaded ${r.capture.filename} (${r.capture.id})` },
        ...(r.job ? [{ type: "action", action: "watch_job", capture_id: r.capture.id, then: afterUpload.current } as ConsoleBlock] : []),
      ] }]);
      qc.invalidateQueries({ queryKey: ["captures"] });
    } catch (err) { setUploadPct(null); setUploadErr(err); }
    if (fileRef.current) fileRef.current.value = "";
  };

  const complete = async () => {
    try {
      const r = await post<{ completions: string[] }>("/console/complete", { line });
      const c = r.completions;
      if (!c.length) return;
      const names = new Set((commands ?? []).map((x) => x.name));
      const apply = (choice: string) => {
        if (names.has(choice) && choice.split(" ")[0].startsWith(line.trim().split(/\s+/)[0] ?? "")) return `${choice} `;
        const parts = line.endsWith(" ") ? line : line.replace(/\S+$/, "");
        return `${parts}${choice} `;
      };
      if (c.length === 1) { setLine(apply(c[0])); setSuggest([]); }
      else setSuggest(c);
    } catch { /* completion is best effort */ }
  };

  const onKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") { e.preventDefault(); const l = line; setLine(""); run(l); }
    else if (e.key === "Tab") { e.preventDefault(); complete(); }
    else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (!history.length) return;
      const i = hIdx === null ? history.length - 1 : Math.max(0, hIdx - 1);
      setHIdx(i); setLine(history[i]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (hIdx === null) return;
      const i = hIdx + 1;
      if (i >= history.length) { setHIdx(null); setLine(""); } else { setHIdx(i); setLine(history[i]); }
    } else if (e.key === "l" && e.ctrlKey) { e.preventDefault(); setEntries([]); }
    else if (e.key === "c" && e.ctrlKey && pending) { e.preventDefault(); setLine(""); run("cancel", { echo: false }); }
  };

  const quick = ["status", "pcap inspect", "tcp handshakes", "findings list", "f5 detect", "mission status", "help"];

  return (
    <div className="flex h-full flex-col gap-3">
      <PageHeader title="Command Deck" subtitle="Real commands against your evidence. Tab completes, ↑/↓ recall history, Ctrl+L clears, Ctrl+C cancels a prompt. References like #42, t3 and F2 are links." />
      <div className="flex flex-wrap gap-1.5">
        {quick.map((q) => <button key={q} className="btn mono py-1 text-xs" onClick={() => run(q)} disabled={busy}>{q}</button>)}
      </div>
      {uploadErr ? <ErrorBox error={uploadErr} /> : null}
      <div className="console-dark card flex min-h-[420px] flex-1 flex-col overflow-hidden bg-[#0d1014] font-mono text-[13px] text-[#e4e7eb]"
        onClick={() => { if (!window.getSelection()?.toString()) inputRef.current?.focus(); }}>
        <div className="flex items-center gap-2 border-b border-[#2c333d] px-3 py-1.5 text-xs text-[#969fab]"><Terminal className="h-3.5 w-3.5" aria-hidden />PacketOps Command Deck · {cap ? cap.filename : "no capture selected"}</div>
        <div className="flex-1 overflow-y-auto p-3" role="log" aria-live="polite" aria-label="Console output">
          {entries.length === 0 && (
            <div className="text-[#969fab]">
              <div className="font-bold text-[#ff485c]">F5 PacketOps Command Deck</div>
              <div>Type <span className="text-[#e4e7eb]">help</span> to list commands, or <span className="text-[#e4e7eb]">mission list</span> to start a training mission.</div>
              <div>Output comes from the analysis engine and your stored evidence. Nothing here is simulated, except data marked SYNTHETIC in training missions.</div>
            </div>
          )}
          {entries.map((en) => (
            <div key={en.id} className="mb-2">
              {en.input && <div><span className="text-[#4ade80]">{en.prompt}</span> {en.input}</div>}
              <div>{en.blocks.map((b, i) => <Block key={i} b={b} onCapture={(c) => run(`pcap use ${c}`)} onRun={(l) => run(l)} />)}</div>
              {en.ask && en.ask.choices.length > 0 && en.id === seq.current && pending && (
                <div className="mt-1 flex flex-wrap gap-1">{en.ask.choices.map((c) => <button key={c} className="rounded border border-[#2c333d] px-1.5 py-0.5 hover:bg-[#1c2128]" onClick={() => run(c, { echo: false })}>{c}</button>)}</div>
              )}
            </div>
          ))}
          {uploadPct !== null && <div className="text-[#969fab]">Uploading… {uploadPct}%</div>}
          <div ref={endRef} />
        </div>
        {suggest.length > 0 && (
          <div className="flex flex-wrap gap-2 border-t border-[#2c333d] px-3 py-1 text-xs text-[#969fab]" aria-label="Completions">
            {suggest.map((s) => <button key={s} className="hover:text-[#e4e7eb]" onClick={() => { setLine((l) => (l.endsWith(" ") ? l : l.replace(/\S+$/, "")) + s + " "); setSuggest([]); inputRef.current?.focus(); }}>{s}</button>)}
          </div>
        )}
        <label className="flex items-center gap-2 border-t border-[#2c333d] px-3 py-2">
          <span className="shrink-0 text-[#4ade80]">{pending ? `[${pending.arg}]>` : promptText}</span>
          <input ref={inputRef} className="min-w-0 flex-1 bg-transparent outline-none" value={line} onChange={(e) => { setLine(e.target.value); setSuggest([]); }}
            onKeyDown={onKey} disabled={busy} spellCheck={false} autoComplete="off" aria-label="Console command" placeholder={pending?.message ?? ""} />
        </label>
      </div>
      <input ref={fileRef} type="file" accept=".pcap,.pcapng,.cap" className="hidden" aria-hidden onChange={(e) => onUpload(e.target.files?.[0])} />
    </div>
  );
}
