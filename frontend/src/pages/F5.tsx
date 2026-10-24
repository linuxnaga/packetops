import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Trash2, Upload } from "lucide-react";
import { del, get, post, type Capture, type Page } from "../api/client";
import { ConfidenceBadge, Empty, ErrorBox, PageHeader, Section, Spinner } from "../components/ui";
import { fmtDate } from "../lib/format";
import { useAuth } from "../lib/auth";
import { useSelection } from "../lib/selection";

interface ConfigSummary { id: string; name: string; source: string; format: string; training: boolean; description?: string; updated_at: string; counts: Record<string, number> }

function ImportConfig({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [text, setText] = useState("");
  const [replace, setReplace] = useState(false);
  const m = useMutation({
    mutationFn: () => {
      const t = text.trim();
      let body: Record<string, unknown> = { name, replace };
      if (t.startsWith("{")) body = { ...body, config: JSON.parse(t) };
      else body = { ...body, text: t };
      return post("/f5/configs", body);
    },
    onSuccess: () => { setName(""); setText(""); onDone(); },
  });
  const loadFile = async (f?: File) => { if (f) { setText(await f.text()); if (!name) setName(f.name.replace(/\.[^.]+$/, "")); } };
  return (
    <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); m.mutate(); }}>
      <p className="text-sm text-muted">Paste <code className="mono">tmsh list ltm</code> / <code className="mono">bigip.conf</code> output or the PacketOps JSON format. Only virtual servers, pools, SNAT, self IPs, VLANs and routes are kept. Do not paste keys or certificates.</p>
      <div className="flex flex-wrap gap-2">
        <input className="input max-w-xs" value={name} onChange={(e) => setName(e.target.value)} placeholder="Name, e.g. bigip-prod-01" aria-label="Configuration name" required maxLength={200} />
        <label className="btn cursor-pointer"><Upload className="h-3.5 w-3.5" />Load file<input type="file" className="hidden" accept=".conf,.txt,.json" onChange={(e) => loadFile(e.target.files?.[0])} /></label>
        <label className="flex items-center gap-1.5 text-sm"><input type="checkbox" checked={replace} onChange={(e) => setReplace(e.target.checked)} />Replace existing with the same name</label>
      </div>
      <textarea className="input mono h-40" value={text} onChange={(e) => setText(e.target.value)} aria-label="Configuration text" placeholder={"ltm virtual /Common/vs_app {\n    destination /Common/10.0.0.100:443\n    pool /Common/pool_app\n    source-address-translation { type automap }\n}"} required />
      {m.error && <ErrorBox error={m.error} />}
      <button className="btn-primary" disabled={m.isPending || !name || !text.trim()}>Import</button>
    </form>
  );
}

function ConfigDetail({ id }: { id: string }) {
  const { data, isLoading, error } = useQuery({ queryKey: ["f5config", id], queryFn: () => get<any>(`/f5/configs/${id}`) });
  if (isLoading) return <Spinner />;
  if (error) return <ErrorBox error={error} />;
  return (
    <div className="space-y-3 text-sm">
      {data.training && <p className="text-xs font-medium text-warn">SYNTHETIC training metadata</p>}
      <div>
        <div className="label mb-1">Virtual servers</div>
        <table className="tbl"><thead><tr><th>Name</th><th>Destination</th><th>Pool</th><th>SNAT</th><th>Profiles</th></tr></thead>
          <tbody>{(data.virtual_servers ?? []).map((v: any) => (
            <tr key={v.name}><td className="mono">{v.name}</td><td className="mono">{v.address}:{v.port}</td><td className="mono">{v.pool ?? "-"}</td>
              <td className="mono">{v.source_address_translation?.type ?? "none"}{v.source_address_translation?.pool ? ` (${v.source_address_translation.pool})` : ""}</td>
              <td className="text-xs">{(v.profiles ?? []).join(", ")}</td></tr>
          ))}</tbody></table>
      </div>
      <div>
        <div className="label mb-1">Pools</div>
        <table className="tbl"><thead><tr><th>Name</th><th>Members</th><th>Monitor</th><th>LB method</th></tr></thead>
          <tbody>{(data.pools ?? []).map((p: any) => (
            <tr key={p.name}><td className="mono">{p.name}</td><td className="mono text-xs">{(p.members ?? []).map((m: any) => `${m.address}:${m.port}`).join(", ")}</td>
              <td className="text-xs">{Array.isArray(p.monitor) ? p.monitor.join(", ") : p.monitor ?? "-"}</td><td className="text-xs">{p.lb_method ?? "not set"}</td></tr>
          ))}</tbody></table>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <div><div className="label mb-1">SNAT addresses / pools</div><p className="mono text-xs">{[...(data.snat_addresses ?? []).map((s: any) => s.address ?? s), ...(data.snat_pools ?? []).map((s: any) => `${s.name}: ${(s.members ?? []).join(", ")}`)].join("; ") || "-"}</p></div>
        <div><div className="label mb-1">Self IPs</div><p className="mono text-xs">{(data.self_ips ?? []).map((s: any) => `${s.address} (${s.vlan ?? "?"})`).join(", ") || "-"}</p></div>
      </div>
    </div>
  );
}

function Correlate({ configs }: { configs: ConfigSummary[] }) {
  const { captureId } = useSelection();
  const qc = useQueryClient();
  const caps = useQuery({ queryKey: ["captures", "analyzed"], queryFn: () => get<Page<Capture>>("/captures", { limit: 100, status: "analyzed" }) });
  const [client, setClient] = useState(captureId ?? "");
  const [server, setServer] = useState("");
  const [config, setConfig] = useState("");
  const m = useMutation({
    mutationFn: () => post<any>("/f5/correlations", { client_capture_id: client, server_capture_id: server || undefined, config_id: config || undefined }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["correlations"] }),
  });
  const opts = caps.data?.items ?? [];
  return (
    <div className="space-y-3">
      <form className="grid gap-2 md:grid-cols-4" onSubmit={(e) => { e.preventDefault(); m.mutate(); }}>
        <label className="text-sm"><span className="label">Client-side / BIG-IP capture</span>
          <select className="input mt-1" value={client} onChange={(e) => setClient(e.target.value)} required>
            <option value="">—</option>{opts.map((c) => <option key={c.id} value={c.id}>{c.training ? "[training] " : ""}{c.filename}</option>)}
          </select></label>
        <label className="text-sm"><span className="label">Server-side capture (optional)</span>
          <select className="input mt-1" value={server} onChange={(e) => setServer(e.target.value)}>
            <option value="">same capture</option>{opts.filter((c) => c.id !== client).map((c) => <option key={c.id} value={c.id}>{c.training ? "[training] " : ""}{c.filename}</option>)}
          </select></label>
        <label className="text-sm"><span className="label">BIG-IP metadata (optional)</span>
          <select className="input mt-1" value={config} onChange={(e) => setConfig(e.target.value)}>
            <option value="">none</option>{configs.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select></label>
        <div className="flex items-end"><button className="btn-primary" disabled={!client || m.isPending}>{m.isPending ? "Correlating…" : "Correlate flows"}</button></div>
      </form>
      {m.error && <ErrorBox error={m.error} />}
      {m.data && <CorrelationView c={m.data} />}
    </div>
  );
}

export function CorrelationView({ c }: { c: any }) {
  const { setCaptureId } = useSelection();
  return (
    <div className="space-y-3 text-sm">
      {c.training && <p className="text-xs font-medium text-warn">SYNTHETIC training data</p>}
      <div className="grid gap-3 md:grid-cols-2">
        <div><div className="label mb-1">BIG-IP evidence</div>
          {c.bigip_evidence?.length ? <ul className="list-disc pl-5">{c.bigip_evidence.map((e: string) => <li key={e}>{e}</li>)}</ul> : <p className="text-muted">No BIG-IP-specific evidence was found. The pairs below rely on timing and metadata only.</p>}</div>
        <div><div className="label mb-1">Summary</div>
          <p>{c.pairs?.length ?? 0} pair(s) via {c.methods?.join(", ") || "-"}; {c.unmatched_client} client-side and {c.unmatched_server} server-side flow(s) unmatched.
            {c.estimated_proxy_delay_ms !== null && c.estimated_proxy_delay_ms !== undefined ? ` Median client→server start delay ${c.estimated_proxy_delay_ms} ms.` : ""}</p></div>
      </div>
      {c.observations?.length > 0 && (
        <div><div className="label mb-1">Observations</div>
          <ul className="space-y-1">{c.observations.map((o: any, i: number) => <li key={i} className={o.level === "warn" ? "text-warn" : ""}>{o.text}</li>)}</ul></div>
      )}
      {c.pairs?.length > 0 && (
        <div className="max-h-[50vh] overflow-auto rounded border border-line">
          <table className="tbl"><thead><tr><th>Client flow</th><th>Client → VIP</th><th>SNAT → member</th><th>Virtual / pool</th><th>Method</th><th>Confidence</th><th>Reset</th></tr></thead>
            <tbody>{c.pairs.map((p: any) => (
              <tr key={`${p.client_flow_id}-${p.server_flow_id}`}>
                <td><Link className="link mono" to={`/flows?flow=${p.client_flow}`} onClick={() => setCaptureId(c.client_capture_id)}>{p.client_flow}</Link> ↔ <Link className="link mono" to={`/flows?flow=${p.server_flow}`} onClick={() => setCaptureId(c.server_capture_id ?? c.client_capture_id)}>{p.server_flow}</Link></td>
                <td className="mono text-xs">{p.client} → {p.vip}</td>
                <td className="mono text-xs">{p.snat ?? "-"} → {p.member}</td>
                <td className="mono text-xs">{p.virtual ?? "-"}<br />{p.pool ?? ""}</td>
                <td className="text-xs" title={(p.notes ?? []).join("; ")}>{p.method}</td>
                <td><ConfidenceBadge level={p.confidence} /></td>
                <td className="text-xs">{p.first_reset_side ? `${p.first_reset_side} side first` : "-"}</td>
              </tr>
            ))}</tbody></table>
        </div>
      )}
      <div><div className="label mb-1">Limitations</div><ul className="list-disc pl-5 text-xs text-muted">{c.limitations?.map((l: string) => <li key={l}>{l}</li>)}</ul></div>
    </div>
  );
}

export default function F5() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const configs = useQuery({ queryKey: ["f5configs"], queryFn: () => get<ConfigSummary[]>("/f5/configs") });
  const corrs = useQuery({ queryKey: ["correlations"], queryFn: () => get<any[]>("/f5/correlations") });
  const [open, setOpen] = useState<string | null>(null);
  const [openCorr, setOpenCorr] = useState<string | null>(null);
  const corr = useQuery({ queryKey: ["correlation", openCorr], queryFn: () => get<any>(`/f5/correlations/${openCorr}`), enabled: !!openCorr });
  const remove = useMutation({ mutationFn: (id: string) => del(`/f5/configs/${id}`), onSuccess: () => qc.invalidateQueries({ queryKey: ["f5configs"] }) });
  return (
    <div className="space-y-4">
      <PageHeader title="BIG-IP intelligence" subtitle="Import BIG-IP configuration as context, then pair client-side and server-side connections through the proxy. A BIG-IP is never assumed; every pair states how it was matched." />
      {can("correlation:run") && <Section title="Correlate client-side and server-side flows"><Correlate configs={configs.data ?? []} /></Section>}
      <div className="grid gap-4 xl:grid-cols-2">
        <Section title="BIG-IP configuration metadata">
          {configs.isLoading ? <Spinner /> : configs.error ? <ErrorBox error={configs.error} /> : configs.data?.length ? (
            <ul className="divide-y divide-line">
              {configs.data.map((c) => (
                <li key={c.id} className="py-2">
                  <div className="flex items-center justify-between gap-2">
                    <button className="link text-left text-sm font-medium" onClick={() => setOpen(open === c.id ? null : c.id)} aria-expanded={open === c.id}>{c.name}</button>
                    <div className="flex items-center gap-2 text-xs text-muted">
                      <span>{c.counts.virtual_servers ?? 0} VS · {c.counts.pools ?? 0} pools · {fmtDate(c.updated_at)}</span>
                      {can("f5config:write") && !c.training && <button className="btn px-1.5 py-0.5" aria-label={`Delete ${c.name}`} onClick={() => { if (confirm(`Delete configuration ${c.name}?`)) remove.mutate(c.id); }}><Trash2 className="h-3.5 w-3.5" /></button>}
                    </div>
                  </div>
                  {open === c.id && <div className="mt-2"><ConfigDetail id={c.id} /></div>}
                </li>
              ))}
            </ul>
          ) : <Empty title="No BIG-IP metadata imported">Correlation still works from F5 Ethernet trailers and timing alone.</Empty>}
          {can("f5config:write") && <details className="mt-3"><summary className="cursor-pointer text-sm font-medium">Import configuration</summary><div className="mt-2"><ImportConfig onDone={() => qc.invalidateQueries({ queryKey: ["f5configs"] })} /></div></details>}
        </Section>
        <Section title="Previous correlations">
          {corrs.isLoading ? <Spinner /> : corrs.data?.length ? (
            <ul className="divide-y divide-line text-sm">
              {corrs.data.map((c) => (
                <li key={c.id} className="py-2">
                  <button className="link text-left" onClick={() => setOpenCorr(openCorr === c.id ? null : c.id)} aria-expanded={openCorr === c.id}>
                    {c.config_name ?? "no metadata"} · {c.methods?.join(", ") || "no pairs"}
                  </button>
                  <div className="text-xs text-muted">{fmtDate(c.created_at)} · {c.training ? "training · " : ""}{c.client_capture_id}{c.server_capture_id ? ` + ${c.server_capture_id}` : ""}</div>
                  {openCorr === c.id && <div className="mt-2">{corr.isLoading ? <Spinner /> : corr.data ? <CorrelationView c={corr.data} /> : null}</div>}
                </li>
              ))}
            </ul>
          ) : <Empty title="No correlations yet" />}
        </Section>
      </div>
    </div>
  );
}
