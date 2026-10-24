import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { get, type Flow, type Page } from "../api/client";
import { EChart } from "../components/EChart";
import { Empty, ErrorBox, PageHeader, Section, Spinner } from "../components/ui";
import { ep, fmtBytes, fmtMs, fmtNum, fmtTsNs } from "../lib/format";
import { useSelection } from "../lib/selection";

function Graph({ captureId, onEdge }: { captureId: string; onEdge: (ip: string) => void }) {
  const { data, error } = useQuery({ queryKey: ["graph", captureId], queryFn: () => get<any>(`/captures/${captureId}/graph`, { limit: 150 }) });
  const { nodes, edges } = useMemo(() => {
    if (!data) return { nodes: [] as Node[], edges: [] as Edge[] };
    const clients = data.nodes.filter((n: any) => !n.roles.includes("server"));
    const servers = data.nodes.filter((n: any) => n.roles.includes("server"));
    const place = (list: any[], x: number): Node[] => list.map((n, i) => ({
      id: n.id, position: { x, y: i * 70 }, data: { label: `${n.id}${n.issues ? `  ⚠ ${n.issues}` : ""}` },
      style: { fontSize: 11, fontFamily: "monospace", borderColor: n.issues ? "#e11d48" : undefined, width: 190 },
    }));
    return {
      nodes: [...place(clients, 0), ...place(servers, 420)],
      edges: data.edges.map((e: any, i: number) => ({
        id: `e${i}`, source: e.source, target: e.target, label: `${e.transport}/${e.port} ×${e.flows}`,
        animated: e.issues > 0, markerEnd: { type: MarkerType.ArrowClosed },
        style: { stroke: e.issues ? "#e11d48" : "#8a94a3", strokeWidth: Math.min(4, 1 + Math.log10(1 + e.packets)) },
        labelStyle: { fontSize: 10 },
      })),
    };
  }, [data]);
  if (error) return <ErrorBox error={error} />;
  if (!data) return <Spinner />;
  return (
    <div className="h-[340px] rounded border border-line" aria-label="Conversation graph: clients on the left, servers on the right; red edges carry findings">
      <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }} onNodeClick={(_, n) => onEdge(n.id)} nodesConnectable={false}>
        <Background /><Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

function SequenceChart({ captureId, flow }: { captureId: string; flow: string }) {
  const { data, error } = useQuery({ queryKey: ["seq", captureId, flow], queryFn: () => get<any>(`/captures/${captureId}/flows/${flow}/sequence`) });
  if (error) return <ErrorBox error={error} />;
  if (!data) return <Spinner />;
  const pts = data.points as any[];
  const series = (dir: string, retrans: boolean) => pts.filter((p) => p.dir === dir && p.tcp_len > 0 && !!p.analysis?.includes("retrans") === retrans)
    .map((p) => [p.rel_s, p.tcp_seq + p.tcp_len, p.number]);
  return (
    <EChart label={`TCP sequence numbers over time for ${flow}; retransmissions highlighted`} height={280} option={{
      tooltip: { trigger: "item", formatter: (p: any) => `#${p.data[2]} · ${p.seriesName}<br/>t=${p.data[0]}s seq end=${p.data[1]}` },
      legend: { top: 0 }, grid: { left: 60, right: 20, top: 30, bottom: 50 },
      xAxis: { type: "value", name: "s", scale: true }, yAxis: { type: "value", name: "rel. seq", scale: true },
      dataZoom: [{ type: "inside" }, { type: "slider", height: 16, bottom: 8 }],
      series: [
        { name: "client→server data", type: "scatter", symbolSize: 5, data: series("c2s", false), itemStyle: { color: "#2563eb" } },
        { name: "server→client data", type: "scatter", symbolSize: 5, data: series("s2c", false), itemStyle: { color: "#16a34a" } },
        { name: "retransmission", type: "scatter", symbolSize: 9, symbol: "diamond", data: [...series("c2s", true), ...series("s2c", true)], itemStyle: { color: "#e11d48" } },
        { name: "ACK (client)", type: "line", step: "end", showSymbol: false, data: pts.filter((p) => p.dir === "c2s").map((p) => [p.rel_s, p.tcp_ack, p.number]), lineStyle: { width: 1, color: "#9ca3af" } },
      ],
    }} />
  );
}

function FlowDetail({ captureId, local }: { captureId: string; local: string }) {
  const { data: f, error } = useQuery({ queryKey: ["flow", captureId, local], queryFn: () => get<Flow>(`/captures/${captureId}/flows/${local}`) });
  if (error) return <ErrorBox error={error} />;
  if (!f) return <Spinner />;
  return (
    <div className="space-y-3">
      <Section title={`${f.local_id} · ${ep(f.client_ip, f.client_port)} → ${ep(f.server_ip, f.server_port)}`}
        actions={<Link className="link text-sm" to={`/workbench?filter=${encodeURIComponent(`flow == "${f.local_id}"`)}`}>packets →</Link>}>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm md:grid-cols-4">
          <dt className="text-muted">State</dt><dd>{f.state}</dd>
          <dt className="text-muted">Duration</dt><dd>{fmtMs(f.duration_ms)}</dd>
          <dt className="text-muted">Packets</dt><dd>{fmtNum(f.packets)}</dd>
          <dt className="text-muted">Bytes c→s / s→c</dt><dd>{fmtBytes(f.bytes_c2s)} / {fmtBytes(f.bytes_s2c)}</dd>
          {f.handshake && <><dt className="text-muted">Handshake RTT</dt><dd>{f.handshake.rtt_ms != null ? fmtMs(f.handshake.rtt_ms) : "not observed"}</dd></>}
          <dt className="text-muted">Retransmissions</dt><dd>{fmtNum(f.retransmissions ?? 0)}</dd>
          {f.tls?.sni && <><dt className="text-muted">TLS SNI</dt><dd className="mono">{f.tls.sni}</dd></>}
          {f.f5 && <><dt className="text-muted">F5 trailer</dt><dd className="mono">{f.f5.vip ?? ""} {f.f5.flow_ids?.[0] ?? ""}</dd></>}
        </dl>
        {f.finding_ids.length > 0 && <p className="mt-2 text-sm">Findings: {f.finding_ids.map((id) => <Link key={id} className="link mr-2" to={`/findings?f=${id.split("-").pop()}`}>{id.split("-").pop()}</Link>)}</p>}
      </Section>
      {f.transport === "tcp" && <Section title="TCP sequence (Stevens) chart"><SequenceChart captureId={captureId} flow={f.local_id} /></Section>}
      <Section title="Timeline">
        {f.timeline?.length ? (
          <ol className="mono space-y-0.5 text-[12px]">
            {f.timeline.map((e, i) => <li key={i} className={e.dir === "s2c" ? "pl-6" : ""}><span className="text-muted">{fmtTsNs(e.ts_ns).slice(11)}</span> {e.frame ? <span className="text-muted">#{e.frame}</span> : null} {e.event}</li>)}
          </ol>) : <p className="text-sm text-muted">No timeline events for this conversation.</p>}
      </Section>
    </div>
  );
}

export default function Flows() {
  const { captureId } = useSelection();
  const [params, setParams] = useSearchParams();
  const [ipFilter, setIp] = useState<string>("");
  const [state, setState] = useState("");
  const selected = params.get("flow");
  const { data, error, isLoading } = useQuery({
    queryKey: ["flows", captureId, ipFilter, state], enabled: !!captureId,
    queryFn: () => get<Page<Flow>>(`/captures/${captureId}/flows`, { limit: 200, ip: ipFilter || undefined, state: state || undefined }),
  });
  if (!captureId) return <Empty title="No capture selected">Choose a capture in the selector above.</Empty>;
  const pick = (id: string) => { const p = new URLSearchParams(params); p.set("flow", id); setParams(p); };
  return (
    <div className="space-y-4">
      <PageHeader title="Flow Explorer" subtitle="Conversations ranked by issues. Click a host in the graph to filter, a row to inspect." />
      <Graph captureId={captureId} onEdge={(ip) => setIp(ip)} />
      <div className="grid gap-4 xl:grid-cols-2">
        <Section title={`Conversations ${data ? `(${data.total})` : ""}`} actions={
          <div className="flex gap-2">
            {ipFilter && <button className="btn py-0.5 text-xs" onClick={() => setIp("")}>host {ipFilter} ✕</button>}
            <select className="input py-0.5 text-xs" value={state} onChange={(e) => setState(e.target.value)} aria-label="Filter by state">
              <option value="">all states</option>{["established", "closed", "reset", "syn-unanswered", "handshake-incomplete", "half-closed", "mid-stream", "udp"].map((s) => <option key={s}>{s}</option>)}
            </select>
          </div>}>
          {isLoading ? <Spinner /> : error ? <ErrorBox error={error} /> : (
            <div className="max-h-[60vh] overflow-auto">
              <table className="tbl">
                <thead><tr><th>Id</th><th>Client</th><th>Server</th><th>State</th><th className="text-right">Pkts</th><th className="text-right">Issues</th></tr></thead>
                <tbody>{data!.items.map((f) => (
                  <tr key={f.local_id} onClick={() => pick(f.local_id)} className={`cursor-pointer ${selected === f.local_id ? "!bg-accent/15" : ""}`} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && pick(f.local_id)}>
                    <td className="mono">{f.local_id}</td><td className="mono">{ep(f.client_ip, f.client_port)}</td><td className="mono">{ep(f.server_ip, f.server_port)}</td>
                    <td className={f.state === "reset" || f.state === "syn-unanswered" ? "text-bad" : ""}>{f.state}</td>
                    <td className="text-right tabular-nums">{f.packets}</td><td className="text-right tabular-nums">{f.finding_ids.length || ""}</td>
                  </tr>))}</tbody>
              </table>
            </div>)}
        </Section>
        {selected ? <FlowDetail captureId={captureId} local={selected} /> : <Empty title="Select a conversation" />}
      </div>
    </div>
  );
}
