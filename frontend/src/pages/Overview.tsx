import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { get } from "../api/client";
import { EChart } from "../components/EChart";
import { ConfidenceBadge, Empty, ErrorBox, PageHeader, Section, SeverityBadge, Spinner, Stat, StatusPill } from "../components/ui";
import { fmtBytes, fmtDate, fmtNum } from "../lib/format";
import { useSelection } from "../lib/selection";

export default function Overview() {
  const { data, isLoading, error } = useQuery({ queryKey: ["overview"], queryFn: () => get<any>("/overview"), refetchInterval: 15000 });
  const { setCaptureId } = useSelection();
  const nav = useNavigate();
  if (isLoading) return <Spinner />;
  if (error) return <ErrorBox error={error} />;
  const sev = data.finding_severity ?? {};
  const open = (id: string, to: string) => { setCaptureId(id); nav(to); };
  return (
    <div className="space-y-4">
      <PageHeader title="Investigation overview" subtitle="Evidence captures, analysis activity and open findings in your tenant. Training captures are excluded from these figures." />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Stat label="Analysed captures" value={fmtNum(data.capture_status?.analyzed ?? 0)} hint={`${data.active_jobs.length} analysis job(s) running`} />
        <Stat label="Critical / high findings" value={`${sev.critical ?? 0} / ${sev.high ?? 0}`} tone={(sev.critical || sev.high) ? "bad" : undefined} hint="open, evidence captures" />
        <Stat label="Medium / low" value={`${sev.medium ?? 0} / ${sev.low ?? 0}`} />
        <Stat label="Open investigations" value={data.active_investigations.length} />
        <Stat label="Your level" value={`Lv ${data.profile.level}`} hint={data.profile.title} />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title={`Protocol distribution (${data.protocol_scope})`}>
          {data.protocol_distribution.length ? (
            <EChart label="Protocol distribution bar chart" height={240} option={{
              grid: { left: 90, right: 20, top: 10, bottom: 20 }, tooltip: {},
              xAxis: { type: "value" }, yAxis: { type: "category", data: data.protocol_distribution.slice(0, 10).map((p: any) => p.name).reverse() },
              series: [{ type: "bar", data: data.protocol_distribution.slice(0, 10).map((p: any) => p.packets).reverse(), itemStyle: { color: "#c8102e" } }],
            }} />
          ) : <Empty title="No analysed evidence captures yet" />}
        </Section>
        <Section title="Top endpoints by bytes">
          {data.top_endpoints.length ? (
            <table className="tbl"><thead><tr><th>Address</th><th className="text-right">Bytes</th></tr></thead>
              <tbody>{data.top_endpoints.slice(0, 8).map((e: any) => <tr key={e.ip}><td className="mono">{e.ip}</td><td className="text-right tabular-nums">{fmtBytes(e.bytes)}</td></tr>)}</tbody></table>
          ) : <Empty title="No endpoints yet" />}
        </Section>
      </div>
      <Section title="Highest-severity open findings">
        {data.top_findings.length ? (
          <table className="tbl"><thead><tr><th>Severity</th><th>Finding</th><th>Confidence</th><th>Capture</th></tr></thead>
            <tbody>{data.top_findings.map((f: any) => (
              <tr key={`${f.capture_id}-${f.short_id}`}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td><button className="link text-left" onClick={() => open(f.capture_id, `/findings?f=${f.short_id}`)}>{f.short_id} · {f.title}</button></td>
                <td><ConfidenceBadge level={f.confidence.level} /></td>
                <td className="mono text-muted">{f.capture_id}</td>
              </tr>))}</tbody></table>
        ) : <Empty title="No open findings">Upload a capture in the <Link className="link" to="/workbench">PCAP Workbench</Link>.</Empty>}
      </Section>
      <Section title="Recent captures">
        {data.recent_captures.length ? (
          <div className="overflow-x-auto"><table className="tbl"><thead><tr><th>File</th><th>Status</th><th className="text-right">Packets</th><th className="text-right">Size</th><th className="text-right">Findings</th><th>Uploaded</th></tr></thead>
            <tbody>{data.recent_captures.map((c: any) => (
              <tr key={c.id}>
                <td><button className="link" onClick={() => open(c.id, "/workbench")}>{c.filename}</button>{c.training && <span className="ml-2 text-xs text-warn">training</span>}</td>
                <td><StatusPill status={c.status} /></td>
                <td className="text-right tabular-nums">{fmtNum(c.stats?.packets)}</td>
                <td className="text-right tabular-nums">{fmtBytes(c.size_bytes)}</td>
                <td className="text-right tabular-nums">{fmtNum(c.stats?.findings)}</td>
                <td className="text-muted">{fmtDate(c.created_at)}</td>
              </tr>))}</tbody></table></div>
        ) : <Empty title="No captures yet" />}
      </Section>
    </div>
  );
}
