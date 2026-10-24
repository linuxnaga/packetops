import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { get, type Page } from "../api/client";
import { Empty, ErrorBox, PageHeader, Section, Spinner } from "../components/ui";
import { fmtDate } from "../lib/format";

interface AuditEvent { id: string; ts: string; actor_email: string; action: string; resource_type: string; resource_id: string; outcome: string; details: Record<string, unknown>; request_id?: string }
const PAGE = 100;

export default function Audit() {
  const [action, setAction] = useState("");
  const [days, setDays] = useState(30);
  const [offset, setOffset] = useState(0);
  const { data, isLoading, error } = useQuery({
    queryKey: ["audit", action, days, offset],
    queryFn: () => get<Page<AuditEvent>>("/audit", { action: action || undefined, days, limit: PAGE, offset }),
    placeholderData: (p) => p,
  });
  return (
    <div className="space-y-4">
      <PageHeader title="Audit log" subtitle="Append-only record of security-relevant actions in this tenant. Payloads and tokens are never recorded." />
      <Section title="Events" actions={data ? <span className="text-xs text-muted">{data.total} event(s)</span> : null}>
        <div className="mb-3 flex flex-wrap gap-2">
          <input className="input max-w-xs" value={action} onChange={(e) => { setAction(e.target.value.trim()); setOffset(0); }} placeholder="Exact action, e.g. capture.upload" aria-label="Filter by action" />
          <select className="input max-w-[10rem]" value={days} onChange={(e) => { setDays(Number(e.target.value)); setOffset(0); }} aria-label="Time range">
            {[1, 7, 30, 90, 365].map((d) => <option key={d} value={d}>Last {d} day(s)</option>)}
          </select>
        </div>
        {isLoading ? <Spinner /> : error ? <ErrorBox error={error} /> : data?.items.length ? (
          <>
            <div className="max-h-[65vh] overflow-auto rounded border border-line">
              <table className="tbl"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th><th>Outcome</th><th>Details</th></tr></thead>
                <tbody>{data.items.map((e) => (
                  <tr key={e.id}>
                    <td className="whitespace-nowrap text-xs">{fmtDate(e.ts)}</td><td className="text-xs">{e.actor_email}</td><td className="mono">{e.action}</td>
                    <td className="mono text-xs">{e.resource_type}:{e.resource_id}</td>
                    <td className={e.outcome === "success" ? "text-ok" : "text-bad"}>{e.outcome}</td>
                    <td className="mono max-w-md truncate text-xs" title={JSON.stringify(e.details)}>{Object.keys(e.details ?? {}).length ? JSON.stringify(e.details) : ""}</td>
                  </tr>
                ))}</tbody></table>
            </div>
            <div className="mt-2 flex gap-2">
              <button className="btn" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
              <button className="btn" disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)}>Next</button>
            </div>
          </>
        ) : <Empty title="No audit events match" />}
      </Section>
    </div>
  );
}
