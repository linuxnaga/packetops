import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileText } from "lucide-react";
import { download, get, post, type Capture } from "../api/client";
import { Empty, ErrorBox, PageHeader, Section, Spinner } from "../components/ui";
import { fmtBytes, fmtDate } from "../lib/format";
import { useAuth } from "../lib/auth";
import { useSelection } from "../lib/selection";

interface Report { id: string; capture_id: string; format: string; filename: string; size_bytes: number; sha256: string; finding_count: number; evidence_count: number; training: boolean; created_at: string }

export default function Reports() {
  const { captureId } = useSelection();
  const { can } = useAuth();
  const qc = useQueryClient();
  const [fmt, setFmt] = useState<"html" | "pdf" | "json">("html");
  const [dlErr, setDlErr] = useState<unknown>(null);
  const cap = useQuery({ queryKey: ["capture", captureId], queryFn: () => get<Capture>(`/captures/${captureId}`), enabled: !!captureId });
  const reports = useQuery({ queryKey: ["reports"], queryFn: () => get<Report[]>("/reports") });
  const create = useMutation({
    mutationFn: () => post<Report>("/reports", { capture_id: captureId, format: fmt }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["reports"] }); qc.invalidateQueries({ queryKey: ["progress"] }); },
  });
  const dl = async (r: Report) => { setDlErr(null); try { await download(`/api/v1/reports/${r.id}/download`, r.filename); } catch (e) { setDlErr(e); } };
  const ready = cap.data?.status === "analyzed";
  return (
    <div className="space-y-4">
      <PageHeader title="Reports" subtitle="Evidence-backed reports with methodology, limitations and reproducible filters. Packet payloads are never included." />
      {can("report:create") && (
        <Section title="Generate a report">
          {!captureId ? <Empty title="No capture selected">Choose a capture from the selector above.</Empty> : (
            <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
              <div className="text-sm"><div className="label">Capture</div><div className="mt-1 font-medium">{cap.data?.filename ?? captureId}{cap.data?.training ? " (synthetic training data)" : ""}</div></div>
              <label className="text-sm"><span className="label">Format</span>
                <select className="input mt-1" value={fmt} onChange={(e) => setFmt(e.target.value as typeof fmt)}>
                  <option value="html">HTML (self-contained)</option><option value="pdf">PDF</option><option value="json">JSON (machine-readable)</option>
                </select></label>
              <button className="btn-primary" disabled={!ready || create.isPending}><FileText className="h-4 w-4" />{create.isPending ? "Generating…" : "Generate"}</button>
              {!ready && cap.data && <span className="text-sm text-muted">The capture must finish analysis first (status: {cap.data.status}).</span>}
            </form>
          )}
          {create.error && <div className="mt-2"><ErrorBox error={create.error} /></div>}
          {create.data && <p className="mt-2 text-sm text-ok" role="status">Created {create.data.filename} with {create.data.finding_count} finding(s). <button className="link" onClick={() => dl(create.data!)}>Download</button></p>}
        </Section>
      )}
      <Section title="Generated reports">
        {dlErr ? <div className="mb-2"><ErrorBox error={dlErr} /></div> : null}
        {reports.isLoading ? <Spinner /> : reports.error ? <ErrorBox error={reports.error} /> : reports.data?.length ? (
          <div className="overflow-x-auto">
            <table className="tbl"><thead><tr><th>File</th><th>Format</th><th>Findings</th><th>Size</th><th>SHA-256</th><th>Created</th><th /></tr></thead>
              <tbody>{reports.data.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.filename}{r.training && <span className="ml-2 text-xs text-warn">training</span>}</td>
                  <td className="uppercase">{r.format}</td><td className="tabular-nums">{r.finding_count}</td><td>{fmtBytes(r.size_bytes)}</td>
                  <td className="mono text-xs" title={r.sha256}>{r.sha256.slice(0, 16)}…</td><td>{fmtDate(r.created_at)}</td>
                  <td><button className="btn py-0.5" onClick={() => dl(r)} aria-label={`Download ${r.filename}`}><Download className="h-3.5 w-3.5" /></button></td>
                </tr>
              ))}</tbody></table>
          </div>
        ) : <Empty title="No reports yet" />}
      </Section>
    </div>
  );
}
