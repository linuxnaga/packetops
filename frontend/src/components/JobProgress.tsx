import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { eventsUrl } from "../api/client";

interface Snap { status: string; progress: number | null; stage: string | null; message: string | null; job_status: string | null; error: string | null }

/** Live analysis progress over server-sent events. */
export function JobProgress({ captureId, onDone }: { captureId: string; onDone?: (s: Snap) => void }) {
  const [snap, setSnap] = useState<Snap | null>(null);
  const qc = useQueryClient();
  useEffect(() => {
    const es = new EventSource(eventsUrl(captureId));
    const handle = (e: MessageEvent) => setSnap(JSON.parse(e.data));
    es.addEventListener("progress", handle as EventListener);
    es.addEventListener("done", ((e: MessageEvent) => {
      const s = JSON.parse(e.data) as Snap;
      setSnap(s); es.close();
      qc.invalidateQueries();
      onDone?.(s);
    }) as EventListener);
    es.onerror = () => es.close();
    return () => es.close();
  }, [captureId]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!snap) return <div className="text-sm text-muted">Waiting for analysis status…</div>;
  const pct = Math.round(snap.progress ?? 0);
  return (
    <div aria-live="polite">
      <div className="flex justify-between text-xs text-muted"><span>{snap.message ?? snap.stage ?? snap.status}</span><span>{pct}%</span></div>
      <div className="mt-1 h-2 overflow-hidden rounded bg-panel2" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
        <div className={`h-full ${snap.status === "failed" || snap.status === "rejected" ? "bg-bad" : "bg-accent"} transition-all`} style={{ width: `${pct}%` }} />
      </div>
      {snap.error && <p className="mt-1 text-xs text-bad">{snap.error}</p>}
    </div>
  );
}
