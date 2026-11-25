import type { ReactNode } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";
import type { Severity } from "../api/client";

const SEV_CLS: Record<string, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
  high: "bg-sev-high/15 text-sev-high border-sev-high/40",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/40",
  low: "bg-sev-low/15 text-sev-low border-sev-low/40",
  info: "bg-sev-info/15 text-sev-info border-sev-info/40",
};

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  return <span className={`inline-block rounded border px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${SEV_CLS[severity] ?? SEV_CLS.info}`}>{severity}</span>;
}

export function ConfidenceBadge({ level }: { level: string }) {
  const dots = level === "high" ? 3 : level === "medium" ? 2 : 1;
  return (
    <span className="inline-flex items-center gap-1 text-xs text-muted" title={`Confidence: ${level}`}>
      {[0, 1, 2].map((i) => <span key={i} className={`h-1.5 w-1.5 rounded-full ${i < dots ? "bg-fg" : "bg-line"}`} />)}
      <span>{level}</span>
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const cls = status === "analyzed" || status === "completed" || status === "confirmed" || status === "resolved" ? "text-ok"
    : status === "failed" || status === "rejected" ? "text-bad" : status === "analyzing" || status === "queued" || status === "running" ? "text-warn" : "text-muted";
  return <span className={`text-xs font-medium ${cls}`}>● {status}</span>;
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return <div role="status" className="flex items-center gap-2 p-4 text-sm text-muted"><Loader2 className="h-4 w-4 animate-spin" aria-hidden />{label}…</div>;
}

export function ErrorBox({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  return <div role="alert" className="flex items-start gap-2 rounded-md border border-bad/40 bg-bad/10 p-3 text-sm text-bad"><AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />{msg}</div>;
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="rounded-lg border border-dashed border-line p-8 text-center"><p className="font-medium">{title}</p>{children && <div className="mt-2 text-sm text-muted">{children}</div>}</div>;
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div><h1 className="text-xl font-semibold">{title}</h1>{subtitle && <p className="mt-0.5 text-sm text-muted">{subtitle}</p>}</div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: "bad" | "warn" | "ok" }) {
  const color = tone === "bad" ? "text-bad" : tone === "warn" ? "text-warn" : tone === "ok" ? "text-ok" : "";
  return (
    <div className="card p-3">
      <div className="label">{label}</div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${color}`}>{value}</div>
      {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function SyntheticBanner() {
  return <div className="mb-3 rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-sm font-medium text-warn">SYNTHETIC TRAINING DATA — generated for a mission, not evidence from a real network.</div>;
}

export function Section({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="card">
      <div className="flex items-center justify-between border-b border-line px-3 py-2"><h2 className="text-sm font-semibold">{title}</h2>{actions}</div>
      <div className="p-3">{children}</div>
    </section>
  );
}
