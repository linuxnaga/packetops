// Thin typed client for the PacketOps REST API (/api/v1).

const TOKEN_KEY = "packetops.token";

export function getToken(): string | null {
  try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
}
export function setToken(token: string | null): void {
  try { if (token) localStorage.setItem(TOKEN_KEY, token); else localStorage.removeItem(TOKEN_KEY); } catch { /* storage unavailable */ }
}

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public details?: unknown) { super(message); }
}

type Query = Record<string, string | number | boolean | undefined | null>;

function qs(params?: Query): string {
  if (!params) return "";
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") u.set(k, String(v));
  const s = u.toString();
  return s ? `?${s}` : "";
}

export async function api<T = unknown>(method: string, path: string, opts: { query?: Query; body?: unknown } = {}): Promise<T> {
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`/api/v1${path}${qs(opts.query)}`, {
    method, headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const data = text ? JSON.parse(text) : undefined;
  if (!res.ok) {
    const err = data?.error ?? {};
    if (res.status === 401) { setToken(null); window.dispatchEvent(new Event("packetops:logout")); }
    throw new ApiError(res.status, err.code ?? "error", err.message ?? res.statusText, err.details);
  }
  return data as T;
}

export const get = <T,>(path: string, query?: Query) => api<T>("GET", path, { query });
export const post = <T,>(path: string, body?: unknown, query?: Query) => api<T>("POST", path, { body, query });
export const patch = <T,>(path: string, body?: unknown) => api<T>("PATCH", path, { body });
export const del = (path: string) => api<void>("DELETE", path);

/** Upload a capture as the raw request body, reporting progress. */
export function uploadCapture(file: File, params: Query, onProgress: (pct: number) => void, signal?: AbortSignal): Promise<UploadResult> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api/v1/captures${qs(params)}`);
    const token = getToken();
    if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("X-Filename", file.name.replace(/[^\x20-\x7e]/g, "_"));
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100)); };
    xhr.onload = () => {
      let data: any;
      try { data = JSON.parse(xhr.responseText); } catch { data = {}; }
      if (xhr.status >= 200 && xhr.status < 300) resolve(data);
      else reject(new ApiError(xhr.status, data?.error?.code ?? "error", data?.error?.message ?? `Upload failed (${xhr.status})`, data?.error?.details));
    };
    xhr.onerror = () => reject(new ApiError(0, "network", "Network error during upload"));
    xhr.onabort = () => reject(new ApiError(0, "aborted", "Upload cancelled"));
    signal?.addEventListener("abort", () => xhr.abort());
    xhr.send(file);
  });
}

/** Authenticated download (reports, exports) without exposing the token in a URL. */
export async function download(path: string, fallbackName: string): Promise<void> {
  const res = await fetch(path, { headers: { Authorization: `Bearer ${getToken() ?? ""}` } });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error.message; } catch { /* not json */ }
    throw new ApiError(res.status, "download_failed", msg);
  }
  const cd = res.headers.get("content-disposition") ?? "";
  const name = /filename="?([^";]+)"?/.exec(cd)?.[1] ?? fallbackName;
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function eventsUrl(captureId: string): string {
  return `/api/v1/captures/${captureId}/events?access_token=${encodeURIComponent(getToken() ?? "")}`;
}

// ------------------------------------------------------------------ types
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export interface Me { user_id: string; email: string; display_name: string; roles: string[]; tenant: { id: string; name: string; slug: string }; permissions: string[] }
export interface CaptureStats { packets: number; bytes: number; duration_s: number; tcp_conversations: number; udp_conversations: number;
  retransmissions: number; resets: number; findings: number; findings_by_severity: Record<Severity, number>; tls_handshakes: number;
  http_requests: number; dns_queries: number; incomplete_handshakes: number }
export interface Capture { id: string; filename: string; sha256: string; size_bytes: number; format: string; status: string; training: boolean;
  created_at: string; description?: string | null; capture_point?: string | null; stats?: CaptureStats; metadata?: any;
  limitations?: { code: string; severity: string; text: string }[]; analysis?: any; duplicate_of?: string | null; mission_id?: string | null; error?: string }
export interface UploadResult { capture: Capture; job: Job | null }
export interface Job { id: string; status: string; progress: number; stage: string; message: string }
export interface Packet { number: number; rel_s: number; ts_ns: number; src: string; dst: string; sport?: number; dport?: number; protocol: string;
  len: number; flow?: string; tcp_flags?: string; analysis?: string | null; expert?: string | null; info: string }
export interface Observation { text: string; frames: number[] }
export interface Finding { id: string; short_id: string; capture_id: string; rule_id: string; rule_version: string; category: string; title: string;
  severity: Severity; confidence: { level: string; score: number; rationale: string }; status: string; summary: string; subject_key: string;
  observations?: Observation[]; assessment?: string; probable_cause?: string; alternatives?: string[];
  verification?: { purpose: string; command: string; where: string }[]; remediation?: { action: string; risk: string }[];
  missing_evidence?: string[]; limitations?: string[]; packets?: { frame: number; ts_ns: number; role: string }[]; flows?: string[];
  timeline?: { ts_ns: number; frame?: number; event: string }[]; metrics?: Record<string, unknown>; f5_relevance?: string | null;
  notes?: { at: string; author_email: string; text: string }[]; assignee?: string | null; training?: boolean; rule?: any }
export interface Flow { id: string; local_id: string; transport: string; client_ip: string; client_port: number; server_ip: string; server_port: number;
  state: string; packets: number; bytes_c2s: number; bytes_s2c: number; duration_ms: number; first_ts_ns: number; issue_score: number;
  finding_ids: string[]; retransmissions?: number; handshake?: any; tls?: any; http?: any[]; f5?: any; timeline?: { ts_ns: number; frame?: number; event: string; dir?: string }[];
  app_protocols?: string[]; rsts?: any[]; max_idle_ms?: number }
export interface Page<T> { items: T[]; total: number }
export interface ConsoleBlock { type: string; level?: string; text?: string; items?: [string, string][]; columns?: string[]; rows?: string[][];
  action?: string; url?: string; label?: string; job_id?: string; capture_id?: string; refs?: any; total?: number }
export interface ConsoleResponse { input: string; blocks: ConsoleBlock[]; capture_id: string | null; prompt?: { command: string; arg: string; message: string; choices: string[] }; error?: boolean; command?: string }
