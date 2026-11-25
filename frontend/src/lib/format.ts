export const fmtBytes = (n?: number | null): string => {
  if (n === undefined || n === null) return "-";
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
};
export const fmtNum = (n?: number | null): string => (n === undefined || n === null ? "-" : n.toLocaleString());
export const fmtMs = (ms?: number | null): string => (ms === undefined || ms === null ? "-" : ms >= 1000 ? `${(ms / 1000).toFixed(3)} s` : `${ms.toFixed(1)} ms`);
// Nanosecond epochs exceed Number's exact integer range (~256 ns steps), so round to microseconds.
export const fmtTsNs = (ns?: number | null): string => {
  if (!ns) return "-";
  const us = Math.round(ns / 1000);
  const d = new Date(Math.floor(us / 1000));
  const frac = String(us % 1_000_000).padStart(6, "0");
  return `${d.toISOString().slice(0, 19).replace("T", " ")}.${frac}Z`;
};
export const fmtDate = (s?: string | null): string => (s ? new Date(s).toLocaleString() : "-");
export const ep = (ip: string, port?: number | null): string => (port === undefined || port === null ? ip : ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`);
