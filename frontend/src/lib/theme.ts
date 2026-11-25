export type Theme = "system" | "light" | "dark";
const KEY = "packetops.theme";
export function loadTheme(): Theme { try { return (localStorage.getItem(KEY) as Theme) || "system"; } catch { return "system"; } }
export function applyTheme(t: Theme): void {
  const root = document.documentElement;
  if (t === "system") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", t);
  try { localStorage.setItem(KEY, t); } catch { /* ignore */ }
}
export function isDark(): boolean {
  const attr = document.documentElement.getAttribute("data-theme");
  if (attr) return attr === "dark";
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
}
