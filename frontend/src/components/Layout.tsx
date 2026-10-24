import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Activity, BookOpen, FileText, Gauge, LogOut, Moon, Network, Search, ShieldAlert, Sun, Terminal, Trophy, Server, ScrollText, Menu } from "lucide-react";
import { get, type Capture, type Page } from "../api/client";
import { useAuth } from "../lib/auth";
import { useSelection } from "../lib/selection";
import { applyTheme, loadTheme, type Theme } from "../lib/theme";

const NAV = [
  { to: "/", label: "Overview", icon: Gauge, end: true },
  { to: "/workbench", label: "PCAP Workbench", icon: Search },
  { to: "/flows", label: "Flow Explorer", icon: Network },
  { to: "/findings", label: "Findings", icon: ShieldAlert },
  { to: "/console", label: "Command Deck", icon: Terminal },
  { to: "/missions", label: "Training", icon: Trophy },
  { to: "/f5", label: "BIG-IP", icon: Server },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/audit", label: "Audit log", icon: ScrollText, perm: "audit:read" },
  { to: "/help", label: "Rules & help", icon: BookOpen },
];

export function CapturePicker() {
  const { captureId, setCaptureId } = useSelection();
  const { data } = useQuery({ queryKey: ["captures", "picker"], queryFn: () => get<Page<Capture>>("/captures", { limit: 50 }) });
  return (
    <label className="flex min-w-0 items-center gap-2 text-sm">
      <span className="hidden text-muted sm:inline">Capture</span>
      <select className="input max-w-[22rem] py-1" value={captureId ?? ""} onChange={(e) => setCaptureId(e.target.value || null)} aria-label="Selected capture">
        <option value="">— select a capture —</option>
        {data?.items.map((c) => (
          <option key={c.id} value={c.id}>{c.training ? "[training] " : ""}{c.filename} · {c.status}</option>
        ))}
      </select>
    </label>
  );
}

export function Layout() {
  const { me, can, logout } = useAuth();
  const [theme, setTheme] = useState<Theme>(loadTheme());
  const [open, setOpen] = useState(false);
  const nav = useNavigate();
  const { data: progress } = useQuery({ queryKey: ["progress"], queryFn: () => get<any>("/me/progress"), enabled: !!me });
  const cycle = () => { const next: Theme = theme === "dark" ? "light" : "dark"; setTheme(next); applyTheme(next); };
  return (
    <div className="flex h-full">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:m-2 focus:rounded focus:bg-panel focus:p-2">Skip to content</a>
      <aside className={`${open ? "fixed inset-0 z-40 flex" : "hidden"} w-60 shrink-0 flex-col border-r border-line bg-panel md:static md:flex`}>
        <div className="flex items-center gap-2 border-b border-line px-4 py-3">
          <Activity className="h-5 w-5 text-accent" aria-hidden />
          <div><div className="text-sm font-bold leading-tight">F5 PacketOps</div><div className="text-[11px] text-muted">PCAP forensics</div></div>
        </div>
        <nav className="flex-1 overflow-y-auto p-2" aria-label="Main">
          {NAV.filter((n) => !n.perm || can(n.perm)).map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} onClick={() => setOpen(false)}
              className={({ isActive }) => `flex items-center gap-2 rounded-md px-3 py-2 text-sm ${isActive ? "bg-accent/10 font-medium text-accent" : "text-fg hover:bg-panel2"}`}>
              <Icon className="h-4 w-4" aria-hidden />{label}
            </NavLink>
          ))}
        </nav>
        {progress && (
          <button className="m-2 rounded-md border border-line p-2 text-left text-xs hover:bg-panel2" onClick={() => nav("/missions")}>
            <div className="font-medium">Lv {progress.level} · {progress.title}</div>
            <div className="mt-1 h-1.5 overflow-hidden rounded bg-panel2"><div className="h-full bg-accent" style={{ width: `${progress.next_level_xp ? Math.min(100, ((progress.xp - progress.xp_floor) / (progress.next_level_xp - progress.xp_floor)) * 100) : 100}%` }} /></div>
            <div className="mt-1 text-muted">{progress.xp} XP</div>
          </button>
        )}
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 border-b border-line bg-panel px-4 py-2">
          <button className="btn md:hidden" onClick={() => setOpen(!open)} aria-label="Toggle navigation"><Menu className="h-4 w-4" /></button>
          <CapturePicker />
          <div className="ml-auto flex items-center gap-2">
            <button className="btn" onClick={cycle} aria-label="Toggle colour theme">{theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}</button>
            <div className="hidden text-right text-xs sm:block"><div className="font-medium">{me?.display_name}</div><div className="text-muted">{me?.tenant.name} · {me?.roles.join(", ")}</div></div>
            <button className="btn" onClick={logout} aria-label="Sign out"><LogOut className="h-4 w-4" /></button>
          </div>
        </header>
        <main id="main" className="min-h-0 flex-1 overflow-auto p-4"><Outlet /></main>
      </div>
    </div>
  );
}
