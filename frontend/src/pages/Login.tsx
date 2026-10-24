import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Activity } from "lucide-react";
import { get } from "../api/client";
import { ErrorBox } from "../components/ui";
import { useAuth } from "../lib/auth";

const DEV_USERS = ["analyst@acme.example", "investigator@acme.example", "admin@acme.example", "auditor@acme.example", "read-only@acme.example", "analyst@globex.example"];

export default function Login() {
  const { login } = useAuth();
  const [email, setEmail] = useState(DEV_USERS[0]);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const { data: cfg } = useQuery({ queryKey: ["auth-config"], queryFn: () => get<{ mode: string; oidc_issuer: string | null; oidc_client_id: string | null }>("/auth/config") });
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(null); setBusy(true);
    try { await login(email); } catch (x) { setErr(x); } finally { setBusy(false); }
  };
  return (
    <div className="flex min-h-full items-center justify-center p-4">
      <div className="card w-full max-w-sm p-6">
        <div className="mb-4 flex items-center gap-2"><Activity className="h-6 w-6 text-accent" aria-hidden /><div><h1 className="text-lg font-bold">F5 PacketOps</h1><p className="text-xs text-muted">PCAP forensics & network troubleshooting</p></div></div>
        {cfg?.mode === "oidc" ? (
          <div className="space-y-2 text-sm">
            <p>This deployment uses single sign-on ({cfg.oidc_issuer}).</p>
            <p className="text-muted">Sign in through your identity provider; the API accepts its access tokens. The browser sign-in flow is configured by your administrator.</p>
          </div>
        ) : (
          <form onSubmit={submit} className="space-y-3">
            <div className="rounded-md border border-warn/40 bg-warn/10 p-2 text-xs text-warn">Development sign-in. Seeded users only; disabled in production.</div>
            <label className="block text-sm"><span className="label">User</span>
              <input className="input mt-1" list="dev-users" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required />
              <datalist id="dev-users">{DEV_USERS.map((u) => <option key={u} value={u} />)}</datalist>
            </label>
            {err ? <ErrorBox error={err} /> : null}
            <button className="btn-primary w-full justify-center" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
          </form>
        )}
      </div>
    </div>
  );
}
