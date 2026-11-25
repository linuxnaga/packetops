import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { get, getToken, post, setToken, type Me } from "../api/client";

interface AuthState { me: Me | undefined; loading: boolean; can: (perm: string) => boolean; login: (email: string) => Promise<void>; logout: () => void }
const AuthCtx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const [token, setTok] = useState<string | null>(getToken());
  const { data: me, isLoading } = useQuery({ queryKey: ["me", token], queryFn: () => get<Me>("/auth/me"), enabled: !!token, retry: false });
  const logout = useCallback(() => { setToken(null); setTok(null); qc.clear(); }, [qc]);
  useEffect(() => {
    const h = () => { setTok(null); qc.clear(); };
    window.addEventListener("packetops:logout", h);
    return () => window.removeEventListener("packetops:logout", h);
  }, [qc]);
  const login = useCallback(async (email: string) => {
    const r = await post<{ access_token: string }>("/auth/dev-login", { email });
    setToken(r.access_token); setTok(r.access_token);
  }, []);
  const can = useCallback((perm: string) => !!me?.permissions.includes(perm), [me]);
  return <AuthCtx.Provider value={{ me, loading: !!token && isLoading, can, login, logout }}>{children}</AuthCtx.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(AuthCtx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
