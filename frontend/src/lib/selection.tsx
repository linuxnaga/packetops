import { createContext, useContext, useState, type ReactNode } from "react";

// The capture the analyst is working on, shared by the standard screens and the Command Deck.
const KEY = "packetops.capture";
interface Sel { captureId: string | null; setCaptureId: (id: string | null) => void }
const Ctx = createContext<Sel | null>(null);

export function SelectionProvider({ children }: { children: ReactNode }) {
  const [captureId, setId] = useState<string | null>(() => { try { return localStorage.getItem(KEY); } catch { return null; } });
  const setCaptureId = (id: string | null) => {
    setId(id);
    try { if (id) localStorage.setItem(KEY, id); else localStorage.removeItem(KEY); } catch { /* ignore */ }
  };
  return <Ctx.Provider value={{ captureId, setCaptureId }}>{children}</Ctx.Provider>;
}
export function useSelection(): Sel {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSelection outside provider");
  return v;
}
