import { ApiError, api, setToken } from "../api/client";

describe("api client", () => {
  afterEach(() => { vi.restoreAllMocks(); setToken(null); });
  it("sends the bearer token and parses JSON", async () => {
    setToken("tok123");
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ ok: 1 }), { status: 200 }));
    await expect(api("GET", "/captures", { query: { limit: 5, q: "" } })).resolves.toEqual({ ok: 1 });
    const [url, init] = f.mock.calls[0];
    expect(url).toBe("/api/v1/captures?limit=5");
    expect((init!.headers as Record<string, string>).Authorization).toBe("Bearer tok123");
  });
  it("raises ApiError with the server's error code and clears the token on 401", async () => {
    setToken("expired");
    const onLogout = vi.fn();
    window.addEventListener("packetops:logout", onLogout);
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ error: { code: "unauthorized", message: "Token expired" } }), { status: 401 }));
    const err = (await api("GET", "/auth/me").catch((e) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.code).toBe("unauthorized");
    expect(localStorage.getItem("packetops.token")).toBeNull();
    expect(onLogout).toHaveBeenCalled();
  });
});
