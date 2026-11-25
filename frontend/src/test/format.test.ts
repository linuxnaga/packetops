import { ep, fmtBytes, fmtMs, fmtTsNs } from "../lib/format";

describe("format helpers", () => {
  it("formats bytes with binary units", () => {
    expect(fmtBytes(0)).toBe("0 B");
    expect(fmtBytes(1536)).toBe("1.5 KiB");
    expect(fmtBytes(undefined)).toBe("-");
  });
  it("formats durations", () => {
    expect(fmtMs(12.34)).toBe("12.3 ms");
    expect(fmtMs(2500)).toBe("2.500 s");
  });
  it("brackets IPv6 endpoints", () => {
    expect(ep("10.0.0.1", 443)).toBe("10.0.0.1:443");
    expect(ep("2001:db8::1", 443)).toBe("[2001:db8::1]:443");
  });
  it("keeps microsecond precision of capture timestamps", () => {
    expect(fmtTsNs(1768471200045300000)).toBe("2026-01-15 10:00:00.045300Z");
  });
});
