import { describe, it, expect } from "vitest";
import { handleLogoutReturn } from "../../src/handlers/logout-return";

const at = (to?: string) =>
  handleLogoutReturn(
    new Request(
      to === undefined
        ? "https://auth.test.example/logout/return"
        : `https://auth.test.example/logout/return?to=${encodeURIComponent(to)}`,
    ),
  );

describe("handleLogoutReturn", () => {
  // Access は「知っているホスト」にしか returnTo を戻さないので、/logout は
  // returnTo をここ (auth-worker 自身) に向ける。最終先へはこの 302 で送り出す。
  it("302s to a same-parent-domain https target", () => {
    const res = at("https://alc.test.example/login");
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("https://alc.test.example/login");
  });

  it("keeps the target's query string intact", () => {
    expect(at("https://dtako.test.example/?lw_callback=1").headers.get("Location")).toBe(
      "https://dtako.test.example/?lw_callback=1",
    );
  });

  it("falls back to the auth origin's /login when ?to= is missing", () => {
    expect(at().headers.get("Location")).toBe("https://auth.test.example/login");
  });

  // open redirect 防止 — Access からの戻りは誰でも踏ませられる URL なので、
  // 共有 cookie の届かないホストへは絶対に送らない。
  it("refuses a foreign host, a non-https target and garbage", () => {
    expect(at("https://evil.example.com/").headers.get("Location")).toBe("/login");
    expect(at("http://auth.test.example/login").headers.get("Location")).toBe("/login");
    expect(at("javascript:alert(1)").headers.get("Location")).toBe("/login");
  });

  it("is never cached", () => {
    expect(at("https://alc.test.example/login").headers.get("Cache-Control")).toBe("no-store");
  });
});
