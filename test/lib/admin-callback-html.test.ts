import { describe, it, expect } from "vitest";
import { renderAdminCallbackPage } from "../../src/lib/admin-callback-html";
import { AUTH_COOKIE } from "../../src/lib/cookies";

function b64url(s: string): string {
  return Buffer.from(s, "utf-8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function jwt(marker: string): string {
  const exp = Math.floor(Date.now() / 1000) + 3600;
  return `${b64url(JSON.stringify({ alg: "HS256" }))}.${b64url(JSON.stringify({ exp, marker }))}.sig`;
}

/** callback ページの script を順に偽 browser 環境で実行する */
function run(targetPath: string, opts: { hash?: string; cookie?: string; session?: string }) {
  const html = renderAdminCallbackPage(targetPath);
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]!);
  expect(scripts.length).toBe(2); // 共通門番 + callback 本体

  const store: Record<string, string> = {};
  if (opts.session) store["auth_token"] = opts.session;
  const sessionStorage = {
    getItem: (k: string): string | null => (k in store ? store[k]! : null),
    setItem: (k: string, v: string): void => { store[k] = v; },
  };
  const replaced: string[] = [];
  const win: Record<string, unknown> = {
    location: {
      origin: "https://auth.ippoan.org",
      hash: opts.hash ?? "",
      replace: (url: string) => { replaced.push(url); },
    },
  };
  const doc = { cookie: opts.cookie ?? "" };
  for (const src of scripts) {
    // eslint-disable-next-line no-new-func
    new Function("window", "document", "sessionStorage", src)(win, doc, sessionStorage);
  }
  return { store, replaced };
}

describe("renderAdminCallbackPage", () => {
  it("fragment の token を sessionStorage に保存して戻す (従来経路)", () => {
    const token = jwt("fragment");
    const r = run("/admin/notify", { hash: `#token=${token}&expires_at=1` });
    expect(r.store["auth_token"]).toBe(token);
    expect(r.replaced).toEqual(["/admin/notify"]);
  });

  it("#474: fragment が無くても cookie があれば正常着地として扱う", () => {
    const token = jwt("cookie");
    const r = run("/admin/notify", { cookie: `${AUTH_COOKIE}=${token}` });
    expect(r.store["auth_token"]).toBe(token);
    expect(r.replaced).toEqual(["/admin/notify"]);
  });

  it("fragment も cookie も無ければ token を保存せず元ページへ戻す (門番が /login へ送る)", () => {
    const r = run("/admin/notify", {});
    expect(r.store["auth_token"]).toBeUndefined();
    expect(r.replaced).toEqual(["/admin/notify"]);
  });

  it("hash に token= があっても値が空なら cookie にフォールバックする", () => {
    const token = jwt("cookie");
    const r = run("/admin/users", { hash: "#token=", cookie: `${AUTH_COOKIE}=${token}` });
    expect(r.store["auth_token"]).toBe(token);
    expect(r.replaced).toEqual(["/admin/users"]);
  });

  it("target path を JSON 埋め込みする (script injection 防止)", () => {
    const html = renderAdminCallbackPage('/admin/x";alert(1);//');
    expect(html).toContain(JSON.stringify('/admin/x";alert(1);//'));
  });
});
