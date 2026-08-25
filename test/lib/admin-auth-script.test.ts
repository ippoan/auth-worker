import { describe, it, expect } from "vitest";
import { renderAdminAuthScript, ADMIN_AUTH_GLOBAL } from "../../src/lib/admin-auth-script";
import { AUTH_COOKIE, LEGACY_ADMIN_COOKIE } from "../../src/lib/cookies";

/** base64url encode (JWT 用) */
function b64url(s: string): string {
  return Buffer.from(s, "utf-8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** exp だけ持つ署名ダミー JWT (門番は署名を見ない) */
function jwt(expOffsetSec: number, marker = "t"): string {
  const exp = Math.floor(Date.now() / 1000) + expOffsetSec;
  return `${b64url(JSON.stringify({ alg: "HS256" }))}.${b64url(JSON.stringify({ exp, marker }))}.sig`;
}

interface Gate {
  readToken(): string | null;
  requireToken(callback: string): string | null;
  rememberToken(token: string | null): void;
  loginUrl(callback: string): string;
}

interface Harness {
  gate: Gate;
  /** location.replace() に渡された URL 群 */
  replaced: string[];
  /** sessionStorage の中身 */
  store: Record<string, string>;
}

/**
 * 生成された門番スクリプトを **そのまま** 偽 browser 環境で実行する。
 * TS で書き直した等価物ではなく、実際に配信される JS を検証する。
 */
function load(opts: {
  cookie?: string;
  session?: string | null;
  sessionThrows?: boolean;
}): Harness {
  const src = renderAdminAuthScript().replace(/^<script>/, "").replace(/<\/script>$/, "");
  const store: Record<string, string> = {};
  if (opts.session) store["auth_token"] = opts.session;
  const sessionStorage = {
    getItem(key: string): string | null {
      if (opts.sessionThrows) throw new Error("SecurityError");
      return key in store ? store[key]! : null;
    },
    setItem(key: string, value: string): void {
      if (opts.sessionThrows) throw new Error("SecurityError");
      store[key] = value;
    },
  };
  const replaced: string[] = [];
  const win: Record<string, unknown> = {
    location: {
      origin: "https://auth.ippoan.org",
      replace: (url: string) => { replaced.push(url); },
    },
  };
  const doc = { cookie: opts.cookie ?? "" };
  // eslint-disable-next-line no-new-func
  new Function("window", "document", "sessionStorage", src)(win, doc, sessionStorage);
  return { gate: win[ADMIN_AUTH_GLOBAL] as Gate, replaced, store };
}

describe("renderAdminAuthScript — 生成物", () => {
  it("cookie 名は cookies.ts の定数から埋め込まれる (ページ JS にハードコードしない)", () => {
    const html = renderAdminAuthScript();
    expect(html).toContain(JSON.stringify(AUTH_COOKIE));
    expect(html).toContain(JSON.stringify(LEGACY_ADMIN_COOKIE));
  });

  it("window.__adminAuth を公開する", () => {
    const { gate } = load({});
    expect(typeof gate.readToken).toBe("function");
    expect(typeof gate.requireToken).toBe("function");
    expect(typeof gate.rememberToken).toBe("function");
    expect(typeof gate.loginUrl).toBe("function");
  });
});

describe("readToken — cookie / sessionStorage の 4 分岐", () => {
  it("cookie のみ → cookie の token を返す (#474 の本命: fragment 無し cookie 配送)", () => {
    const token = jwt(3600, "cookie");
    const { gate } = load({ cookie: `${AUTH_COOKIE}=${token}` });
    expect(gate.readToken()).toBe(token);
  });

  it("sessionStorage のみ → sessionStorage の token を返す (後方互換)", () => {
    const token = jwt(3600, "session");
    const { gate } = load({ session: token });
    expect(gate.readToken()).toBe(token);
  });

  it("両方あり → cookie を優先する", () => {
    const cookieToken = jwt(3600, "cookie");
    const sessionToken = jwt(3600, "session");
    const { gate } = load({ cookie: `${AUTH_COOKIE}=${cookieToken}`, session: sessionToken });
    expect(gate.readToken()).toBe(cookieToken);
  });

  it("どちらも無い → null", () => {
    const { gate } = load({});
    expect(gate.readToken()).toBeNull();
  });
});

describe("readToken — cookie の細部", () => {
  it("同名 cookie が複数届いても期限切れでない方を選ぶ (#387 shadowing)", () => {
    const stale = jwt(-60, "stale");
    const fresh = jwt(3600, "fresh");
    const { gate } = load({ cookie: `${AUTH_COOKIE}=${stale}; ${AUTH_COOKIE}=${fresh}` });
    expect(gate.readToken()).toBe(fresh);
  });

  it("期限切れ cookie しか無ければ「無い」扱い (再ログインで新しい cookie が載る)", () => {
    const { gate } = load({ cookie: `${AUTH_COOKIE}=${jwt(-60)}` });
    expect(gate.readToken()).toBeNull();
  });

  it("期限切れ sessionStorage は使わない", () => {
    const { gate } = load({ session: jwt(-60) });
    expect(gate.readToken()).toBeNull();
  });

  it("名前が後方一致する別 cookie を誤って拾わない", () => {
    const { gate } = load({ cookie: `x_${AUTH_COOKIE}=${jwt(3600)}` });
    expect(gate.readToken()).toBeNull();
  });

  it("legacy cookie (sso_admin_token) も後方互換で読む", () => {
    const token = jwt(3600, "legacy");
    const { gate } = load({ cookie: `${LEGACY_ADMIN_COOKIE}=${token}` });
    expect(gate.readToken()).toBe(token);
  });

  it("legacy より logi_auth_token を優先する", () => {
    const primary = jwt(3600, "primary");
    const legacy = jwt(3600, "legacy");
    const { gate } = load({ cookie: `${LEGACY_ADMIN_COOKIE}=${legacy}; ${AUTH_COOKIE}=${primary}` });
    expect(gate.readToken()).toBe(primary);
  });

  it("percent-encode された値は decode する", () => {
    const token = jwt(3600, "encoded");
    const { gate } = load({ cookie: `${AUTH_COOKIE}=${encodeURIComponent(token)}%` });
    // 末尾に不正な % を付けても decode に失敗して raw のまま扱う (throw しない)
    expect(gate.readToken()).toBe(`${token}%`);
  });

  it("空値 cookie / '=' の無い欠片は無視する", () => {
    const token = jwt(3600, "ok");
    const { gate } = load({ cookie: `${AUTH_COOKIE}=; junk; ${AUTH_COOKIE}=${token}` });
    expect(gate.readToken()).toBe(token);
  });

  it("exp を読めない token (JWT でない / payload 不正) は期限不明として使う", () => {
    const { gate: a } = load({ cookie: `${AUTH_COOKIE}=opaque-token` });
    expect(a.readToken()).toBe("opaque-token");
    const noExp = `${b64url(JSON.stringify({ alg: "HS256" }))}.${b64url(JSON.stringify({ sub: "u" }))}.sig`;
    const { gate: b } = load({ cookie: `${AUTH_COOKIE}=${noExp}` });
    expect(b.readToken()).toBe(noExp);
  });

  it("sessionStorage が使えない環境 (private mode 等) でも cookie で動く", () => {
    const token = jwt(3600, "cookie");
    const { gate } = load({ cookie: `${AUTH_COOKIE}=${token}`, sessionThrows: true });
    expect(gate.readToken()).toBe(token);
    expect(() => gate.rememberToken(token)).not.toThrow();
  });

  it("cookie が空文字でも落ちない", () => {
    const { gate } = load({ cookie: "" });
    expect(gate.readToken()).toBeNull();
  });
});

describe("requireToken", () => {
  it("cookie から取れたら sessionStorage にミラーして返す (redirect しない)", () => {
    const token = jwt(3600, "cookie");
    const h = load({ cookie: `${AUTH_COOKIE}=${token}` });
    expect(h.gate.requireToken("/admin/notify/callback")).toBe(token);
    expect(h.store["auth_token"]).toBe(token);
    expect(h.replaced).toEqual([]);
  });

  it("token が無ければ /login?redirect_uri=<callback> へ replace して null", () => {
    const h = load({});
    expect(h.gate.requireToken("/admin/notify/callback")).toBeNull();
    expect(h.replaced).toEqual([
      "/login?redirect_uri=" + encodeURIComponent("https://auth.ippoan.org/admin/notify/callback"),
    ]);
  });

  it("絶対 URL の callback はそのまま redirect_uri に使う", () => {
    const h = load({});
    h.gate.requireToken("https://auth.ippoan.org/admin/line-users?from=x");
    expect(h.replaced[0]).toBe(
      "/login?redirect_uri=" + encodeURIComponent("https://auth.ippoan.org/admin/line-users?from=x"),
    );
  });

  it("rememberToken(null) は何もしない", () => {
    const h = load({});
    h.gate.rememberToken(null);
    expect(h.store["auth_token"]).toBeUndefined();
  });

  it("loginUrl は相対 path を origin 付きに正規化する", () => {
    const { gate } = load({});
    expect(gate.loginUrl("/admin/sso/callback")).toBe(
      "/login?redirect_uri=" + encodeURIComponent("https://auth.ippoan.org/admin/sso/callback"),
    );
  });
});
