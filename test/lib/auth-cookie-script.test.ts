import { describe, it, expect } from "vitest";
import { renderAuthCookieScript, AUTH_COOKIE_GLOBAL, AUTH_COOKIE } from "../../src/lib/auth-cookie-script";

/** base64url encode (JWT 用) */
function b64url(s: string): string {
  return Buffer.from(s, "utf-8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** exp を持つダミー JWT (snippet は署名を見ない) */
function jwt(expOffsetSec: number, marker = "t"): string {
  const exp = Math.floor(Date.now() / 1000) + expOffsetSec;
  return `${b64url(JSON.stringify({ alg: "HS256" }))}.${b64url(JSON.stringify({ exp, marker }))}.sig`;
}

interface AuthCookieApi {
  decodeJwtPayload(token: string): Record<string, unknown> | null;
  cookieValues(name: string): string[];
  findValidToken(names: string[], nowSec: number): string | null;
  isValidToken(token: string, nowSec: number): boolean;
}

/**
 * 生成された snippet を **そのまま** 偽 browser 環境で実行する。
 * TS で書き直した等価物ではなく、実際に配信される JS を検証する。
 */
function load(cookie: string): AuthCookieApi {
  const src = renderAuthCookieScript();
  const win: Record<string, unknown> = {};
  const doc = { cookie };
  // eslint-disable-next-line no-new-func
  new Function("window", "document", src)(win, doc);
  return win[AUTH_COOKIE_GLOBAL] as AuthCookieApi;
}

describe("renderAuthCookieScript — 生成物", () => {
  it(`window.${AUTH_COOKIE_GLOBAL} を公開する`, () => {
    const api = load("");
    expect(typeof api.decodeJwtPayload).toBe("function");
    expect(typeof api.cookieValues).toBe("function");
    expect(typeof api.findValidToken).toBe("function");
    expect(typeof api.isValidToken).toBe("function");
  });

  it("cookie 名の既定を埋め込まない (呼び出し側が名前を渡す設計)", () => {
    const html = renderAuthCookieScript();
    expect(html).not.toContain(JSON.stringify(AUTH_COOKIE));
  });

  it("<script> タグを含まない (呼び出し側の <script> に埋め込む断片)", () => {
    const html = renderAuthCookieScript();
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("</script>");
  });
});

describe("decodeJwtPayload", () => {
  it("3 分割の JWT を decode する", () => {
    const token = jwt(3600, "ok");
    const { marker } = load("").decodeJwtPayload(token) as { marker: string };
    expect(marker).toBe("ok");
  });

  it("base64url の -/_ と多バイト claim を含む payload を throw せず decode する (Refs #529)", () => {
    // "大石 太郎" を含む payload → 標準 base64 化すると +/=/など、base64url 化すると -/_ を含む
    const payload = { name: "大石 太郎", tenant_id: "00000000-1111-4111-8111-111111111111", exp: 9999999999 };
    const token = `h.${b64url(JSON.stringify(payload))}.sig`;
    const decoded = load("").decodeJwtPayload(token) as { name?: string; tenant_id?: string; exp?: number };
    expect(decoded.name).toBe("大石 太郎");
    expect(decoded.tenant_id).toBe(payload.tenant_id);
    expect(decoded.exp).toBe(9999999999);
  });

  it("3 分割でない token は null", () => {
    expect(load("").decodeJwtPayload("not-a-jwt")).toBeNull();
    expect(load("").decodeJwtPayload("a.b")).toBeNull();
  });

  it("payload が JSON として壊れていれば null (throw しない)", () => {
    const token = `h.${b64url("not-json")}.sig`;
    expect(load("").decodeJwtPayload(token)).toBeNull();
  });
});

describe("cookieValues", () => {
  it("同名 cookie を全て返す (#387 shadowing 対策)", () => {
    const api = load(`${AUTH_COOKIE}=v1; ${AUTH_COOKIE}=v2`);
    expect(api.cookieValues(AUTH_COOKIE)).toEqual(["v1", "v2"]);
  });

  it("percent-encode された値は decode する", () => {
    const raw = "a b/c";
    const api = load(`${AUTH_COOKIE}=${encodeURIComponent(raw)}`);
    expect(api.cookieValues(AUTH_COOKIE)).toEqual([raw]);
  });

  it("decode に失敗する不正な % は raw のまま使う (throw しない)", () => {
    const api = load(`${AUTH_COOKIE}=abc%`);
    expect(api.cookieValues(AUTH_COOKIE)).toEqual(["abc%"]);
  });

  it("空値 cookie / '=' の無い欠片は無視する", () => {
    const api = load(`${AUTH_COOKIE}=; junk; ${AUTH_COOKIE}=v`);
    expect(api.cookieValues(AUTH_COOKIE)).toEqual(["v"]);
  });

  it("名前が後方一致する別 cookie は拾わない", () => {
    const api = load(`x_${AUTH_COOKIE}=v`);
    expect(api.cookieValues(AUTH_COOKIE)).toEqual([]);
  });

  it("cookie が空文字なら空配列", () => {
    expect(load("").cookieValues(AUTH_COOKIE)).toEqual([]);
  });
});

describe("isValidToken", () => {
  it("exp が未来なら true", () => {
    expect(load("").isValidToken(jwt(3600), Math.floor(Date.now() / 1000))).toBe(true);
  });

  it("exp が過去なら false", () => {
    expect(load("").isValidToken(jwt(-60), Math.floor(Date.now() / 1000))).toBe(false);
  });

  it("exp を読めない (JWT でない / payload に exp が無い) token は false", () => {
    const noExp = `${b64url(JSON.stringify({ alg: "HS256" }))}.${b64url(JSON.stringify({ sub: "u" }))}.sig`;
    const now = Math.floor(Date.now() / 1000);
    expect(load("").isValidToken("opaque-token", now)).toBe(false);
    expect(load("").isValidToken(noExp, now)).toBe(false);
  });
});

describe("findValidToken", () => {
  const now = () => Math.floor(Date.now() / 1000);

  it("shadowing: 期限切れが先頭でも後続の有効な値を採る (#387/#529)", () => {
    const stale = jwt(-60, "stale");
    const fresh = jwt(3600, "fresh");
    const api = load(`${AUTH_COOKIE}=${stale}; ${AUTH_COOKIE}=${fresh}`);
    expect(api.findValidToken([AUTH_COOKIE], now())).toBe(fresh);
  });

  it("先頭候補が壊れていても後続の有効な値を採る", () => {
    const broken = "not-a-jwt";
    const fresh = jwt(3600, "fresh");
    const api = load(`${AUTH_COOKIE}=${broken}; ${AUTH_COOKIE}=${fresh}`);
    expect(api.findValidToken([AUTH_COOKIE], now())).toBe(fresh);
  });

  it("names の順で探す (先に渡した名前を優先)", () => {
    const legacy = "legacy_cookie";
    const primaryToken = jwt(3600, "primary");
    const legacyToken = jwt(3600, "legacy");
    const api = load(`${legacy}=${legacyToken}; ${AUTH_COOKIE}=${primaryToken}`);
    expect(api.findValidToken([AUTH_COOKIE, legacy], now())).toBe(primaryToken);
    expect(api.findValidToken([legacy, AUTH_COOKIE], now())).toBe(legacyToken);
  });

  it("exp が無ければ候補として使わない", () => {
    const noExp = `${b64url(JSON.stringify({ alg: "HS256" }))}.${b64url(JSON.stringify({ sub: "u" }))}.sig`;
    const api = load(`${AUTH_COOKIE}=${noExp}`);
    expect(api.findValidToken([AUTH_COOKIE], now())).toBeNull();
  });

  it("cookie が空なら null", () => {
    const api = load("");
    expect(api.findValidToken([AUTH_COOKIE], now())).toBeNull();
  });

  it("全候補が期限切れ/不正なら null", () => {
    const api = load(`${AUTH_COOKIE}=${jwt(-60)}`);
    expect(api.findValidToken([AUTH_COOKIE], now())).toBeNull();
  });
});
