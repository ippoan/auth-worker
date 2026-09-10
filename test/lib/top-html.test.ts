import { describe, it, expect, afterAll } from "vitest";
import { renderTopPage, renderStagingFooter } from "../../src/lib/top-html";

/**
 * 埋め込み `<script>` から `decodeJwtPayload` (Refs #529) の本体だけを取り出して
 * 実行可能な関数にする。renderTopPage は DOM 前提の巨大な inline script を返す
 * ので、jsdom を足さずにこの純粋関数だけを実機の atob() で検証する。
 */
function extractDecodeJwtPayload(html: string): (token: string) => unknown {
  const m = /function decodeJwtPayload\(token\) \{[\s\S]*?\n {4}\}/.exec(html);
  if (!m) throw new Error("decodeJwtPayload not found in rendered HTML");
  // eslint-disable-next-line no-new-func
  return new Function(`return (${m[0]});`)() as (token: string) => unknown;
}

/**
 * 複数の named function を辿って抽出し、まとめて実行可能にする (互いに呼び合う
 * decodeJwtPayload / getAllCookies / findValidAuthCookie を一括で eval する用途)。
 * `document` はテスト側でグローバルに差し込む。
 */
function extractClientFunctions<T extends Record<string, (...args: never[]) => unknown>>(
  html: string,
  names: (keyof T & string)[],
): T {
  const sources = names.map((name) => {
    const re = new RegExp(`function ${name}\\([^)]*\\) \\{[\\s\\S]*?\\n {4}\\}`);
    const m = re.exec(html);
    if (!m) throw new Error(`${name} not found in rendered HTML`);
    return m[0];
  });
  // findValidAuthCookie 等が参照する module-level const (AUTH_COOKIE 等) も
  // 一緒に extract して eval scope に持ち込む。
  const constMatch = /const AUTH_COOKIE = [^;]+;/.exec(html);
  const consts = constMatch ? constMatch[0] : "";
  const body = `${consts}\n${sources.join("\n")}\nreturn { ${names.join(", ")} };`;
  // eslint-disable-next-line no-new-func
  return new Function(body)() as T;
}

/** JSON payload を base64url encode して <header>.<payload>.<sig> 形の JWT にする。 */
function fakeJwt(payload: Record<string, unknown>): string {
  const b64url = Buffer.from(JSON.stringify(payload), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `h.${b64url}.sig`;
}

describe("renderTopPage", () => {
  it("returns a string", () => {
    const result = renderTopPage([], "https://auth.example.com");
    expect(typeof result).toBe("string");
  });

  it("contains DOCTYPE html", () => {
    const result = renderTopPage([], "https://auth.example.com");
    expect(result).toContain("<!DOCTYPE html>");
  });

  it("handles empty apps array", () => {
    const result = renderTopPage([], "https://auth.example.com");
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
  });

  it("includes apps data in output", () => {
    const apps = [
      { name: "Test App", url: "https://app.example.com", icon: "T", description: "A test app" },
    ];
    const result = renderTopPage(apps, "https://auth.example.com");
    expect(result).toContain("Test App");
  });

  it("includes authWorkerOrigin", () => {
    const result = renderTopPage([], "https://auth.my-domain.com");
    expect(result).toContain("auth.my-domain.com");
  });

  describe("staging footer", () => {
    it("omits the staging footer when workerEnv is prod", () => {
      const result = renderTopPage([], "https://auth.example.com", {
        workerEnv: "prod",
        alcApiOrigin: "https://alc.example.com",
        tenantId: "tid-1",
      });
      expect(result).not.toContain("staging-footer");
    });

    it("omits the footer when alcApiOrigin is missing", () => {
      const result = renderTopPage([], "https://auth.example.com", {
        workerEnv: "staging",
      });
      expect(result).not.toContain("staging-footer");
    });

    it("renders the footer when workerEnv is staging and alcApiOrigin is set", () => {
      const result = renderTopPage([], "https://auth.example.com", {
        workerEnv: "staging",
        alcApiOrigin: "https://alc-staging.example.com",
        tenantId: "tid-1",
      });
      expect(result).toContain("staging-footer");
      expect(result).toContain("STAGING");
    });

    it("defaults to no footer when stagingOpts is omitted", () => {
      const result = renderTopPage([], "https://auth.example.com");
      expect(result).not.toContain("staging-footer");
    });
  });

  describe("client-side decodeJwtPayload (Refs #529)", () => {
    // signJwt (jwt.ts) が吐く実運用の AppClaims 相当。name に日本語 (多バイト UTF-8)
    // が乗ると base64url encode が `-`/`_` を含みやすく、旧実装 (atob 直呼び) は
    // InvalidCharacterError で例外 → /top ↔ /login 無限ループになっていた
    // (2026-09-10 本番 wrangler tail で実測)。この token は実際に `-` を含む。
    const REALISTIC_PAYLOAD_B64URL =
      "eyJzdWIiOiJ1MCIsImVtYWlsIjoidGFybzBAZXhhbXBsZS5jb20iLCJuYW1lIjoi5aSn55-zIOWkqumDjiIsInRlbmFudF9pZCI6IjAwMDAwMDAwLTExMTEtNDExMS04MTExLTExMTExMTExMTExMSIsInJvbGUiOiJtZW1iZXIiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OX0";

    it("has a `-` in the payload segment (sanity check for the fixture below)", () => {
      expect(REALISTIC_PAYLOAD_B64URL).toContain("-");
    });

    it("raw atob() throws on this payload (documents the bug this guards against)", () => {
      expect(() => atob(REALISTIC_PAYLOAD_B64URL)).toThrow();
    });

    it("decodeJwtPayload decodes a base64url payload containing `-`/`_` without throwing", () => {
      const html = renderTopPage([], "https://auth.example.com");
      const decodeJwtPayload = extractDecodeJwtPayload(html);
      const token = `header.${REALISTIC_PAYLOAD_B64URL}.sig`;
      const payload = decodeJwtPayload(token) as { name?: string; tenant_id?: string; exp?: number };
      expect(payload).not.toBeNull();
      expect(payload.name).toBe("大石 太郎");
      expect(payload.tenant_id).toBe("00000000-1111-4111-8111-111111111111");
      expect(payload.exp).toBe(9999999999);
    });

    it("returns null (not throw) for a malformed token", () => {
      const html = renderTopPage([], "https://auth.example.com");
      const decodeJwtPayload = extractDecodeJwtPayload(html);
      expect(decodeJwtPayload("not-a-jwt")).toBeNull();
    });
  });

  describe("client-side findValidAuthCookie cookie shadowing (Refs #529 follow-up)", () => {
    // server 側 getAuthCookies (cookies.ts) は同名 cookie を全部 verify するが、
    // client の旧実装 getCookie() は document.cookie の先頭一致しか見ていなかった。
    // host-only の古い/無効な cookie が Domain 付きの新しい cookie より先に並ぶと、
    // server は 200 を返す (payloadValid:true) のに client だけ「未ログイン」と
    // 誤判定して /login に戻り続けるループになっていた (2026-09-10 本番実測)。
    afterAll(() => {
      // @ts-expect-error test-only global stub
      delete globalThis.document;
    });

    it("skips a stale/expired cookie candidate and picks a later valid one", () => {
      const html = renderTopPage([], "https://auth.example.com");
      const fns = extractClientFunctions<{
        decodeJwtPayload: (token: string) => unknown;
        getAllCookies: (name: string) => string[];
        findValidAuthCookie: () => string | null;
      }>(html, ["decodeJwtPayload", "getAllCookies", "findValidAuthCookie"]);

      const now = Math.floor(Date.now() / 1000);
      const staleToken = fakeJwt({ exp: now - 3600, org: "stale" }); // 期限切れ (古い host-only cookie 相当)
      const validToken = fakeJwt({ exp: now + 3600, org: "fresh" }); // 有効 (Domain 付きの新しい cookie 相当)

      // @ts-expect-error test-only global stub
      globalThis.document = { cookie: `logi_auth_token=${staleToken}; logi_auth_token=${validToken}` };

      expect(fns.getAllCookies("logi_auth_token")).toEqual([staleToken, validToken]);
      expect(fns.findValidAuthCookie()).toBe(validToken);
    });

    it("returns null when every candidate is invalid/expired", () => {
      const html = renderTopPage([], "https://auth.example.com");
      const fns = extractClientFunctions<{
        decodeJwtPayload: (token: string) => unknown;
        getAllCookies: (name: string) => string[];
        findValidAuthCookie: () => string | null;
      }>(html, ["decodeJwtPayload", "getAllCookies", "findValidAuthCookie"]);

      const now = Math.floor(Date.now() / 1000);
      const staleToken = fakeJwt({ exp: now - 3600, org: "stale" });

      // @ts-expect-error test-only global stub
      globalThis.document = { cookie: `logi_auth_token=${staleToken}` };

      expect(fns.findValidAuthCookie()).toBeNull();
    });
  });

  describe("client-side getValidToken sessionStorage fallback (Refs #531 follow-up)", () => {
    // sessionStorage はタブを閉じるまで残る。getValidToken() が「sessionStorage に
    // 何か値があれば cookie を見ずにそれだけを使う」実装だと、一度古い/期限切れの
    // token が sessionStorage に残った瞬間、以降どれだけ有効な cookie が発行
    // されても client は「未ログイン」と誤判定し続けてループになる
    // (cookie 自体は1個で shadowing (#531本体) ではないケース、2026-09-10 本番実測:
    // server は毎回 payloadValid:true で 200 を返すのに client だけ /login に
    // 戻り続けた)。sessionStorage が無効なら cookie にフォールバックし、
    // 見つかった有効な token で sessionStorage も更新するのが正しい挙動。
    afterAll(() => {
      // @ts-expect-error test-only global stub
      delete globalThis.document;
      // @ts-expect-error test-only global stub
      delete globalThis.sessionStorage;
    });

    function extractGetValidToken(html: string) {
      return extractClientFunctions<{
        decodeJwtPayload: (token: string) => unknown;
        getAllCookies: (name: string) => string[];
        findValidAuthCookie: () => string | null;
        getValidToken: () => { token: string; orgId?: string; expiresAt: number } | null;
      }>(html, ["decodeJwtPayload", "getAllCookies", "findValidAuthCookie", "getValidToken"]);
    }

    it("falls back to a valid cookie when sessionStorage holds an expired token", () => {
      const html = renderTopPage([], "https://auth.example.com");
      const fns = extractGetValidToken(html);

      const now = Math.floor(Date.now() / 1000);
      const staleSessionToken = fakeJwt({ exp: now - 3600, org: "stale-session" });
      const validCookieToken = fakeJwt({ exp: now + 3600, org: "fresh-cookie" });

      const store: Record<string, string> = { auth_token: staleSessionToken };
      // @ts-expect-error test-only global stub
      globalThis.sessionStorage = {
        getItem: (k: string) => store[k] ?? null,
        setItem: (k: string, v: string) => { store[k] = v; },
      };
      // @ts-expect-error test-only global stub
      globalThis.document = { cookie: `logi_auth_token=${validCookieToken}` };

      const result = fns.getValidToken();
      expect(result).not.toBeNull();
      expect(result!.token).toBe(validCookieToken);
      // sessionStorage の古い値も更新される (以降の呼び出しも一致させる)
      expect(store.auth_token).toBe(validCookieToken);
    });

    it("returns null when both sessionStorage and every cookie candidate are invalid", () => {
      const html = renderTopPage([], "https://auth.example.com");
      const fns = extractGetValidToken(html);

      const now = Math.floor(Date.now() / 1000);
      const staleSessionToken = fakeJwt({ exp: now - 3600 });
      const staleCookieToken = fakeJwt({ exp: now - 7200 });

      const store: Record<string, string> = { auth_token: staleSessionToken };
      // @ts-expect-error test-only global stub
      globalThis.sessionStorage = {
        getItem: (k: string) => store[k] ?? null,
        setItem: (k: string, v: string) => { store[k] = v; },
      };
      // @ts-expect-error test-only global stub
      globalThis.document = { cookie: `logi_auth_token=${staleCookieToken}` };

      expect(fns.getValidToken()).toBeNull();
    });
  });
});

describe("renderStagingFooter", () => {
  it("embeds the alc api origin via JSON.stringify", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-1");
    expect(html).toContain(JSON.stringify("https://alc.example.com"));
  });

  it("embeds the tenant_id via JSON.stringify", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-xyz");
    expect(html).toContain(JSON.stringify("tid-xyz"));
  });

  it("uses /api/staging/export with URL-encoded tenant_id", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-xyz");
    expect(html).toContain("/api/staging/export");
    expect(html).toContain("encodeURIComponent(TENANT_ID)");
  });

  it("uses POST /api/staging/import", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-xyz");
    expect(html).toContain("/api/staging/import");
    expect(html).toContain("method: 'POST'");
  });

  it("contains Export and Import buttons", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-xyz");
    expect(html).toContain("staging-btn-export");
    expect(html).toContain("staging-btn-import");
  });

  it("safely escapes a tenant_id that contains a quote", () => {
    const html = renderStagingFooter("https://alc.example.com", 'tid\";alert(1);//');
    expect(html).toContain(JSON.stringify('tid\";alert(1);//'));
    expect(html).not.toContain('"tid";alert(1);//"');
  });
});
