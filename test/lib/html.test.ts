import { describe, it, expect, afterEach } from "vitest";
import { renderLoginPage } from "../../src/lib/html";

/** clearAllCookies() の本体だけを取り出して実行可能な関数にする (Refs #531 follow-up)。 */
function extractClearAllCookies(html: string): () => void {
  const m = /function clearAllCookies\(\) \{[\s\S]*?\n {4}\}/.exec(html);
  if (!m) throw new Error("clearAllCookies not found in rendered HTML");
  // eslint-disable-next-line no-new-func
  return new Function(`return (${m[0]});`)() as () => void;
}

describe("renderLoginPage", () => {
  it("returns a string", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      googleEnabled: true,
      googleRedirectUrl: "https://api.example.com/auth/google/redirect",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
      lineLoginRedirectUrl: "https://api.example.com/auth/line/redirect",
    });
    expect(typeof result).toBe("string");
  });

  it("contains DOCTYPE html", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      googleEnabled: true,
      googleRedirectUrl: "https://api.example.com/auth/google/redirect",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
      lineLoginRedirectUrl: "https://api.example.com/auth/line/redirect",
    });
    expect(result).toContain("<!DOCTYPE html>");
  });

  it("contains Google login button when googleEnabled=true", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      googleEnabled: true,
      googleRedirectUrl: "https://api.example.com/auth/google/redirect",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
      lineLoginRedirectUrl: "https://api.example.com/auth/line/redirect",
    });
    expect(result).toContain("google");
  });

  it("does not contain Google redirect URL when googleEnabled=false", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      googleEnabled: false,
      googleRedirectUrl: "",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
      lineLoginRedirectUrl: "https://api.example.com/auth/line/redirect",
    });
    // The <a> tag with google-btn class should not be present, but CSS may still reference it
    expect(result).not.toContain('href="https://api.example.com/auth/google');
  });

  it("includes error message when provided", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      error: "invalid_token",
      googleEnabled: true,
      googleRedirectUrl: "https://api.example.com/auth/google/redirect",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
      lineLoginRedirectUrl: "https://api.example.com/auth/line/redirect",
    });
    expect(result).toContain("invalid_token");
  });

  it("escapes HTML special characters in error", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      error: '<script>alert("xss")</script>',
      googleEnabled: true,
      googleRedirectUrl: "https://api.example.com/auth/google/redirect",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
      lineLoginRedirectUrl: "https://api.example.com/auth/line/redirect",
    });
    expect(result).toContain("&lt;script&gt;");
    expect(result).not.toContain('<script>alert("xss")</script>');
  });

  it("escapes & < > characters", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      error: "a&b<c>d",
      googleEnabled: true,
      googleRedirectUrl: "https://api.example.com/auth/google/redirect",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
      lineLoginRedirectUrl: "https://api.example.com/auth/line/redirect",
    });
    expect(result).toContain("a&amp;b&lt;c&gt;d");
  });

  it("includes orgId in hidden field when provided", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      orgId: "test-org-id",
      googleEnabled: true,
      googleRedirectUrl: "https://api.example.com/auth/google/redirect",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
      lineLoginRedirectUrl: "https://api.example.com/auth/line/redirect",
    });
    expect(result).toContain("test-org-id");
  });

  describe("clearAllCookies (Refs #531 follow-up)", () => {
    // sessionStorage はタブを閉じるまで残り、top-html.ts の getValidToken() は
    // cookie より sessionStorage を優先して読む。「Cookie をクリア」ボタンが
    // sessionStorage を消していないと、cookie だけ消しても古い/無効な
    // sessionStorage の token が残ったままになり、/top ↔ /login ループが
    // 直らない (2026-09-10 本番実測)。
    afterEach(() => {
      // @ts-expect-error test-only global stubs
      delete globalThis.document;
      // @ts-expect-error test-only global stubs
      delete globalThis.location;
      // @ts-expect-error test-only global stubs
      delete globalThis.localStorage;
      // @ts-expect-error test-only global stubs
      delete globalThis.sessionStorage;
    });

    it("removes sessionStorage auth_token, not just cookies/localStorage", () => {
      const html = renderLoginPage({
        redirectUri: "https://app.example.com/callback",
        googleEnabled: true,
        googleRedirectUrl: "https://api.example.com/auth/google/redirect",
        lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
        lineLoginRedirectUrl: "https://api.example.com/auth/line/redirect",
      });
      const clearAllCookies = extractClearAllCookies(html);

      const removedLocalStorageKeys: string[] = [];
      const removedSessionStorageKeys: string[] = [];
      // @ts-expect-error test-only global stubs
      globalThis.document = {
        cookie: "",
        getElementById: () => ({ style: {} }),
      };
      // @ts-expect-error test-only global stubs
      globalThis.location = { hostname: "auth.ippoan.org", reload: () => {} };
      // @ts-expect-error test-only global stubs
      globalThis.localStorage = { removeItem: (k: string) => removedLocalStorageKeys.push(k) };
      // @ts-expect-error test-only global stubs
      globalThis.sessionStorage = { removeItem: (k: string) => removedSessionStorageKeys.push(k) };

      clearAllCookies();

      expect(removedSessionStorageKeys).toContain("auth_token");
      // 既存の localStorage clear も壊していないことを確認
      expect(removedLocalStorageKeys).toEqual(expect.arrayContaining(["logi_auth", "logi_lw_domain"]));
    });
  });
});
