import { describe, it, expect } from "vitest";
import { renderLoginPage, escapeHtml } from "../../src/lib/html";
import { getLwLastDomain, setLwLastDomainCookie } from "../../src/lib/cookies";
import { authorizeUrl } from "../../src/lib/lineworks-oauth";
import { handleLoginPage } from "../../src/handlers/login-page";
import { createMockEnv } from "../helpers/mock-env";

const params = {
  redirectUri: "https://app.example.com/callback",
  googleEnabled: false,
  googleRedirectUrl: "",
  lineworksRedirectUrl: "https://auth.example.com/oauth/lineworks/redirect",
  lineLoginRedirectUrl: "https://auth.example.com/oauth/line/redirect",
};

describe("renderLoginPage の LINE WORKS 欄", () => {
  it("前回の会社が無ければ入力欄だけ (ボタン無し)", () => {
    const html = renderLoginPage(params);
    expect(html).toContain("LINE WORKS (会社のドメイン)");
    expect(html).toContain('placeholder="例: example"');
    expect(html).not.toContain("lw_quick");
    expect(html).not.toContain("別の会社でログイン");
  });

  it("前回の会社があればボタンと「別の会社でログイン」を出し、入力欄は隠す", () => {
    const html = renderLoginPage({ ...params, lineworksLastDomain: "example" });
    expect(html).toContain("LINE WORKS (example) でログイン");
    expect(html).toContain("address=example");
    expect(html).toContain("別の会社でログイン");
    expect(html).toContain('id="lw_form" class="lw-form" style="display:none"');
  });

  it("前回の会社は HTML エスケープする", () => {
    const html = renderLoginPage({ ...params, lineworksLastDomain: '"><script>x</script>' });
    expect(html).not.toContain("<script>x</script>");
    expect(html).toContain(escapeHtml('"><script>x</script>'));
  });
});

describe("前回の会社 cookie", () => {
  it("読み取りは形を検証する", () => {
    const req = (c?: string) =>
      new Request("https://auth.test.example/login", c ? { headers: { Cookie: c } } : {});
    expect(getLwLastDomain(req())).toBeNull();
    expect(getLwLastDomain(req("a=1; lw_last_domain=example"))).toBe("example");
    expect(getLwLastDomain(req("lw_last_domain=bad/domain"))).toBeNull();
  });

  it("Set-Cookie は host-only", () => {
    expect(setLwLastDomainCookie("example")).not.toContain("Domain=");
  });
});

describe("authorizeUrl", () => {
  it("domain 省略なら付けない", () => {
    expect(authorizeUrl("c", "r", "s")).not.toContain("domain=");
  });
});

describe("handleLoginPage (実 HTML)", () => {
  it("cookie があれば前回の会社ボタンが出る", async () => {
    const res = await handleLoginPage(
      new Request("https://auth.test.example/login?redirect_uri=https://app1.test.example/page", {
        headers: { Cookie: "lw_last_domain=example" },
      }),
      createMockEnv(),
    );
    expect(await res.text()).toContain("LINE WORKS (example) でログイン");
  });
});
