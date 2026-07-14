import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMockEnv, createMockKV, TEST_JWT_SECRET } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";

vi.mock("../../src/lib/top-html", () => ({
  renderTopPage: vi.fn(() => "<html>mock top page</html>"),
}));

import { handleTopPage } from "../../src/handlers/top-page";
import { renderTopPage } from "../../src/lib/top-html";

/** Sign a JWT with the test secret so verifyJwt accepts it. */
function authedCookie(payload: Record<string, unknown> = {}): Promise<string> {
  return signTestJwt(payload, TEST_JWT_SECRET).then(
    (token) => `logi_auth_token=${token}`,
  );
}

describe("handleTopPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("redirects to /login when no auth cookie", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/top");

    const res = await handleTopPage(req, env);

    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/login");
    expect(location).toContain("redirect_uri=");
    expect(location).toContain(encodeURIComponent("https://auth.test.example/top"));
  });

  it("redirects to /login when cookie JWT signature is invalid", async () => {
    // Token signed with a different secret → fails verifyJwt.
    const token = await signTestJwt({ sub: "u1" }, "wrong-secret");
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: `logi_auth_token=${token}` },
    });

    const res = await handleTopPage(req, env);

    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("/login");
  });

  it("redirects to /login when cookie JWT is expired", async () => {
    const token = await signTestJwt(
      { sub: "u1", exp: Math.floor(Date.now() / 1000) - 60 },
      TEST_JWT_SECRET,
    );
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: `logi_auth_token=${token}` },
    });

    const res = await handleTopPage(req, env);

    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("/login");
  });

  it("redirects to /login when cookie JWT is malformed", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: "logi_auth_token=not.a.valid.jwt" },
    });

    const res = await handleTopPage(req, env);

    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("/login");
  });

  it("returns HTML when auth cookie is a valid signed JWT", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie() },
    });

    const res = await handleTopPage(req, env);

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await res.text()).toBe("<html>mock top page</html>");
    // 有効 cookie の通常フローに破棄 Set-Cookie を混入させない (Refs #387)
    expect(res.headers.get("Set-Cookie")).toBeNull();
  });

  describe("毒 cookie の自動破棄 + shadowing 耐性 (Refs #387)", () => {
    it("invalid cookie 付き redirect には破棄 Set-Cookie (Domain 付き/無し) が付く", async () => {
      const token = await signTestJwt({ sub: "u1" }, "wrong-secret");
      const env = createMockEnv();
      const req = new Request("https://auth.test.example/top", {
        headers: { Cookie: `logi_auth_token=${token}` },
      });

      const res = await handleTopPage(req, env);

      expect(res.status).toBe(302);
      const setCookies = res.headers.getSetCookie();
      expect(setCookies.length).toBe(2);
      for (const c of setCookies) {
        expect(c).toContain("logi_auth_token=;");
        expect(c).toContain("Max-Age=0");
      }
      // Domain 付き (親ドメイン) と host-only の両方を破棄する
      expect(setCookies.some((c) => c.includes("Domain=.test.example"))).toBe(true);
      expect(setCookies.some((c) => !c.includes("Domain="))).toBe(true);
    });

    it("cookie 無しの redirect には Set-Cookie を付けない", async () => {
      const env = createMockEnv();
      const req = new Request("https://auth.test.example/top");

      const res = await handleTopPage(req, env);

      expect(res.status).toBe(302);
      expect(res.headers.get("Set-Cookie")).toBeNull();
    });

    it("同名 cookie 2 個 (先頭 invalid / 後方 valid) でも表示できる", async () => {
      const stale = await signTestJwt({ sub: "u1" }, "wrong-secret");
      const env = createMockEnv();
      const req = new Request("https://auth.test.example/top", {
        headers: {
          Cookie: `logi_auth_token=${stale}; ${await authedCookie()}`,
        },
      });

      const res = await handleTopPage(req, env);

      expect(res.status).toBe(200);
      expect(await res.text()).toBe("<html>mock top page</html>");
    });
  });

  describe("dangling tenant 検知 (my-orgs 空 → /logout、ループ回避)", () => {
    // verifiedIdentityHeaders が identity を組める full claims (4 点必須)
    const fullClaims = {
      sub: "11111111-1111-1111-1111-111111111111",
      tenant_id: "22222222-2222-2222-2222-222222222222",
      email: "op@example.com",
      role: "admin",
    };
    const realFetch = globalThis.fetch;
    afterEach(() => {
      globalThis.fetch = realFetch;
    });
    function stubMyOrgs(organizations: unknown[] | null, status = 200): void {
      globalThis.fetch = vi
        .fn()
        .mockResolvedValue(
          new Response(JSON.stringify(organizations === null ? {} : { organizations }), {
            status,
          }),
        ) as unknown as typeof fetch;
    }

    it("my-orgs が空なら /logout へ 302 (/login ではない = ループ回避)", async () => {
      stubMyOrgs([]);
      const env = createMockEnv();
      const req = new Request("https://auth.test.example/top", {
        headers: { Cookie: await authedCookie(fullClaims) },
      });

      const res = await handleTopPage(req, env);

      expect(res.status).toBe(302);
      const loc = res.headers.get("Location")!;
      expect(loc).toContain("/logout");
      expect(loc).not.toContain("/login");
    });

    it("組織があれば通常どおり表示する", async () => {
      stubMyOrgs([{ id: "org-1", name: "Org", slug: "org" }]);
      const env = createMockEnv();
      const req = new Request("https://auth.test.example/top", {
        headers: { Cookie: await authedCookie(fullClaims) },
      });

      const res = await handleTopPage(req, env);

      expect(res.status).toBe(200);
      expect(await res.text()).toBe("<html>mock top page</html>");
    });

    it("判定不能 (fetch 失敗 / 非 200 / 応答形不正) は fail-open で表示", async () => {
      const env = createMockEnv();
      for (const setup of [
        () => {
          globalThis.fetch = vi
            .fn()
            .mockRejectedValue(new Error("rust down")) as unknown as typeof fetch;
        },
        () => stubMyOrgs([], 503),
        () => stubMyOrgs(null),
      ]) {
        setup();
        const req = new Request("https://auth.test.example/top", {
          headers: { Cookie: await authedCookie(fullClaims) },
        });
        const res = await handleTopPage(req, env);
        expect(res.status).toBe(200);
        expect(await res.text()).toBe("<html>mock top page</html>");
      }
    });

    it("?woff=1 は組織 gate をスキップ (WOFF 非破壊)", async () => {
      stubMyOrgs([]);
      const env = createMockEnv();
      const req = new Request("https://auth.test.example/top?woff=1", {
        headers: { Cookie: await authedCookie(fullClaims) },
      });

      const res = await handleTopPage(req, env);

      expect(res.status).toBe(200);
      expect(await res.text()).toBe("<html>mock top page</html>");
    });

    it("identity claims 不足は fetch せず fail-open", async () => {
      const fetchSpy = vi.fn();
      globalThis.fetch = fetchSpy as unknown as typeof fetch;
      const env = createMockEnv();
      const req = new Request("https://auth.test.example/top", {
        headers: { Cookie: await authedCookie() }, // claims なし
      });

      const res = await handleTopPage(req, env);

      expect(res.status).toBe(200);
      expect(fetchSpy).not.toHaveBeenCalled();
    });
  });

  it("allows access with ?woff=1 even without cookie (WOFF flow)", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/top?woff=1&lw=ohishi");

    const res = await handleTopPage(req, env);

    expect(res.status).toBe(200);
    expect(await res.text()).toBe("<html>mock top page</html>");
  });

  it("allows access with ?lw_callback=1 even without cookie (OAuth return)", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/top?lw_callback=1");

    const res = await handleTopPage(req, env);

    expect(res.status).toBe(200);
    expect(await res.text()).toBe("<html>mock top page</html>");
  });

  it("filters out auth origins and self from app list", async () => {
    const env = createMockEnv({
      allowedOrigins:
        "https://nuxt-pwa-carins.example,https://auth.test.example,https://ohishi2.example",
      AUTH_WORKER_ORIGIN: "https://auth.test.example",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie() },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [
        { name: "車検証管理", url: "https://nuxt-pwa-carins.example", icon: "車", description: "車検証・ファイル管理" },
        { name: "車両位置", url: "https://ohishi2.example", icon: "🚛", description: "GPS トラック位置" },
      ],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });

  it("maps dtako-logs.ippoan.org to 車両位置 and prefers it over old ohishi2 on dedup", async () => {
    const env = createMockEnv({
      // 移行期間: 旧 ohishi2 が先、新 dtako-logs.ippoan.org が後。
      allowedOrigins:
        "https://ohishi2.mtamaramu.com,https://dtako-logs.ippoan.org",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie() },
    });

    await handleTopPage(req, env);

    // 同名 (車両位置) は 1 タイルに統合され、リンク先は canonical な ippoan ドメイン。
    expect(renderTopPage).toHaveBeenCalledWith(
      [
        { name: "車両位置", url: "https://dtako-logs.ippoan.org", icon: "🚛", description: "GPS トラック位置" },
      ],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });

  it("maps nuxt-items origin correctly", async () => {
    const env = createMockEnv({
      allowedOrigins: "https://nuxt-items.example",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie() },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [{ name: "物品管理", url: "https://nuxt-items.example", icon: "箱", description: "組織・個人の物品管理" }],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });

  it("maps ichibanboshi-seikyu to its own tile (not collapsed into 一番星)", async () => {
    const env = createMockEnv({
      allowedOrigins:
        "https://ichibanboshi.ippoan.org,https://ichibanboshi-seikyu.ippoan.org",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie() },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [
        { name: "一番星", url: "https://ichibanboshi.ippoan.org", icon: "⭐", description: "一番星管理" },
        { name: "一番星 請求", url: "https://ichibanboshi-seikyu.ippoan.org", icon: "🧾", description: "燃料サーチャージ請求" },
      ],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });

  it("falls back to generic app entry for unknown origins", async () => {
    const env = createMockEnv({
      allowedOrigins: "https://unknown.example",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie() },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [{ name: "https://unknown.example", url: "https://unknown.example", icon: "App", description: "" }],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });

  it("maps staging URLs correctly", async () => {
    const env = createMockEnv({
      allowedOrigins:
        "https://alc-app-staging.m-tama-ramu.workers.dev,https://dtako-admin-staging.m-tama-ramu.workers.dev,https://nuxt-ichibanboshi-staging.m-tama-ramu.workers.dev,https://nuxt-notify-staging.m-tama-ramu.workers.dev,https://nuxt-pwa-carins-staging.m-tama-ramu.workers.dev",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie() },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [
        { name: "アルコールチェック", url: "https://alc-app-staging.m-tama-ramu.workers.dev", icon: "🍺", description: "アルコール検知・管理" },
        { name: "DTako 管理", url: "https://dtako-admin-staging.m-tama-ramu.workers.dev", icon: "DVR", description: "ドライブレコーダーログ" },
        { name: "一番星", url: "https://nuxt-ichibanboshi-staging.m-tama-ramu.workers.dev", icon: "⭐", description: "一番星管理" },
        { name: "通知管理", url: "https://nuxt-notify-staging.m-tama-ramu.workers.dev", icon: "📨", description: "メッセージ配信" },
        { name: "車検証管理", url: "https://nuxt-pwa-carins-staging.m-tama-ramu.workers.dev", icon: "車", description: "車検証・ファイル管理" },
      ],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });

  it("filters out auth-worker-staging URL", async () => {
    const env = createMockEnv({
      allowedOrigins:
        "https://auth-worker-staging.m-tama-ramu.workers.dev,https://alc-app-staging.m-tama-ramu.workers.dev",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie() },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [
        { name: "アルコールチェック", url: "https://alc-app-staging.m-tama-ramu.workers.dev", icon: "🍺", description: "アルコール検知・管理" },
      ],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });

  it("maps ippoan.org staging subdomains correctly", async () => {
    const env = createMockEnv({
      allowedOrigins:
        "https://alc-staging.ippoan.org,https://carins-staging.ippoan.org,https://dtako-staging.ippoan.org,https://ichibanboshi-staging.ippoan.org,https://notify-staging.ippoan.org,https://items-staging.ippoan.org",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie() },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [
        { name: "アルコールチェック", url: "https://alc-staging.ippoan.org", icon: "🍺", description: "アルコール検知・管理" },
        { name: "車検証管理", url: "https://carins-staging.ippoan.org", icon: "車", description: "車検証・ファイル管理" },
        { name: "DTako 管理", url: "https://dtako-staging.ippoan.org", icon: "DVR", description: "ドライブレコーダーログ" },
        { name: "一番星", url: "https://ichibanboshi-staging.ippoan.org", icon: "⭐", description: "一番星管理" },
        { name: "通知管理", url: "https://notify-staging.ippoan.org", icon: "📨", description: "メッセージ配信" },
        { name: "物品管理", url: "https://items-staging.ippoan.org", icon: "箱", description: "組織・個人の物品管理" },
      ],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });

  it("deduplicates apps by name, keeping first (ippoan.org) URL", async () => {
    const env = createMockEnv({
      allowedOrigins:
        "https://carins-staging.ippoan.org,https://nuxt-pwa-carins-staging.m-tama-ramu.workers.dev",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie() },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [{ name: "車検証管理", url: "https://carins-staging.ippoan.org", icon: "車", description: "車検証・ファイル管理" }],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });

  it("handles empty ALLOWED_REDIRECT_ORIGINS", async () => {
    const env = createMockEnv({ allowedOrigins: "" });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie() },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });

  it("hides origins:wt entries from the rendered tile list", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({
        "origins:prod": "https://nuxt-pwa-carins.example",
        "origins:wt": "https://vast-requests-kurt-showing.trycloudflare.com",
      }),
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie() },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [{ name: "車検証管理", url: "https://nuxt-pwa-carins.example", icon: "車", description: "車検証・ファイル管理" }],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
    const lastCall = vi.mocked(renderTopPage).mock.calls[0]!;
    const calledApps = lastCall[0];
    expect(calledApps.some((a: { url: string }) => a.url.includes("trycloudflare.com"))).toBe(false);
  });

  it("shows ohishi-exp tile when tenant_id is in TENANT_ACL", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({
        "origins:prod": "https://dtako-admin.example",
        "app-orgs": JSON.stringify({ "dtako-admin": "ohishi-exp" }),
      }),
      TENANT_ACL: JSON.stringify({ "ohishi-exp": ["tenant-a"] }),
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie({ tenant_id: "tenant-a" }) },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [{ name: "DTako 管理", url: "https://dtako-admin.example", icon: "DVR", description: "ドライブレコーダーログ" }],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });

  it("hides ohishi-exp tile when tenant_id is not in TENANT_ACL", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({
        "origins:prod": "https://dtako-admin.example,https://nuxt-pwa-carins.example",
        "app-orgs": JSON.stringify({ "dtako-admin": "ohishi-exp" }),
      }),
      TENANT_ACL: JSON.stringify({ "ohishi-exp": ["tenant-a"] }),
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie({ tenant_id: "tenant-z" }) },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [{ name: "車検証管理", url: "https://nuxt-pwa-carins.example", icon: "車", description: "車検証・ファイル管理" }],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });

  it("hides ohishi-exp tile when cookie JWT has no tenant_id", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({
        "origins:prod": "https://dtako-admin.example",
        "app-orgs": JSON.stringify({ "dtako-admin": "ohishi-exp" }),
      }),
      TENANT_ACL: JSON.stringify({ "ohishi-exp": ["tenant-a"] }),
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie({ sub: "user-1" }) },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });

  it("hides ohishi-exp tile when TENANT_ACL secret is missing (fail-closed)", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({
        "origins:prod": "https://dtako-admin.example",
        "app-orgs": JSON.stringify({ "dtako-admin": "ohishi-exp" }),
      }),
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie({ tenant_id: "tenant-a" }) },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });

  it("leaves ippoan tiles visible regardless of tenant_id", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({
        "origins:prod": "https://nuxt-pwa-carins.example",
        "app-orgs": JSON.stringify({ "dtako-admin": "ohishi-exp" }),
      }),
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: await authedCookie() },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [{ name: "車検証管理", url: "https://nuxt-pwa-carins.example", icon: "車", description: "車検証・ファイル管理" }],
      "https://auth.test.example",
      expect.objectContaining({ workerEnv: "prod", alcApiOrigin: "https://alc-api.test.example" }),
    );
  });
});
