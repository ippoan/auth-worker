import { describe, it, expect, vi, beforeEach } from "vitest";
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
        { name: "DTako 管理", url: "https://ohishi2.example", icon: "DVR", description: "ドライブレコーダーログ" },
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
