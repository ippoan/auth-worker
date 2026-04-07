import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

vi.mock("../../src/lib/top-html", () => ({
  renderTopPage: vi.fn(() => "<html>mock top page</html>"),
}));

import { handleTopPage } from "../../src/handlers/top-page";
import { renderTopPage } from "../../src/lib/top-html";

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

  it("returns HTML when auth cookie is present", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: "logi_auth_token=some-jwt-token" },
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
      ALLOWED_REDIRECT_ORIGINS:
        "https://nuxt-pwa-carins.example,https://auth.test.example,https://ohishi2.example",
      AUTH_WORKER_ORIGIN: "https://auth.test.example",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: "logi_auth_token=test-jwt" },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [
        { name: "車検証管理", url: "https://nuxt-pwa-carins.example", icon: "車", description: "車検証・ファイル管理" },
        { name: "DTako 管理", url: "https://ohishi2.example", icon: "DVR", description: "ドライブレコーダーログ" },
      ],
      "https://auth.test.example",
    );
  });

  it("maps nuxt-items origin correctly", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS: "https://nuxt-items.example",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: "logi_auth_token=test-jwt" },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [{ name: "物品管理", url: "https://nuxt-items.example", icon: "箱", description: "組織・個人の物品管理" }],
      "https://auth.test.example",
    );
  });

  it("falls back to generic app entry for unknown origins", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS: "https://unknown.example",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: "logi_auth_token=test-jwt" },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [{ name: "https://unknown.example", url: "https://unknown.example", icon: "App", description: "" }],
      "https://auth.test.example",
    );
  });

  it("maps staging URLs correctly", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS:
        "https://alc-app-staging.m-tama-ramu.workers.dev,https://dtako-admin-staging.m-tama-ramu.workers.dev,https://nuxt-ichibanboshi-staging.m-tama-ramu.workers.dev,https://nuxt-notify-staging.m-tama-ramu.workers.dev,https://nuxt-pwa-carins-staging.m-tama-ramu.workers.dev",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: "logi_auth_token=test-jwt" },
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
    );
  });

  it("filters out auth-worker-staging URL", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS:
        "https://auth-worker-staging.m-tama-ramu.workers.dev,https://alc-app-staging.m-tama-ramu.workers.dev",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: "logi_auth_token=test-jwt" },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [
        { name: "アルコールチェック", url: "https://alc-app-staging.m-tama-ramu.workers.dev", icon: "🍺", description: "アルコール検知・管理" },
      ],
      "https://auth.test.example",
    );
  });

  it("maps ippoan.org staging subdomains correctly", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS:
        "https://alc-staging.ippoan.org,https://carins-staging.ippoan.org,https://dtako-staging.ippoan.org,https://ichibanboshi-staging.ippoan.org,https://notify-staging.ippoan.org,https://items-staging.ippoan.org",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: "logi_auth_token=test-jwt" },
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
    );
  });

  it("deduplicates apps by name, keeping first (ippoan.org) URL", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS:
        "https://carins-staging.ippoan.org,https://nuxt-pwa-carins-staging.m-tama-ramu.workers.dev",
    });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: "logi_auth_token=test-jwt" },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [{ name: "車検証管理", url: "https://carins-staging.ippoan.org", icon: "車", description: "車検証・ファイル管理" }],
      "https://auth.test.example",
    );
  });

  it("handles empty ALLOWED_REDIRECT_ORIGINS", async () => {
    const env = createMockEnv({ ALLOWED_REDIRECT_ORIGINS: "" });
    const req = new Request("https://auth.test.example/top", {
      headers: { Cookie: "logi_auth_token=test-jwt" },
    });

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith([], "https://auth.test.example");
  });
});
