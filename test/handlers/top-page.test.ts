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

  it("returns HTML with correct Content-Type", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/top");

    const res = await handleTopPage(req, env);

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await res.text()).toBe("<html>mock top page</html>");
  });

  it("filters out auth origins and self from app list", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS:
        "https://nuxt-pwa-carins.example,https://auth.test.example,https://ohishi2.example",
      AUTH_WORKER_ORIGIN: "https://auth.test.example",
    });
    const req = new Request("https://auth.test.example/top");

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [
        { name: "車検証管理", url: "https://nuxt-pwa-carins.example", icon: "車", description: "車検証・ファイル管理" },
        { name: "DTako ログ", url: "https://ohishi2.example", icon: "DVR", description: "ドライブレコーダーログ" },
      ],
      "https://auth.test.example",
    );
  });

  it("maps nuxt-items origin correctly", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS: "https://nuxt-items.example",
    });
    const req = new Request("https://auth.test.example/top");

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
    const req = new Request("https://auth.test.example/top");

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      [{ name: "https://unknown.example", url: "https://unknown.example", icon: "App", description: "" }],
      "https://auth.test.example",
    );
  });

  it("handles empty ALLOWED_REDIRECT_ORIGINS", async () => {
    const env = createMockEnv({ ALLOWED_REDIRECT_ORIGINS: "" });
    const req = new Request("https://auth.test.example/top");

    await handleTopPage(req, env);

    expect(renderTopPage).toHaveBeenCalledWith([], "https://auth.test.example");
  });
});
