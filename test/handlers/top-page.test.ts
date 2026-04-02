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
    const request = new Request("https://auth.test.example/top");

    const response = await handleTopPage(request, env);

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await response.text()).toBe("<html>mock top page</html>");
  });

  it("maps nuxt-pwa-carins origin to correct app entry", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS: "https://nuxt-pwa-carins.example.com",
      AUTH_WORKER_ORIGIN: "https://auth.test.example",
    });
    const request = new Request("https://auth.test.example/top");

    await handleTopPage(request, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ name: "車検証管理", icon: "車" }),
      ]),
      "https://auth.test.example",
    );
  });

  it("maps ohishi2 origin to DTako", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS: "https://ohishi2.example.com",
      AUTH_WORKER_ORIGIN: "https://auth.test.example",
    });
    const request = new Request("https://auth.test.example/top");

    await handleTopPage(request, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ name: "DTako ログ", icon: "DVR" }),
      ]),
      "https://auth.test.example",
    );
  });

  it("maps nuxt-items origin to correct app entry", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS: "https://nuxt-items.example.com",
      AUTH_WORKER_ORIGIN: "https://auth.test.example",
    });
    const request = new Request("https://auth.test.example/top");

    await handleTopPage(request, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ name: "物品管理", icon: "箱" }),
      ]),
      "https://auth.test.example",
    );
  });

  it("maps unknown origin to default app entry", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS: "https://unknown.example.com",
      AUTH_WORKER_ORIGIN: "https://auth.test.example",
    });
    const request = new Request("https://auth.test.example/top");

    await handleTopPage(request, env);

    expect(renderTopPage).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({
          name: "https://unknown.example.com",
          icon: "App",
          description: "",
        }),
      ]),
      "https://auth.test.example",
    );
  });

  it("filters out AUTH_WORKER_ORIGIN from apps", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS: "https://auth.test.example,https://app1.test.example",
      AUTH_WORKER_ORIGIN: "https://auth.test.example",
    });
    const request = new Request("https://auth.test.example/top");

    await handleTopPage(request, env);

    const apps = (renderTopPage as ReturnType<typeof vi.fn>).mock.calls[0]![0];
    expect(apps).toHaveLength(1);
    expect(apps[0].url).toBe("https://app1.test.example");
  });

  it("filters out auth. origins", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS: "https://auth.other.example,https://app1.test.example",
      AUTH_WORKER_ORIGIN: "https://auth.test.example",
    });
    const request = new Request("https://auth.test.example/top");

    await handleTopPage(request, env);

    const apps = (renderTopPage as ReturnType<typeof vi.fn>).mock.calls[0]![0];
    expect(apps).toHaveLength(1);
    expect(apps[0].url).toBe("https://app1.test.example");
  });

  it("handles empty ALLOWED_REDIRECT_ORIGINS", async () => {
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS: "",
      AUTH_WORKER_ORIGIN: "https://auth.test.example",
    });
    const request = new Request("https://auth.test.example/top");

    await handleTopPage(request, env);

    const apps = (renderTopPage as ReturnType<typeof vi.fn>).mock.calls[0]![0];
    expect(apps).toHaveLength(0);
  });
});
