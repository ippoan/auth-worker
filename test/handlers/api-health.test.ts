import { describe, it, expect, vi } from "vitest";
import { createMockEnv } from "../helpers/mock-env";
import worker from "../../src/index";

describe("GET /api/health", () => {
  it("proxies backend health response", async () => {
    const env = createMockEnv();
    const mockHealth = { status: "ok", version: "0.1.0", git_sha: "abc1234" };

    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify(mockHealth), { status: 200 })
    );

    const req = new Request("https://auth.test.example/api/health");
    const res = await worker.fetch(req, env);

    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    const body = await res.json();
    expect(body).toEqual(mockHealth);

    expect(globalThis.fetch).toHaveBeenCalledWith(
      "https://alc-api.test.example/api/health"
    );
  });

  it("passes through backend error", async () => {
    const env = createMockEnv();

    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response("error", { status: 500 })
    );

    const req = new Request("https://auth.test.example/api/health");
    const res = await worker.fetch(req, env);

    expect(res.status).toBe(500);
  });
});
