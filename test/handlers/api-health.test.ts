import { describe, it, expect, vi, afterEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";
import { handleHealthProxy } from "../../src/handlers/health";

// backend (rust-alc-api) の health は撤収で無くなった (W9、Refs ippoan/rust-alc-api#680)。auth-worker 自身の版だけを返す
describe("handleHealthProxy", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("returns its own status and version with CORS header, without calling any backend", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const env = createMockEnv({ VERSION: "v1.2.3" });
    const res = await handleHealthProxy(env);

    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(res.headers.get("Content-Type")).toBe("application/json");
    expect(await res.json()).toEqual({ status: "ok", auth_worker_version: "v1.2.3" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("falls back to 'dev' when VERSION is empty", async () => {
    const env = createMockEnv({ VERSION: "" });
    const res = await handleHealthProxy(env);
    const body = (await res.json()) as { auth_worker_version: string };
    expect(body.auth_worker_version).toBe("dev");
  });
});
