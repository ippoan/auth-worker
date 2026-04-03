import { describe, it, expect, afterAll } from "vitest";
import {
  stubOrReal,
  testEnv,
  restoreFetch,
  waitIfLive,
} from "../helpers/stub-or-real";
import { handleHealthProxy } from "../../src/handlers/health";

waitIfLive();
afterAll(() => restoreFetch());

describe("handleHealthProxy", () => {
  it("proxies backend health response with CORS header", async () => {
    const mockHealth = { status: "ok", version: "0.1.0", git_sha: "abc1234" };
    stubOrReal(new Response(JSON.stringify(mockHealth), { status: 200 }));

    const env = testEnv();
    const res = await handleHealthProxy(env);

    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    const body = await res.json() as { status: string; auth_worker_version: string };
    expect(body.status).toBe("ok");
    expect(body.auth_worker_version).toBeTruthy();
  });

  it("returns auth_worker_version even when backend returns non-JSON", async () => {
    stubOrReal(new Response("not json", { status: 500 }));

    // live: 存在しないパスで非 JSON レスポンスを取得
    const env = testEnv();
    env.ALC_API_ORIGIN = `${env.ALC_API_ORIGIN}/nonexistent-html`;
    const res = await handleHealthProxy(env);

    const body = await res.json() as { auth_worker_version: string };
    expect(body.auth_worker_version).toBeTruthy();
  });

  it("falls back to 'dev' when VERSION is empty", async () => {
    const mockHealth = { status: "ok" };
    stubOrReal(new Response(JSON.stringify(mockHealth), { status: 200 }));

    // live: 実 API に対して VERSION="" で呼ぶ
    const env = testEnv();
    env.VERSION = "";
    const res = await handleHealthProxy(env);

    const body = await res.json() as { auth_worker_version: string };
    expect(body.auth_worker_version).toBe("dev");
  });

  it("passes through backend error status", async () => {
    stubOrReal(new Response("error", { status: 500 }));

    // live: API の存在しないパスに向けて 404 を取得
    const env = testEnv();
    env.ALC_API_ORIGIN = `${env.ALC_API_ORIGIN}/nonexistent`;
    const res = await handleHealthProxy(env);

    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});
