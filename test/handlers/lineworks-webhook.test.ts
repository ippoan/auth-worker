import { describe, expect, test, vi } from "vitest";
import { handleLineworksHook } from "../../src/handlers/lineworks-webhook";
import type { Env } from "../../src/index";
import { encodeHookId } from "../../src/lib/lineworks-hook-id";

/**
 * Cloudflare Workers の DurableObjectNamespace / DurableObjectStub をモック化したヘルパー。
 * vitest-pool-workers を入れずに DO の正面ルーティングだけ検証する。
 */
function mockDONamespace(stubFetch: (req: Request) => Promise<Response>): {
  ns: DurableObjectNamespace;
  idFromNameCalls: string[];
  fetchCalls: Request[];
} {
  const idFromNameCalls: string[] = [];
  const fetchCalls: Request[] = [];
  const stub = {
    fetch: async (req: Request) => {
      fetchCalls.push(req);
      return stubFetch(req);
    },
  } as unknown as DurableObjectStub;
  const ns = {
    idFromName: (name: string) => {
      idFromNameCalls.push(name);
      return { name } as unknown as DurableObjectId;
    },
    get: () => stub,
  } as unknown as DurableObjectNamespace;
  return { ns, idFromNameCalls, fetchCalls };
}

function makeEnv(overrides: Partial<Env> = {}): Env {
  const { ns } = mockDONamespace(async () => new Response("ok", { status: 200 }));
  return {
    GOOGLE_CLIENT_ID: "",
    GOOGLE_CLIENT_SECRET: "",
    OAUTH_STATE_SECRET: "",
    AUTH_WORKER_ORIGIN: "",
    VERSION: "test",
    WORKER_ENV: "test",
    JWT_SECRET: "test-secret",
    SSO_ENCRYPTION_KEY: "test-key",
    LINEWORKS_WEBHOOK_DO: ns,
    AUTH_CONFIG: {} as unknown as KVNamespace,
    ...overrides,
  } as Env;
}

describe("handleLineworksHook (tenant を暗号化した識別子の callback URL)", () => {
  const T = "11111111-2222-4333-8444-555555555555";
  const post = (sig?: string) =>
    new Request("https://x/lineworks/hook/id", {
      method: "POST",
      body: '{"type":"joined","source":{"channelId":"ch"}}',
      headers: sig
        ? { "x-works-signature": sig, "Content-Type": "application/json" }
        : { "Content-Type": "application/json" },
    });

  test("decodes the id and forwards to the (tenant, bot) DO with x-tenant-id", async () => {
    const { ns, idFromNameCalls, fetchCalls } = mockDONamespace(
      async () => new Response('{"ok":true}', { status: 200 }),
    );
    const env = makeEnv({ LINEWORKS_WEBHOOK_DO: ns });
    const id = await encodeHookId({ tenantId: T, botId: "13333925" }, "test-key");

    const resp = await handleLineworksHook(post("sig123"), env, id);

    expect(resp.status).toBe(200);
    expect(idFromNameCalls).toEqual([`hook:${T}:13333925`]);
    const fwd = fetchCalls[0]!;
    expect(fwd.headers.get("x-bot-id")).toBe("13333925");
    expect(fwd.headers.get("x-tenant-id")).toBe(T);
    expect(fwd.headers.get("x-works-signature")).toBe("sig123");
    expect(fwd.headers.get("content-type")).toBe("application/json");
    expect(await fwd.text()).toBe('{"type":"joined","source":{"channelId":"ch"}}');
  });

  test("rejects non-POST, unsigned, unknown ids and a missing key", async () => {
    const { ns, fetchCalls } = mockDONamespace(async () => new Response("ok"));
    const env = makeEnv({ LINEWORKS_WEBHOOK_DO: ns });
    const id = await encodeHookId({ tenantId: T, botId: "b" }, "test-key");

    expect((await handleLineworksHook(new Request("https://x", { method: "GET" }), env, id)).status).toBe(405);
    expect((await handleLineworksHook(post(), env, id)).status).toBe(401);
    for (const bad of ["", "garbage", await encodeHookId({ tenantId: T, botId: "b" }, "other-key")]) {
      const resp = await handleLineworksHook(post("s"), env, bad);
      expect(resp.status).toBe(404);
      expect(await resp.json()).toEqual({ error: "not_found" });
    }
    const noKey = makeEnv({ LINEWORKS_WEBHOOK_DO: ns, SSO_ENCRYPTION_KEY: undefined as unknown as string });
    expect((await handleLineworksHook(post("s"), noKey, id)).status).toBe(503);
    expect(fetchCalls).toHaveLength(0);
  });
});
