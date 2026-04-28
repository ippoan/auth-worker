import { describe, expect, test, vi } from "vitest";
import {
  handleLineworksWebhook,
  handleLineworksRefresh,
} from "../../src/handlers/lineworks-webhook";
import type { Env } from "../../src/index";

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
    ALC_API_ORIGIN: "https://alc-api.test",
    VERSION: "test",
    WORKER_ENV: "test",
    JWT_SECRET: "test-secret",
    SSO_ENCRYPTION_KEY: "test-key",
    LINEWORKS_WEBHOOK_DO: ns,
    AUTH_CONFIG: {} as unknown as KVNamespace,
    ...overrides,
  } as Env;
}

describe("handleLineworksWebhook", () => {
  test("returns 400 when bot_id is empty", async () => {
    const env = makeEnv();
    const req = new Request("https://x/lineworks/webhook/", {
      method: "POST",
      body: "{}",
      headers: { "x-works-signature": "sig" },
    });
    const resp = await handleLineworksWebhook(req, env, "");
    expect(resp.status).toBe(400);
  });

  test("returns 405 when method is not POST", async () => {
    const env = makeEnv();
    const req = new Request("https://x/lineworks/webhook/bot1", { method: "GET" });
    const resp = await handleLineworksWebhook(req, env, "bot1");
    expect(resp.status).toBe(405);
  });

  test("returns 401 when x-works-signature is missing", async () => {
    const env = makeEnv();
    const req = new Request("https://x/lineworks/webhook/bot1", {
      method: "POST",
      body: "{}",
    });
    const resp = await handleLineworksWebhook(req, env, "bot1");
    expect(resp.status).toBe(401);
  });

  test("forwards request to DO and returns its response", async () => {
    const fetchSpy = vi.fn(async (_req: Request) => {
      return new Response(JSON.stringify({ ok: true, queued: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    const { ns, idFromNameCalls, fetchCalls } = mockDONamespace(fetchSpy);
    const env = makeEnv({ LINEWORKS_WEBHOOK_DO: ns });

    const req = new Request("https://x/lineworks/webhook/bot-xyz", {
      method: "POST",
      body: '{"type":"join","source":{"channelId":"ch"}}',
      headers: { "x-works-signature": "sig123", "Content-Type": "application/json" },
    });
    const resp = await handleLineworksWebhook(req, env, "bot-xyz");

    expect(resp.status).toBe(200);
    const body = (await resp.json()) as { ok: boolean; queued: boolean };
    expect(body.ok).toBe(true);
    expect(idFromNameCalls).toEqual(["bot-xyz"]);
    expect(fetchCalls).toHaveLength(1);
    expect(fetchCalls[0]?.headers.get("x-bot-id")).toBe("bot-xyz");
    expect(fetchCalls[0]?.headers.get("x-works-signature")).toBe("sig123");
  });

  test("forwards 401 from DO unchanged (signature_mismatch)", async () => {
    const { ns } = mockDONamespace(
      async () =>
        new Response(JSON.stringify({ error: "signature_mismatch" }), { status: 401 }),
    );
    const env = makeEnv({ LINEWORKS_WEBHOOK_DO: ns });

    const req = new Request("https://x/lineworks/webhook/bot-xyz", {
      method: "POST",
      body: "{}",
      headers: { "x-works-signature": "wrong" },
    });
    const resp = await handleLineworksWebhook(req, env, "bot-xyz");
    expect(resp.status).toBe(401);
  });
});

describe("handleLineworksRefresh", () => {
  async function signTestJwt(secret: string, payload: object): Promise<string> {
    const enc = new TextEncoder();
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const body = btoa(JSON.stringify(payload))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(`${header}.${body}`));
    let bin = "";
    const sigBytes = new Uint8Array(sig);
    for (let i = 0; i < sigBytes.length; i++) bin += String.fromCharCode(sigBytes[i] ?? 0);
    const sigB64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return `${header}.${body}.${sigB64}`;
  }

  test("returns 400 when bot_id is empty", async () => {
    const env = makeEnv();
    const resp = await handleLineworksRefresh(
      new Request("https://x/lineworks/refresh/", { method: "POST" }),
      env,
      "",
    );
    expect(resp.status).toBe(400);
  });

  test("returns 405 when method is not POST", async () => {
    const env = makeEnv();
    const resp = await handleLineworksRefresh(
      new Request("https://x/lineworks/refresh/bot1", { method: "GET" }),
      env,
      "bot1",
    );
    expect(resp.status).toBe(405);
  });

  test("returns 401 without Bearer token", async () => {
    const env = makeEnv();
    const resp = await handleLineworksRefresh(
      new Request("https://x/lineworks/refresh/bot1", { method: "POST" }),
      env,
      "bot1",
    );
    expect(resp.status).toBe(401);
  });

  test("returns 401 with malformed token", async () => {
    const env = makeEnv();
    const resp = await handleLineworksRefresh(
      new Request("https://x/lineworks/refresh/bot1", {
        method: "POST",
        headers: { Authorization: "Bearer not.valid" },
      }),
      env,
      "bot1",
    );
    expect(resp.status).toBe(401);
  });

  test("returns 401 with wrong aud", async () => {
    const env = makeEnv();
    const exp = Math.floor(Date.now() / 1000) + 60;
    const jwt = await signTestJwt(env.JWT_SECRET, { aud: "wrong", exp });
    const resp = await handleLineworksRefresh(
      new Request("https://x/lineworks/refresh/bot1", {
        method: "POST",
        headers: { Authorization: `Bearer ${jwt}` },
      }),
      env,
      "bot1",
    );
    expect(resp.status).toBe(401);
  });

  test("returns 401 with expired token", async () => {
    const env = makeEnv();
    const exp = Math.floor(Date.now() / 1000) - 10;
    const jwt = await signTestJwt(env.JWT_SECRET, { aud: "alc-api-internal", exp });
    const resp = await handleLineworksRefresh(
      new Request("https://x/lineworks/refresh/bot1", {
        method: "POST",
        headers: { Authorization: `Bearer ${jwt}` },
      }),
      env,
      "bot1",
    );
    expect(resp.status).toBe(401);
  });

  test("forwards refresh to DO with valid internal JWT", async () => {
    const fetchSpy = vi.fn(async (_req: Request) => new Response(JSON.stringify({ ok: true }), { status: 200 }));
    const { ns, fetchCalls } = mockDONamespace(fetchSpy);
    const env = makeEnv({ LINEWORKS_WEBHOOK_DO: ns });
    const exp = Math.floor(Date.now() / 1000) + 60;
    const jwt = await signTestJwt(env.JWT_SECRET, { aud: "alc-api-internal", exp });

    const resp = await handleLineworksRefresh(
      new Request("https://x/lineworks/refresh/bot1", {
        method: "POST",
        headers: { Authorization: `Bearer ${jwt}` },
      }),
      env,
      "bot1",
    );
    expect(resp.status).toBe(200);
    expect(fetchCalls).toHaveLength(1);
    const url = new URL(fetchCalls[0]!.url);
    expect(url.pathname).toBe("/refresh");
  });
});
