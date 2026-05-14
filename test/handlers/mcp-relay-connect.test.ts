/**
 * `handleMcpRelayConnect` unit test (issue #117 / Phase 6)。
 *
 * `Authorization` / Upgrade ヘッダ / JWT 検証 / user 一致のみを検証する。
 * DO の WS accept ロジックは `test/durable_objects/mcp-session-do.test.ts` で
 * 別途検証するので、ここでは DO stub に流れたか (forward) と stub レスポンスを
 * passthrough したかだけ確認する。
 */

import { describe, it, expect, vi } from "vitest";

// --- Response polyfill: allow status 101 (undici は 200-599 のみ) ---
// connect handler は DO から 101 を passthrough するので、test stub 内でも
// 101 を返せるようにしておく。
const OriginalResponse = globalThis.Response;
class ResponseWithStatus extends OriginalResponse {
  constructor(body?: BodyInit | null, init?: ResponseInit) {
    const { status, ...rest } = init ?? {};
    const safeStatus = status === 101 ? 200 : status;
    super(body ?? null, { ...rest, status: safeStatus });
    if (status !== undefined && status !== safeStatus) {
      Object.defineProperty(this, "status", { value: status, configurable: true });
    }
  }
}
(globalThis as unknown as { Response: typeof Response }).Response =
  ResponseWithStatus as unknown as typeof Response;

import { handleMcpRelayConnect } from "../../src/handlers/mcp-relay-connect";
import { createMockEnv } from "../helpers/mock-env";
import { signMcpJwt } from "../../src/lib/mcp-jwt";
import type { Env } from "../../src/index";

const TEST_SECRET = "test-mcp-jwt-secret-32chars!!!!!!!";
const AUD = "github-mcp-server-rs";

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

function envWithDO(stubFetch?: (req: Request) => Promise<Response>): {
  env: Env;
  idFromNameCalls: string[];
  fetchCalls: Request[];
} {
  const { ns, idFromNameCalls, fetchCalls } = mockDONamespace(
    stubFetch ?? (async () => new Response(null, { status: 101 })),
  );
  const env = createMockEnv({
    MCP_JWT_SECRET: TEST_SECRET,
    MCP_SESSION_DO: ns,
  });
  return { env, idFromNameCalls, fetchCalls };
}

async function validJwt(login = "alice"): Promise<string> {
  return signMcpJwt(
    { sub: `github:${login}`, github_login: login, scope: "mcp.read", aud: AUD },
    TEST_SECRET,
    3600,
  );
}

function wsReq(opts: { auth?: string | null; upgrade?: string }): Request {
  const headers: Record<string, string> = {};
  if (opts.upgrade !== undefined) headers.Upgrade = opts.upgrade;
  if (opts.auth !== null && opts.auth !== undefined) headers.Authorization = opts.auth;
  return new Request("https://mcp.test.example/u/alice/connect", {
    method: "GET",
    headers,
  });
}

describe("handleMcpRelayConnect — env / pre-flight guards", () => {
  it("returns 503 when MCP_JWT_SECRET missing", async () => {
    const env = createMockEnv({ MCP_JWT_SECRET: undefined });
    const res = await handleMcpRelayConnect(wsReq({ upgrade: "websocket" }), env, "alice");
    expect(res.status).toBe(503);
  });

  it("returns 426 when Upgrade header is not 'websocket'", async () => {
    const { env } = envWithDO();
    const res = await handleMcpRelayConnect(wsReq({}), env, "alice");
    expect(res.status).toBe(426);
  });

  it("returns 503 when MCP_SESSION_DO binding missing", async () => {
    const env = createMockEnv({ MCP_JWT_SECRET: TEST_SECRET });
    // MCP_SESSION_DO は default で undefined
    const res = await handleMcpRelayConnect(wsReq({ upgrade: "websocket" }), env, "alice");
    expect(res.status).toBe(503);
  });

  it("returns 400 when :user is empty", async () => {
    const { env } = envWithDO();
    const res = await handleMcpRelayConnect(wsReq({ upgrade: "websocket" }), env, "");
    expect(res.status).toBe(400);
  });
});

describe("handleMcpRelayConnect — JWT authentication", () => {
  // Phase 4 / issue #126: WS upgrade の 401 にも `WWW-Authenticate` を付ける
  // (binary 側 client が JWT 取り直し flow に進めるように)。
  const expectedWwwAuth =
    'Bearer realm="MCP", resource_metadata="https://auth.test.example/.well-known/oauth-protected-resource"';

  it("returns 401 + WWW-Authenticate when Authorization header is missing", async () => {
    const { env } = envWithDO();
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket" }),
      env,
      "alice",
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBe(expectedWwwAuth);
  });

  it("returns 401 + WWW-Authenticate when Authorization is not Bearer-format", async () => {
    const { env } = envWithDO();
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: "Basic xyz" }),
      env,
      "alice",
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBe(expectedWwwAuth);
  });

  it("returns 401 + WWW-Authenticate when JWT signature is invalid", async () => {
    const { env } = envWithDO();
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: "Bearer a.b.c" }),
      env,
      "alice",
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBe(expectedWwwAuth);
  });

  it("returns 403 when payload.github_login does not match :user", async () => {
    const { env } = envWithDO();
    const jwt = await validJwt("alice");
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: `Bearer ${jwt}` }),
      env,
      "bob",
    );
    expect(res.status).toBe(403);
  });
});

describe("handleMcpRelayConnect — DO forwarding", () => {
  it("calls DO.idFromName(user) and forwards request to /__connect", async () => {
    const stubFetch = vi.fn(
      async () => new Response(null, { status: 101 }),
    );
    const { env, idFromNameCalls, fetchCalls } = envWithDO(stubFetch);
    const jwt = await validJwt("alice");
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: `Bearer ${jwt}` }),
      env,
      "alice",
    );
    expect(res.status).toBe(101);
    expect(idFromNameCalls).toEqual(["alice"]);
    expect(fetchCalls).toHaveLength(1);
    const forwarded = fetchCalls[0]!;
    expect(new URL(forwarded.url).pathname).toBe("/__connect");
    expect(forwarded.headers.get("Upgrade")).toBe("websocket");
    expect(forwarded.headers.get("Authorization")).toBe(`Bearer ${jwt}`);
  });

  it("passes through whatever status the DO returns", async () => {
    const stubFetch = vi.fn(
      async () =>
        new Response("nope", { status: 503, headers: { "X-DO": "1" } }),
    );
    const { env } = envWithDO(stubFetch);
    const jwt = await validJwt("alice");
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: `Bearer ${jwt}` }),
      env,
      "alice",
    );
    expect(res.status).toBe(503);
    expect(res.headers.get("X-DO")).toBe("1");
  });
});
