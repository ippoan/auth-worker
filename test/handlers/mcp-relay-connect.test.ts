/**
 * `handleMcpRelayConnect` unit test (issue #117 / Phase 6 + ADR-003)。
 *
 * `Authorization` / Upgrade ヘッダ / JWT 検証 / user 一致のみを検証する。
 * DO の WS accept ロジックは `test/durable_objects/mcp-session-do.test.ts` で
 * 別途検証するので、ここでは DO stub に流れたか (forward) と stub レスポンスを
 * passthrough したかだけ確認する。
 *
 * ADR-003 (ippoan/cc-relay#35) Phase A: `GET /connect` (user=null) も
 * 同じパスを通り、DO id が JWT.github_login から解決されることを確認する。
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
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import { signMcpJwt } from "../../src/lib/mcp-jwt";
import { PAIR_CODE_TTL_SEC, putPair, type PairRecord } from "../../src/lib/mcp-pair";
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

function wsReq(opts: { auth?: string | null; upgrade?: string; url?: string }): Request {
  const headers: Record<string, string> = {};
  if (opts.upgrade !== undefined) headers.Upgrade = opts.upgrade;
  if (opts.auth !== null && opts.auth !== undefined) headers.Authorization = opts.auth;
  return new Request(opts.url ?? "https://mcp.test.example/u/alice/connect", {
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

// ADR-003 (ippoan/cc-relay#35) Phase A: user-less endpoint variant.
// `GET /connect` (no `/u/<github_login>/` segment) lets a host-side binary
// connect without pinning its github_login in URL config — the DO id is
// derived from the JWT's `github_login` claim instead of the URL.
describe("handleMcpRelayConnect — user-less mode (ADR-003)", () => {
  it("uses jwt.github_login as DO key when user is null", async () => {
    const { env, idFromNameCalls, fetchCalls } = envWithDO();
    const jwt = await validJwt("yhonda-ohishi");
    const res = await handleMcpRelayConnect(
      wsReq({
        url: "https://mcp.test.example/connect",
        upgrade: "websocket",
        auth: `Bearer ${jwt}`,
      }),
      env,
      null,
    );
    expect(res.status).toBe(101);
    expect(idFromNameCalls).toEqual(["yhonda-ohishi"]);
    expect(fetchCalls).toHaveLength(1);
    expect(new URL(fetchCalls[0]!.url).pathname).toBe("/__connect");
  });

  it("does NOT 403 on user-less when JWT has any github_login (mismatch check is skipped)", async () => {
    const { env, idFromNameCalls } = envWithDO();
    const jwt = await validJwt("someone-else");
    const res = await handleMcpRelayConnect(
      wsReq({
        url: "https://mcp.test.example/connect",
        upgrade: "websocket",
        auth: `Bearer ${jwt}`,
      }),
      env,
      null,
    );
    expect(res.status).toBe(101);
    expect(idFromNameCalls).toEqual(["someone-else"]);
  });

  it("returns 401 (not 400) when user is null and Authorization is missing", async () => {
    const { env } = envWithDO();
    const res = await handleMcpRelayConnect(
      wsReq({ url: "https://mcp.test.example/connect", upgrade: "websocket" }),
      env,
      null,
    );
    expect(res.status).toBe(401);
  });
});

// issue #144: WS upgrade で Bearer <pair_code> を受け取って KV approve 状態を
// 確認できる path のテスト。
describe("handleMcpRelayConnect — pair_code path (issue #144)", () => {
  function envWithDOAndKv(
    stubFetch?: (req: Request) => Promise<Response>,
  ): {
    env: Env;
    kv: MockKV;
    idFromNameCalls: string[];
    fetchCalls: Request[];
  } {
    const { ns, idFromNameCalls, fetchCalls } = mockDONamespace(
      stubFetch ?? (async () => new Response(null, { status: 101 })),
    );
    const kv = createMockKV() as MockKV;
    const env = createMockEnv({
      MCP_JWT_SECRET: TEST_SECRET,
      MCP_SESSION_DO: ns,
      MCP_OAUTH_KV: kv,
    });
    return { env, kv, idFromNameCalls, fetchCalls };
  }

  function pairRec(overrides: Partial<PairRecord> = {}): PairRecord {
    const now = Date.now();
    return {
      pair_code: "PAIRCODE_x".padEnd(40, "x"),
      claim_login: "alice",
      binary_version: "v0.0.13",
      created_at: now,
      expires_at: now + PAIR_CODE_TTL_SEC * 1000,
      status: "approved",
      binding_jwt: "BINDING-JWT-VALUE",
      ...overrides,
    };
  }

  it("forwards approved pair_code as DO request with binding_jwt in Authorization", async () => {
    const { env, kv, idFromNameCalls, fetchCalls } = envWithDOAndKv();
    const rec = pairRec();
    await putPair(env, rec);
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: `Bearer ${rec.pair_code}` }),
      env,
      "alice",
    );
    expect(res.status).toBe(101);
    expect(idFromNameCalls).toEqual(["alice"]);
    expect(fetchCalls).toHaveLength(1);
    expect(fetchCalls[0]!.headers.get("Authorization")).toBe("Bearer BINDING-JWT-VALUE");
    // pair_code は使い捨てなので削除されている
    expect(kv._data[`mcp/pair/${rec.pair_code}`]).toBeUndefined();
  });

  it("returns 401 + Pair-Status: pending when status=pending", async () => {
    const { env, kv } = envWithDOAndKv();
    const rec = pairRec({ status: "pending", binding_jwt: null });
    await putPair(env, rec);
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: `Bearer ${rec.pair_code}` }),
      env,
      "alice",
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("Pair-Status")).toBe("pending");
    // WWW-Authenticate は付けない (device flow への fallback を防ぐ)
    expect(res.headers.get("WWW-Authenticate")).toBeNull();
    // pair_code は消されない (binary が retry できるよう保持)
    expect(kv._data[`mcp/pair/${rec.pair_code}`]).toBeDefined();
  });

  it("returns 401 + WWW-Authenticate when pair_code not found", async () => {
    const { env } = envWithDOAndKv();
    const code = "no-such-code-".padEnd(40, "x");
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: `Bearer ${code}` }),
      env,
      "alice",
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBeTruthy();
    expect(res.headers.get("Pair-Status")).toBeNull();
  });

  it("returns 401 when approved pair_code has null binding_jwt (defensive)", async () => {
    const { env } = envWithDOAndKv();
    const rec = pairRec({ status: "approved", binding_jwt: null });
    await putPair(env, rec);
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: `Bearer ${rec.pair_code}` }),
      env,
      "alice",
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBeTruthy();
  });

  it("returns 401 when token has invalid pair_code format (not base64url long enough)", async () => {
    const { env } = envWithDOAndKv();
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: "Bearer short" }),
      env,
      "alice",
    );
    expect(res.status).toBe(401);
  });

  it("returns 403 when pair claim_login does not match :user", async () => {
    const { env } = envWithDOAndKv();
    const rec = pairRec({ claim_login: "alice" });
    await putPair(env, rec);
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: `Bearer ${rec.pair_code}` }),
      env,
      "bob",
    );
    expect(res.status).toBe(403);
  });

  it("user-less mode: uses pair.claim_login as DO key", async () => {
    const { env, idFromNameCalls } = envWithDOAndKv();
    const rec = pairRec({ claim_login: "yhonda-ohishi" });
    await putPair(env, rec);
    const res = await handleMcpRelayConnect(
      wsReq({
        url: "https://mcp.test.example/connect",
        upgrade: "websocket",
        auth: `Bearer ${rec.pair_code}`,
      }),
      env,
      null,
    );
    expect(res.status).toBe(101);
    expect(idFromNameCalls).toEqual(["yhonda-ohishi"]);
  });

  it("deletes pair_code even when DO returns non-101 (still single-use)", async () => {
    const stubFetch = vi.fn(async () => new Response("nope", { status: 503 }));
    const { env, kv } = envWithDOAndKv(stubFetch);
    const rec = pairRec();
    await putPair(env, rec);
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: `Bearer ${rec.pair_code}` }),
      env,
      "alice",
    );
    expect(res.status).toBe(503);
    expect(kv._data[`mcp/pair/${rec.pair_code}`]).toBeUndefined();
  });

  // issue #157 Phase A: 101 response に Pair-Refresh-Token header を載せる
  it("attaches Pair-Refresh-Token + Pair-Refresh-Expires-In on 101 when pair has refresh_token", async () => {
    const { env } = envWithDOAndKv();
    const rec = pairRec({ refresh_token: "RT-opaque-43chars", refresh_token_expires_at: Date.now() + 1_000_000 });
    await putPair(env, rec);
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: `Bearer ${rec.pair_code}` }),
      env,
      "alice",
    );
    expect(res.status).toBe(101);
    expect(res.headers.get("Pair-Refresh-Token")).toBe("RT-opaque-43chars");
    expect(res.headers.get("Pair-Refresh-Expires-In")).toBe(String(30 * 24 * 60 * 60));
  });


  it("does NOT attach Pair-Refresh-Token when DO returns non-101 even if pair has refresh_token", async () => {
    const stubFetch = vi.fn(async () => new Response("err", { status: 503 }));
    const { env } = envWithDOAndKv(stubFetch);
    const rec = pairRec({ refresh_token: "RT", refresh_token_expires_at: Date.now() + 1_000_000 });
    await putPair(env, rec);
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: `Bearer ${rec.pair_code}` }),
      env,
      "alice",
    );
    expect(res.status).toBe(503);
    expect(res.headers.get("Pair-Refresh-Token")).toBeNull();
  });

  it("does NOT attach header for JWT path (no refresh_token in JWT auth)", async () => {
    const { env } = envWithDOAndKv();
    const jwt = await validJwt("alice");
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: `Bearer ${jwt}` }),
      env,
      "alice",
    );
    expect(res.status).toBe(101);
    expect(res.headers.get("Pair-Refresh-Token")).toBeNull();
  });

  it("does NOT attach header when pair has no refresh_token (legacy/pre-#157)", async () => {
    const { env } = envWithDOAndKv();
    const rec = pairRec(); // refresh_token undefined
    await putPair(env, rec);
    const res = await handleMcpRelayConnect(
      wsReq({ upgrade: "websocket", auth: `Bearer ${rec.pair_code}` }),
      env,
      "alice",
    );
    expect(res.status).toBe(101);
    expect(res.headers.get("Pair-Refresh-Token")).toBeNull();
  });
});
