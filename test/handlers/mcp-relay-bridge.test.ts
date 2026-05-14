/**
 * `handleMcpRelayBridge` unit test (issue #117 / Phase 6)。
 *
 * `POST /u/:user/mcp` の認証パス (JWT 検証 + user 一致) と DO への forward を検証する。
 * Phase 6 では DO 側が 503/501 を返すので、bridge 側はそのまま passthrough する
 * ことを確認する。
 */

import { describe, it, expect, vi } from "vitest";
import { handleMcpRelayBridge } from "../../src/handlers/mcp-relay-bridge";
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
    stubFetch ??
      (async () =>
        new Response(
          JSON.stringify({ error: "no_active_relay_session" }),
          { status: 503, headers: { "Content-Type": "application/json" } },
        )),
  );
  const env = createMockEnv({
    MCP_JWT_SECRET: TEST_SECRET,
    MCP_SESSION_DO: ns,
  });
  return { env, idFromNameCalls, fetchCalls };
}

async function validJwt(login = "alice"): Promise<string> {
  return signMcpJwt(
    { sub: `github:${login}`, github_login: login, scope: "mcp.read mcp.write", aud: AUD },
    TEST_SECRET,
    3600,
  );
}

function bridgeReq(opts: {
  auth?: string | null;
  body?: BodyInit | null;
  contentType?: string;
}): Request {
  const headers: Record<string, string> = {};
  if (opts.auth !== null && opts.auth !== undefined) headers.Authorization = opts.auth;
  if (opts.contentType !== undefined) headers["Content-Type"] = opts.contentType;
  return new Request("https://mcp.test.example/u/alice/mcp", {
    method: "POST",
    headers,
    body: opts.body ?? null,
  });
}

describe("handleMcpRelayBridge — env / pre-flight guards", () => {
  it("returns 503 when MCP_JWT_SECRET missing", async () => {
    const env = createMockEnv({ MCP_JWT_SECRET: undefined });
    const res = await handleMcpRelayBridge(bridgeReq({}), env, "alice");
    expect(res.status).toBe(503);
  });

  it("returns 503 when MCP_SESSION_DO binding missing", async () => {
    const env = createMockEnv({ MCP_JWT_SECRET: TEST_SECRET });
    const res = await handleMcpRelayBridge(bridgeReq({}), env, "alice");
    expect(res.status).toBe(503);
  });

  it("returns 400 when :user is empty", async () => {
    const { env } = envWithDO();
    const res = await handleMcpRelayBridge(bridgeReq({}), env, "");
    expect(res.status).toBe(400);
  });
});

describe("handleMcpRelayBridge — JWT authentication", () => {
  // Phase 4 / issue #126: 401 応答は MCP Authorization spec に従い
  // `WWW-Authenticate: Bearer realm="MCP", resource_metadata="..."` を持つ。
  // Anthropic Claude.ai client はこの header を見て AS metadata を発見する。
  const expectedWwwAuth =
    'Bearer realm="MCP", resource_metadata="https://auth.test.example/.well-known/oauth-protected-resource"';

  it("returns 401 + WWW-Authenticate when Authorization header missing", async () => {
    const { env } = envWithDO();
    const res = await handleMcpRelayBridge(bridgeReq({}), env, "alice");
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBe(expectedWwwAuth);
  });

  it("returns 401 + WWW-Authenticate when Authorization is not Bearer", async () => {
    const { env } = envWithDO();
    const res = await handleMcpRelayBridge(
      bridgeReq({ auth: "Basic xyz" }),
      env,
      "alice",
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBe(expectedWwwAuth);
  });

  it("returns 401 + WWW-Authenticate when JWT signature is invalid", async () => {
    const { env } = envWithDO();
    const res = await handleMcpRelayBridge(
      bridgeReq({ auth: "Bearer a.b.c" }),
      env,
      "alice",
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBe(expectedWwwAuth);
  });

  it("returns 403 when payload.github_login !== :user", async () => {
    const { env } = envWithDO();
    const jwt = await validJwt("alice");
    const res = await handleMcpRelayBridge(
      bridgeReq({ auth: `Bearer ${jwt}` }),
      env,
      "bob",
    );
    expect(res.status).toBe(403);
  });
});

describe("handleMcpRelayBridge — DO forwarding", () => {
  it("forwards to DO /__bridge with body + headers, passes status through (Phase 6 = 503)", async () => {
    const { env, idFromNameCalls, fetchCalls } = envWithDO();
    const jwt = await validJwt("alice");
    const res = await handleMcpRelayBridge(
      bridgeReq({
        auth: `Bearer ${jwt}`,
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
        contentType: "application/json",
      }),
      env,
      "alice",
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("no_active_relay_session");
    expect(idFromNameCalls).toEqual(["alice"]);
    expect(fetchCalls).toHaveLength(1);
    const forwarded = fetchCalls[0]!;
    expect(new URL(forwarded.url).pathname).toBe("/__bridge");
    expect(forwarded.headers.get("Authorization")).toBe(`Bearer ${jwt}`);
    expect(forwarded.headers.get("Content-Type")).toBe("application/json");
  });

  it("passes through DO's 501 'phase 7' when WS is active", async () => {
    const stubFetch = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ error: "bridge_not_implemented", phase: 7 }),
          { status: 501, headers: { "Content-Type": "application/json" } },
        ),
    );
    const { env } = envWithDO(stubFetch);
    const jwt = await validJwt("alice");
    const res = await handleMcpRelayBridge(
      bridgeReq({ auth: `Bearer ${jwt}` }),
      env,
      "alice",
    );
    expect(res.status).toBe(501);
    const body = (await res.json()) as { error: string; phase: number };
    expect(body.phase).toBe(7);
  });
});
