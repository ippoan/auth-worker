/**
 * `handleMcpRegister` (RFC 7591 DCR) unit test (Phase 5 / #128).
 */

import { describe, it, expect } from "vitest";
import { handleMcpRegister } from "../../src/handlers/mcp-register";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

function envWithKv(): { env: Env; kv: MockKV } {
  const kv = createMockKV() as unknown as MockKV;
  const env = createMockEnv({ MCP_OAUTH_KV: kv });
  return { env, kv: kv as MockKV };
}

function jsonReq(body: unknown): Request {
  return new Request("https://mcp-staging.example/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("handleMcpRegister — env / body validation", () => {
  it("returns 503 when MCP_OAUTH_KV not configured", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    const res = await handleMcpRegister(jsonReq({ redirect_uris: ["https://x.example/cb"] }), env);
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("server_error");
  });

  it("returns 400 invalid_client_metadata when body is not JSON", async () => {
    const { env } = envWithKv();
    const req = new Request("https://mcp-staging.example/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not-json",
    });
    const res = await handleMcpRegister(req, env);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_client_metadata");
  });

  it("returns 400 invalid_client_metadata when body is JSON but not an object", async () => {
    const { env } = envWithKv();
    const res = await handleMcpRegister(jsonReq("string-not-object"), env);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_client_metadata");
  });

  it("returns 400 invalid_redirect_uri when redirect_uris missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpRegister(jsonReq({ client_name: "X" }), env);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_redirect_uri");
  });

  it("returns 400 invalid_redirect_uri when redirect_uris is empty array", async () => {
    const { env } = envWithKv();
    const res = await handleMcpRegister(jsonReq({ redirect_uris: [] }), env);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_redirect_uri");
  });

  it("returns 400 invalid_redirect_uri when redirect_uris contains non-string", async () => {
    const { env } = envWithKv();
    const res = await handleMcpRegister(jsonReq({ redirect_uris: [123] }), env);
    expect(res.status).toBe(400);
  });

  it("returns 400 invalid_redirect_uri when redirect_uris contains http (non-localhost)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpRegister(
      jsonReq({ redirect_uris: ["http://example.com/cb"] }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 invalid_redirect_uri when redirect_uris contains malformed URL", async () => {
    const { env } = envWithKv();
    const res = await handleMcpRegister(
      jsonReq({ redirect_uris: ["not a url at all"] }),
      env,
    );
    expect(res.status).toBe(400);
  });
});

describe("handleMcpRegister — successful registration", () => {
  it("returns 201 with client_id + DCR record fields and stores in KV", async () => {
    const { env, kv } = envWithKv();
    const res = await handleMcpRegister(
      jsonReq({
        redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
        client_name: "Claude.ai",
        scope: "mcp.read mcp.write",
      }),
      env,
    );
    expect(res.status).toBe(201);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = (await res.json()) as {
      client_id: string;
      client_id_issued_at: number;
      token_endpoint_auth_method: string;
      grant_types: string[];
      response_types: string[];
      redirect_uris: string[];
      client_name: string;
      scope: string;
    };
    expect(body.client_id).toMatch(/^[0-9a-f]{8}-/);
    expect(body.token_endpoint_auth_method).toBe("none");
    expect(body.grant_types).toEqual(["authorization_code", "refresh_token"]);
    expect(body.response_types).toEqual(["code"]);
    expect(body.redirect_uris).toEqual(["https://claude.ai/api/mcp/auth_callback"]);
    expect(body.client_name).toBe("Claude.ai");
    expect(body.scope).toBe("mcp.read mcp.write");
    // KV に書かれている
    expect(kv._data[`dcr:client:${body.client_id}`]).toBeDefined();
  });

  it("accepts http://localhost as redirect_uri (dev tools)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpRegister(
      jsonReq({ redirect_uris: ["http://localhost:3000/cb"] }),
      env,
    );
    expect(res.status).toBe(201);
  });

  it("accepts http://127.0.0.1 as redirect_uri", async () => {
    const { env } = envWithKv();
    const res = await handleMcpRegister(
      jsonReq({ redirect_uris: ["http://127.0.0.1:8080/cb"] }),
      env,
    );
    expect(res.status).toBe(201);
  });

  it("omits client_name and scope when not provided", async () => {
    const { env } = envWithKv();
    const res = await handleMcpRegister(
      jsonReq({ redirect_uris: ["https://x.example/cb"] }),
      env,
    );
    const body = (await res.json()) as Record<string, unknown>;
    expect(body["client_name"]).toBeUndefined();
    expect(body["scope"]).toBeUndefined();
  });
});
