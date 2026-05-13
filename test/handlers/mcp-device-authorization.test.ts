import { describe, it, expect } from "vitest";
import { handleMcpDeviceAuthorization } from "../../src/handlers/mcp-device-authorization";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

/** RFC 8628 §3.1 準拠の form-encoded リクエストを組み立てる。
 *  Cloudflare Workers の Request.formData() は
 *  `application/x-www-form-urlencoded` を URLSearchParams body から parse する。 */
function formRequest(fields: Record<string, string>): Request {
  const body = new URLSearchParams(fields);
  return new Request("https://auth.test.example/mcp/device_authorization", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
}

function envWithKv(): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: "https://auth.test.example",
  });
  return { env, kv };
}

interface DeviceAuthResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

interface OAuthError {
  error: string;
  error_description?: string;
}

describe("POST /mcp/device_authorization — happy path", () => {
  it("returns RFC 8628 §3.2 response shape and writes both KV keys", async () => {
    const { env, kv } = envWithKv();
    const res = await handleMcpDeviceAuthorization(
      formRequest({ client_id: "github-mcp-server-rs", scope: "mcp.read mcp.write" }),
      env,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");

    const body = (await res.json()) as DeviceAuthResponse;
    expect(body.device_code).toMatch(/^[0-9a-f]{64}$/);
    expect(body.user_code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
    expect(body.verification_uri).toBe("https://auth.test.example/device");
    expect(body.verification_uri_complete).toBe(
      `https://auth.test.example/device?user_code=${encodeURIComponent(body.user_code)}`,
    );
    expect(body.expires_in).toBe(900);
    expect(body.interval).toBe(5);

    // 両 KV key 書込 + TTL 900s
    const storedJson = kv._data[`device_code:${body.device_code}`];
    expect(storedJson).toBeDefined();
    const stored = JSON.parse(storedJson as string);
    expect(stored.client_id).toBe("github-mcp-server-rs");
    expect(stored.scope).toBe("mcp.read mcp.write");
    expect(stored.status).toBe("pending");

    expect(kv._data[`user_code:${body.user_code}`]).toBe(body.device_code);
    expect(kv._ttls[`device_code:${body.device_code}`]).toBe(900);
    expect(kv._ttls[`user_code:${body.user_code}`]).toBe(900);
  });

  it("accepts request without scope (empty string stored)", async () => {
    const { env, kv } = envWithKv();
    const res = await handleMcpDeviceAuthorization(
      formRequest({ client_id: "github-mcp-server-rs" }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as DeviceAuthResponse;
    const storedJson = kv._data[`device_code:${body.device_code}`] as string;
    expect(JSON.parse(storedJson).scope).toBe("");
  });
});

describe("POST /mcp/device_authorization — error cases", () => {
  it("returns 503 server_error when MCP_OAUTH_KV is not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    const res = await handleMcpDeviceAuthorization(
      formRequest({ client_id: "foo" }),
      env,
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as OAuthError;
    expect(body.error).toBe("server_error");
    expect(body.error_description).toMatch(/not configured/);
  });

  it("returns 400 invalid_request when client_id is missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpDeviceAuthorization(formRequest({}), env);
    expect(res.status).toBe(400);
    const body = (await res.json()) as OAuthError;
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/client_id/);
  });

  it("returns 400 invalid_request when client_id is whitespace-only", async () => {
    const { env } = envWithKv();
    const res = await handleMcpDeviceAuthorization(formRequest({ client_id: "   " }), env);
    expect(res.status).toBe(400);
    const body = (await res.json()) as OAuthError;
    expect(body.error).toBe("invalid_request");
  });

  it("returns 400 invalid_request when body is JSON (not form-encoded)", async () => {
    const { env } = envWithKv();
    const req = new Request("https://auth.test.example/mcp/device_authorization", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: "foo" }),
    });
    const res = await handleMcpDeviceAuthorization(req, env);
    expect(res.status).toBe(400);
    const body = (await res.json()) as OAuthError;
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/form-urlencoded/);
  });
});
