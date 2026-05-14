/**
 * `handleMcpAuthorize` (RFC 6749 §4.1) unit test (Phase 5 / #128).
 */

import { describe, it, expect } from "vitest";
import { handleMcpAuthorize } from "../../src/handlers/mcp-authorize";
import { putDcrClient } from "../../src/lib/mcp-dcr";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

async function envWithRegisteredClient(
  redirectUris: string[] = ["https://claude.ai/cb"],
  client_id = "c-1",
): Promise<{ env: Env; kv: MockKV; client_id: string }> {
  const kv = createMockKV() as unknown as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    GITHUB_MCP_CLIENT_ID: "gh-test-id",
    OAUTH_STATE_SECRET: "test-state-secret-32chars!!!!!!!",
    AUTH_WORKER_ORIGIN: "https://auth.test.example",
  });
  await putDcrClient(env, {
    client_id,
    client_id_issued_at: 1_000_000,
    token_endpoint_auth_method: "none",
    response_types: ["code"],
    grant_types: ["authorization_code", "refresh_token"],
    redirect_uris: redirectUris,
  });
  return { env, kv, client_id };
}

function authorizeReq(params: Record<string, string>): Request {
  const u = new URL("https://mcp-staging.example/authorize");
  for (const [k, v] of Object.entries(params)) {
    u.searchParams.set(k, v);
  }
  return new Request(u.toString());
}

const validParams = (client_id: string): Record<string, string> => ({
  response_type: "code",
  client_id,
  redirect_uri: "https://claude.ai/cb",
  state: "csrf-1",
  code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  code_challenge_method: "S256",
  scope: "mcp.read mcp.write",
});

describe("handleMcpAuthorize — env / param validation (no redirect)", () => {
  it("returns 503 when MCP_OAUTH_KV not configured", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    const res = await handleMcpAuthorize(authorizeReq({}), env);
    expect(res.status).toBe(503);
  });

  it("returns 400 when client_id missing", async () => {
    const { env } = await envWithRegisteredClient();
    const params = validParams("c-1");
    delete (params as Record<string, string | undefined>)["client_id"];
    const res = await handleMcpAuthorize(authorizeReq(params as Record<string, string>), env);
    expect(res.status).toBe(400);
  });

  it("returns 400 invalid_client when client_id not registered", async () => {
    const { env } = await envWithRegisteredClient();
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams("c-1"), client_id: "unknown" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_client");
  });

  it("returns 400 when redirect_uri does not match registered uris", async () => {
    const { env, client_id } = await envWithRegisteredClient(["https://claude.ai/cb"]);
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams(client_id), redirect_uri: "https://attacker.example/cb" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_request");
  });
});

describe("handleMcpAuthorize — redirect-with-error path", () => {
  it("redirects with unsupported_response_type when response_type != code", async () => {
    const { env, client_id } = await envWithRegisteredClient();
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams(client_id), response_type: "token" }),
      env,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("unsupported_response_type");
    expect(loc.searchParams.get("state")).toBe("csrf-1");
  });

  it("redirects with invalid_request when code_challenge missing", async () => {
    const { env, client_id } = await envWithRegisteredClient();
    const params = validParams(client_id);
    delete (params as Record<string, string | undefined>)["code_challenge"];
    const res = await handleMcpAuthorize(authorizeReq(params as Record<string, string>), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("invalid_request");
    expect(loc.searchParams.get("error_description")).toMatch(/code_challenge/);
  });

  it("redirects with invalid_request when code_challenge_method != S256", async () => {
    const { env, client_id } = await envWithRegisteredClient();
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams(client_id), code_challenge_method: "plain" }),
      env,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("invalid_request");
  });
});

describe("handleMcpAuthorize — successful redirect to GitHub", () => {
  it("stores auth request in KV and redirects to GitHub OAuth with state HMAC", async () => {
    const { env, kv, client_id } = await envWithRegisteredClient();
    const res = await handleMcpAuthorize(authorizeReq(validParams(client_id)), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.host).toBe("github.com");
    expect(loc.pathname).toBe("/login/oauth/authorize");
    expect(loc.searchParams.get("client_id")).toBe("gh-test-id");
    expect(loc.searchParams.get("redirect_uri")).toBe(
      "https://auth.test.example/mcp/auth_callback",
    );
    expect(loc.searchParams.get("scope")).toBe("read:user");
    expect(loc.searchParams.get("state")).toBeTruthy();
    // KV に auth:request:* が 1 件入った
    const reqKey = Object.keys(kv._data).find((k) => k.startsWith("auth:request:"));
    expect(reqKey).toBeDefined();
    const stored = JSON.parse(kv._data[reqKey!]!) as {
      client_id: string;
      redirect_uri: string;
      code_challenge: string;
      client_state: string;
    };
    expect(stored.client_id).toBe(client_id);
    expect(stored.redirect_uri).toBe("https://claude.ai/cb");
    expect(stored.code_challenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    expect(stored.client_state).toBe("csrf-1");
  });

  // L79 (`scope ?? ""` の null branch) と success path で scope=空 の record 保存検証
  it("stores empty scope and succeeds when scope param is omitted", async () => {
    const { env, kv, client_id } = await envWithRegisteredClient();
    const params = validParams(client_id);
    delete (params as Record<string, string | undefined>)["scope"];
    const res = await handleMcpAuthorize(authorizeReq(params as Record<string, string>), env);
    expect(res.status).toBe(302);
    const reqKey = Object.keys(kv._data).find((k) => k.startsWith("auth:request:"))!;
    const stored = JSON.parse(kv._data[reqKey]!) as { scope: string };
    expect(stored.scope).toBe("");
  });
});

// L96/99/102 の `state || null` null branch + L78 (code_challenge_method ?? "")
// を 3 ケースで網羅。client_state を空にすると redirect URL に state は付かない。
describe("handleMcpAuthorize — error redirects with empty client state (?? + || branches)", () => {
  it("L96: response_type != code AND empty state → no state on redirect", async () => {
    const { env, client_id } = await envWithRegisteredClient();
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams(client_id), response_type: "token", state: "" }),
      env,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("unsupported_response_type");
    expect(loc.searchParams.has("state")).toBe(false);
  });

  it("L99: code_challenge missing AND empty state → no state on redirect", async () => {
    const { env, client_id } = await envWithRegisteredClient();
    const params = validParams(client_id);
    delete (params as Record<string, string | undefined>)["code_challenge"];
    params["state"] = "";
    const res = await handleMcpAuthorize(authorizeReq(params as Record<string, string>), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("invalid_request");
    expect(loc.searchParams.has("state")).toBe(false);
  });

  it("L78 + L102: code_challenge_method missing (defaults to '') AND empty state", async () => {
    const { env, client_id } = await envWithRegisteredClient();
    const params = validParams(client_id);
    delete (params as Record<string, string | undefined>)["code_challenge_method"];
    params["state"] = "";
    const res = await handleMcpAuthorize(authorizeReq(params as Record<string, string>), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("invalid_request");
    expect(loc.searchParams.has("state")).toBe(false);
  });
});

// `params.get(...) ?? ""` の null branch カバー (string-empty vs null は別 branch 扱い)
describe("handleMcpAuthorize — query param truly missing (?? null branch)", () => {
  it("response_type missing → defaults to '' → unsupported_response_type", async () => {
    const { env, client_id } = await envWithRegisteredClient();
    const params = validParams(client_id);
    delete (params as Record<string, string | undefined>)["response_type"];
    const res = await handleMcpAuthorize(authorizeReq(params as Record<string, string>), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("unsupported_response_type");
  });

  it("redirect_uri missing → 400 invalid_request (no redirect)", async () => {
    const { env, client_id } = await envWithRegisteredClient();
    const params = validParams(client_id);
    delete (params as Record<string, string | undefined>)["redirect_uri"];
    const res = await handleMcpAuthorize(authorizeReq(params as Record<string, string>), env);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("state missing → defaults to '' → success but no client_state on KV record", async () => {
    const { env, kv, client_id } = await envWithRegisteredClient();
    const params = validParams(client_id);
    delete (params as Record<string, string | undefined>)["state"];
    const res = await handleMcpAuthorize(authorizeReq(params as Record<string, string>), env);
    expect(res.status).toBe(302);
    const reqKey = Object.keys(kv._data).find((k) => k.startsWith("auth:request:"))!;
    const stored = JSON.parse(kv._data[reqKey]!) as { client_state: string };
    expect(stored.client_state).toBe("");
  });
});
