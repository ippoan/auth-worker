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
    // validParams() sends scope="mcp.read mcp.write" → GitHub repo grant (issue #130)
    expect(loc.searchParams.get("scope")).toBe("read:user repo");
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

  // L79 (`scope ?? ""` の null branch) と success path で scope 省略時の default decay 検証
  it("decays omitted scope to 'mcp.read' and requests GitHub 'read:user'", async () => {
    const { env, kv, client_id } = await envWithRegisteredClient();
    const params = validParams(client_id);
    delete (params as Record<string, string | undefined>)["scope"];
    const res = await handleMcpAuthorize(authorizeReq(params as Record<string, string>), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("scope")).toBe("read:user");
    const reqKey = Object.keys(kv._data).find((k) => k.startsWith("auth:request:"))!;
    const stored = JSON.parse(kv._data[reqKey]!) as { scope: string };
    expect(stored.scope).toBe("mcp.read");
  });

  it("normalizes scope=mcp.write to KV 'mcp.write' and GitHub 'read:user repo' (issue #130)", async () => {
    const { env, kv, client_id } = await envWithRegisteredClient();
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams(client_id), scope: "mcp.write" }),
      env,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("scope")).toBe("read:user repo");
    const reqKey = Object.keys(kv._data).find((k) => k.startsWith("auth:request:"))!;
    const stored = JSON.parse(kv._data[reqKey]!) as { scope: string };
    expect(stored.scope).toBe("mcp.write");
  });

  it("drops unknown scope tokens and decays to 'mcp.read'", async () => {
    const { env, kv, client_id } = await envWithRegisteredClient();
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams(client_id), scope: "garbage" }),
      env,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("scope")).toBe("read:user");
    const reqKey = Object.keys(kv._data).find((k) => k.startsWith("auth:request:"))!;
    const stored = JSON.parse(kv._data[reqKey]!) as { scope: string };
    expect(stored.scope).toBe("mcp.read");
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

// RFC 8707 Resource Indicators (MCP Authorization spec 2025-06-18)
// `mcp-staging.example` host で `AUTH_WORKER_ORIGIN=https://auth.test.example`
// → `mcpRelayOrigin(env)` = `https://mcp.test.example` (mcp-origins.ts の derive 規約)
describe("handleMcpAuthorize — RFC 8707 resource parameter", () => {
  // mcpRelayOrigin(env) は `auth-` → `mcp-` の置換で導出。test env では
  // `auth.test.example` → `mcp.test.example`。
  const RELAY_ORIGIN = "https://mcp.test.example";

  it("stores resource on AuthRequestRecord when origin matches (path included)", async () => {
    const { env, kv, client_id } = await envWithRegisteredClient();
    // Anthropic Claude.ai は MCP server URL のフルパス (例 `/mcp`) を送る。
    const withPath = `${RELAY_ORIGIN}/mcp`;
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams(client_id), resource: withPath }),
      env,
    );
    expect(res.status).toBe(302);
    const reqKey = Object.keys(kv._data).find((k) => k.startsWith("auth:request:"))!;
    const stored = JSON.parse(kv._data[reqKey]!) as { resource?: string };
    // 送信値をそのまま echo (Anthropic 側 aud 検証用)。
    expect(stored.resource).toBe(withPath);
  });

  it("accepts origin-only resource (no path)", async () => {
    const { env, kv, client_id } = await envWithRegisteredClient();
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams(client_id), resource: RELAY_ORIGIN }),
      env,
    );
    expect(res.status).toBe(302);
    const reqKey = Object.keys(kv._data).find((k) => k.startsWith("auth:request:"))!;
    const stored = JSON.parse(kv._data[reqKey]!) as { resource?: string };
    expect(stored.resource).toBe(RELAY_ORIGIN);
  });

  it("redirects with invalid_target when resource origin does not match", async () => {
    const { env, client_id } = await envWithRegisteredClient();
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams(client_id), resource: "https://attacker.example/mcp" }),
      env,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.origin + loc.pathname).toBe("https://claude.ai/cb");
    expect(loc.searchParams.get("error")).toBe("invalid_target");
    expect(loc.searchParams.get("state")).toBe("csrf-1");
  });

  it("redirects with invalid_target when resource is not a valid URL", async () => {
    const { env, client_id } = await envWithRegisteredClient();
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams(client_id), resource: "not a url" }),
      env,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("invalid_target");
  });

  it("invalid_target redirect drops state when client_state is empty", async () => {
    const { env, client_id } = await envWithRegisteredClient();
    const res = await handleMcpAuthorize(
      authorizeReq({
        ...validParams(client_id),
        resource: "https://attacker.example/mcp",
        state: "",
      }),
      env,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("invalid_target");
    expect(loc.searchParams.has("state")).toBe(false);
  });

  it("omits resource from KV record when client does not send it (legacy path)", async () => {
    const { env, kv, client_id } = await envWithRegisteredClient();
    const res = await handleMcpAuthorize(authorizeReq(validParams(client_id)), env);
    expect(res.status).toBe(302);
    const reqKey = Object.keys(kv._data).find((k) => k.startsWith("auth:request:"))!;
    const stored = JSON.parse(kv._data[reqKey]!) as { resource?: string };
    expect(stored.resource).toBeUndefined();
  });

  // ippoan/secrets-inventory#45: MCP relay 以外の RS (= secrets-inventory worker
  // など、独立 host) を `MCP_RESOURCE_ORIGINS_ALLOWLIST` env で許容する分岐。
  // 旧来 mcpRelayOrigin のみ許容 → secrets-inventory MCP に audience 焼けない
  // 問題を fix。
  it("accepts resource origin listed in MCP_RESOURCE_ORIGINS_ALLOWLIST", async () => {
    const kv = createMockKV() as unknown as MockKV;
    const env = createMockEnv({
      MCP_OAUTH_KV: kv,
      GITHUB_MCP_CLIENT_ID: "gh-test-id",
      OAUTH_STATE_SECRET: "test-state-secret-32chars!!!!!!!",
      AUTH_WORKER_ORIGIN: "https://auth.test.example",
      MCP_RESOURCE_ORIGINS_ALLOWLIST: "https://security-inventory.ippoan.org",
    } as unknown as Partial<Env>);
    await putDcrClient(env, {
      client_id: "c-1",
      client_id_issued_at: 1_000_000,
      token_endpoint_auth_method: "none",
      response_types: ["code"],
      grant_types: ["authorization_code", "refresh_token"],
      redirect_uris: ["https://claude.ai/cb"],
    });
    const resourceUrl = "https://security-inventory.ippoan.org/mcp";
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams("c-1"), resource: resourceUrl }),
      env,
    );
    expect(res.status).toBe(302);
    // GitHub OAuth に redirect されているはず (= invalid_target エラーではない)
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.host).toBe("github.com");
    const reqKey = Object.keys(kv._data).find((k) => k.startsWith("auth:request:"))!;
    const stored = JSON.parse(kv._data[reqKey]!) as { resource?: string };
    expect(stored.resource).toBe(resourceUrl);
  });
});

// MCP OAuth に Google IdP を追加。resource origin が MCP_RESOURCE_GOOGLE_ORIGINS に
// 列挙されている時だけ Google に redirect する分岐を検証する。
describe("handleMcpAuthorize — Google IdP branch (MCP OAuth に Google IdP を追加)", () => {
  const RELAY_ORIGIN = "https://mcp.test.example";
  const GOOGLE_RESOURCE = `${RELAY_ORIGIN}/kyuyo`;

  async function envWithGoogleOrigin(
    overrides: Partial<Env> = {},
  ): Promise<{ env: Env; kv: MockKV; client_id: string }> {
    const kv = createMockKV() as unknown as MockKV;
    const env = createMockEnv({
      MCP_OAUTH_KV: kv,
      GITHUB_MCP_CLIENT_ID: "gh-test-id",
      GOOGLE_CLIENT_ID: "google-test-id",
      OAUTH_STATE_SECRET: "test-state-secret-32chars!!!!!!!",
      AUTH_WORKER_ORIGIN: "https://auth.test.example",
      MCP_RESOURCE_ORIGINS_ALLOWLIST: RELAY_ORIGIN,
      MCP_RESOURCE_GOOGLE_ORIGINS: RELAY_ORIGIN,
      ...overrides,
    } as unknown as Partial<Env>);
    await putDcrClient(env, {
      client_id: "c-1",
      client_id_issued_at: 1_000_000,
      token_endpoint_auth_method: "none",
      response_types: ["code"],
      grant_types: ["authorization_code", "refresh_token"],
      redirect_uris: ["https://claude.ai/cb"],
    });
    return { env, kv, client_id: "c-1" };
  }

  it("redirects to accounts.google.com with openid email scope for a Google-listed resource origin", async () => {
    const { env, kv, client_id } = await envWithGoogleOrigin();
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams(client_id), resource: GOOGLE_RESOURCE }),
      env,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.host).toBe("accounts.google.com");
    expect(loc.pathname).toBe("/o/oauth2/v2/auth");
    expect(loc.searchParams.get("client_id")).toBe("google-test-id");
    expect(loc.searchParams.get("redirect_uri")).toBe(
      "https://auth.test.example/mcp/auth_callback_google",
    );
    expect(loc.searchParams.get("response_type")).toBe("code");
    expect(loc.searchParams.get("scope")).toBe("openid email");
    expect(loc.searchParams.get("state")).toBeTruthy();
    const reqKey = Object.keys(kv._data).find((k) => k.startsWith("auth:request:"))!;
    const stored = JSON.parse(kv._data[reqKey]!) as { resource?: string };
    expect(stored.resource).toBe(GOOGLE_RESOURCE);
  });

  it("still redirects to GitHub when resource origin is allowed but not in MCP_RESOURCE_GOOGLE_ORIGINS", async () => {
    const { env, client_id } = await envWithGoogleOrigin({
      MCP_RESOURCE_GOOGLE_ORIGINS: "https://someone-else.ippoan.org",
    } as unknown as Partial<Env>);
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams(client_id), resource: GOOGLE_RESOURCE }),
      env,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.host).toBe("github.com");
  });

  it("returns 503 when routed to Google but GOOGLE_CLIENT_ID is missing", async () => {
    const { env, client_id } = await envWithGoogleOrigin({ GOOGLE_CLIENT_ID: undefined });
    const res = await handleMcpAuthorize(
      authorizeReq({ ...validParams(client_id), resource: GOOGLE_RESOURCE }),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("does not write an auth:request KV record when Google client id is missing (guard before KV write)", async () => {
    const { env, kv, client_id } = await envWithGoogleOrigin({ GOOGLE_CLIENT_ID: undefined });
    await handleMcpAuthorize(
      authorizeReq({ ...validParams(client_id), resource: GOOGLE_RESOURCE }),
      env,
    );
    const reqKey = Object.keys(kv._data).find((k) => k.startsWith("auth:request:"));
    expect(reqKey).toBeUndefined();
  });

  it("returns 503 when routed to GitHub (default) but GITHUB_MCP_CLIENT_ID is missing", async () => {
    const { env, client_id } = await envWithGoogleOrigin({ GITHUB_MCP_CLIENT_ID: undefined });
    const res = await handleMcpAuthorize(authorizeReq(validParams(client_id)), env);
    expect(res.status).toBe(503);
  });

  // issue #438: Google IdP surface (`/mcp/google/authorize` → idpDefault: "google")。
  // claude.ai custom connector は resource を送らないため、resource 無しでも
  // Google に振れることを検証する。既定 surface (opts 無し) は GitHub のまま。
  describe("idpDefault: 'google' (issue #438 Google IdP surface)", () => {
    it("redirects to accounts.google.com without any resource parameter", async () => {
      const { env, kv, client_id } = await envWithGoogleOrigin({
        MCP_RESOURCE_GOOGLE_ORIGINS: "",
      } as unknown as Partial<Env>);
      const res = await handleMcpAuthorize(
        authorizeReq(validParams(client_id)),
        env,
        { idpDefault: "google" },
      );
      expect(res.status).toBe(302);
      const loc = new URL(res.headers.get("Location")!);
      expect(loc.host).toBe("accounts.google.com");
      expect(loc.searchParams.get("scope")).toBe("openid email");
      // resource 未指定なので auth request record にも resource は積まれない
      const reqKey = Object.keys(kv._data).find((k) => k.startsWith("auth:request:"))!;
      const stored = JSON.parse(kv._data[reqKey]!) as { resource?: string };
      expect(stored.resource).toBeUndefined();
    });

    it("keeps google even when an allowed resource origin is NOT in MCP_RESOURCE_GOOGLE_ORIGINS (surface default wins)", async () => {
      const { env, kv, client_id } = await envWithGoogleOrigin({
        MCP_RESOURCE_GOOGLE_ORIGINS: "",
      } as unknown as Partial<Env>);
      const res = await handleMcpAuthorize(
        authorizeReq({ ...validParams(client_id), resource: GOOGLE_RESOURCE }),
        env,
        { idpDefault: "google" },
      );
      expect(res.status).toBe(302);
      const loc = new URL(res.headers.get("Location")!);
      expect(loc.host).toBe("accounts.google.com");
      // resource は record に echo される (token aud binding 用)
      const reqKey = Object.keys(kv._data).find((k) => k.startsWith("auth:request:"))!;
      const stored = JSON.parse(kv._data[reqKey]!) as { resource?: string };
      expect(stored.resource).toBe(GOOGLE_RESOURCE);
    });

    it("accepts resource = <auth origin>/mcp/google (the google-surface PRM resource)", async () => {
      const { env, client_id } = await envWithGoogleOrigin({
        MCP_RESOURCE_GOOGLE_ORIGINS: "",
      } as unknown as Partial<Env>);
      const res = await handleMcpAuthorize(
        authorizeReq({
          ...validParams(client_id),
          resource: "https://auth.test.example/mcp/google",
        }),
        env,
        { idpDefault: "google" },
      );
      expect(res.status).toBe(302);
      const loc = new URL(res.headers.get("Location")!);
      expect(loc.host).toBe("accounts.google.com");
    });

    it("explicit idpDefault: 'github' behaves like the default surface (no resource → GitHub)", async () => {
      const { env, client_id } = await envWithGoogleOrigin({
        MCP_RESOURCE_GOOGLE_ORIGINS: "",
      } as unknown as Partial<Env>);
      const res = await handleMcpAuthorize(
        authorizeReq(validParams(client_id)),
        env,
        { idpDefault: "github" },
      );
      expect(res.status).toBe(302);
      const loc = new URL(res.headers.get("Location")!);
      expect(loc.host).toBe("github.com");
    });
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
