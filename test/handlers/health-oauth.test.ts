/**
 * Tests for handleHealthOAuth (issue #209 — 4-provider probe).
 *
 * 外部 provider を実際に叩かないよう、fetch を URL ベースで mock する。
 *
 * 各 probe の役割:
 *   - google     : client_id 生死を判定 (mode = "client_id_check")
 *   - github_mcp : reachability のみ (GitHub は client_id 正否で挙動が変わらない)
 *   - lineworks  : rust-alc-api の reachability のみ
 *   - egov       : Keycloak well-known の reachability + JSON 整合性
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { Env } from "../../src/index";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import { handleHealthOAuth } from "../../src/handlers/health-oauth";

async function authedRequest(): Promise<Request> {
  const token = await signTestJwt({ sub: "ci" }, TEST_JWT_SECRET);
  return new Request("https://auth.test.example/health/oauth", {
    headers: { Authorization: `Bearer ${token}` },
  });
}

type ProbeMode = "client_id_check" | "reachability" | "secret_check";
type ProbeResultJson =
  | { configured: false }
  | { configured: true; ok: boolean; status: number; mode: ProbeMode; hint?: string }
  | { configured: true; unknown: true; mode: ProbeMode; hint: string };

interface OAuthBody {
  checked_at: string;
  overall: "ok" | "degraded" | "unknown";
  providers: {
    google: ProbeResultJson;
    google_secret: ProbeResultJson;
    github_mcp: ProbeResultJson;
    github_mcp_secret: ProbeResultJson;
    lineworks: ProbeResultJson;
    egov: ProbeResultJson;
  };
}

/** デフォルトで全 provider が ok を返すような happy-path Response 群。 */
function defaultResponses(): Record<string, Response> {
  return {
    google: new Response(null, {
      status: 302,
      headers: { Location: "https://accounts.google.com/v3/signin/identifier?client_id=x" },
    }),
    // google token endpoint: creds OK + code bad => 400 invalid_grant
    google_token: new Response(
      JSON.stringify({ error: "invalid_grant", error_description: "Bad Request" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    ),
    github: new Response(null, {
      status: 302,
      headers: { Location: "https://github.com/login?client_id=x&return_to=..." },
    }),
    // github token endpoint: creds OK + code bad => 200 bad_verification_code
    github_token: new Response(
      JSON.stringify({ error: "bad_verification_code" }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ),
    // パラメータ無しで叩いた時の rust-alc-api 期待応答。
    lineworks: new Response("Missing parameters", { status: 400 }),
    egov: new Response(
      JSON.stringify({
        issuer: "https://egov.test.example/auth/realms/test",
        authorization_endpoint: "https://egov.test.example/auth/realms/test/protocol/openid-connect/auth",
        token_endpoint: "https://egov.test.example/auth/realms/test/protocol/openid-connect/token",
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ),
  };
}

/** URL host / path で probe 先を識別して mock を返す。
 *  値が `Error` の場合は throw される (fetch 失敗の模擬)。
 *  各 probe は 1 リクエストしか発行しないので Response を clone しなくて良い。 */
function setupFetch(overrides: Partial<{
  google: Response | Error;
  google_token: Response | Error;
  github: Response | Error;
  github_token: Response | Error;
  lineworks: Response | Error;
  egov: Response | Error;
}> = {}): void {
  const merged: Record<string, Response | Error> = {
    ...defaultResponses(),
    ...overrides,
  };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    let key: string | undefined;
    if (url.includes("oauth2.googleapis.com/token")) key = "google_token";
    else if (url.includes("accounts.google.com")) key = "google";
    else if (url.includes("github.com/login/oauth/access_token")) key = "github_token";
    else if (url.includes("github.com")) key = "github";
    else if (url.includes("/api/auth/lineworks/redirect")) key = "lineworks";
    else if (url.includes(".well-known/openid-configuration")) key = "egov";
    if (!key) throw new Error(`unexpected fetch URL: ${url}`);
    const r = merged[key];
    if (!r) throw new Error(`no mock for fetch URL: ${url}`);
    if (r instanceof Error) throw r;
    return r;
  }));
}

/** 全 provider が configured になる env を返す。デフォルト env は github_mcp / egov 未設定。
 *  GITHUB_MCP_CLIENT_SECRET も含めることで github_mcp_secret probe が configured 扱いになる。
 *  GOOGLE_CLIENT_SECRET は createMockEnv のデフォで既に設定済。 */
function envAllConfigured(extra: Partial<Env> = {}): Env {
  return createMockEnv({
    GITHUB_MCP_CLIENT_ID: "Iv1.testgithubclient",
    GITHUB_MCP_CLIENT_SECRET: "test-github-mcp-secret",
    EGOV_CLIENT_ID: "egov-test-client",
    EGOV_AUTH_BASE: "https://egov.test.example/auth/realms/test",
    ...extra,
  });
}

describe("handleHealthOAuth", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // auth guard
  // -------------------------------------------------------------------------

  it("returns 503 when JWT_SECRET is empty (fail-closed)", async () => {
    const env = createMockEnv({ JWT_SECRET: "" });
    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(503);
    expect(await res.text()).toBe("server not configured");
  });

  it("returns 401 when Authorization header is missing", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/health/oauth");
    const res = await handleHealthOAuth(req, env);
    expect(res.status).toBe(401);
  });

  it("returns 401 when Bearer token signature is invalid", async () => {
    const env = createMockEnv();
    const badToken = await signTestJwt({ sub: "ci" }, "wrong-secret");
    const req = new Request("https://auth.test.example/health/oauth", {
      headers: { Authorization: `Bearer ${badToken}` },
    });
    const res = await handleHealthOAuth(req, env);
    expect(res.status).toBe(401);
  });

  it("returns 401 when header has Bearer but no token", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/health/oauth", {
      headers: { Authorization: "Basic xxx" },
    });
    const res = await handleHealthOAuth(req, env);
    expect(res.status).toBe(401);
  });

  // -------------------------------------------------------------------------
  // overall response shape
  // -------------------------------------------------------------------------

  it("returns overall:ok with all 6 probes configured and healthy", async () => {
    setupFetch();
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(200);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("ok");
    expect(typeof body.checked_at).toBe("string");
    // mode が各 probe で正しく出る
    expect((body.providers.google as { mode: ProbeMode }).mode).toBe("client_id_check");
    expect((body.providers.google_secret as { mode: ProbeMode }).mode).toBe("secret_check");
    expect((body.providers.github_mcp as { mode: ProbeMode }).mode).toBe("reachability");
    expect((body.providers.github_mcp_secret as { mode: ProbeMode }).mode).toBe("secret_check");
    expect((body.providers.lineworks as { mode: ProbeMode }).mode).toBe("reachability");
    expect((body.providers.egov as { mode: ProbeMode }).mode).toBe("reachability");
  });

  it("reports skip (configured:false) for unset providers without calling fetch for them", async () => {
    // default env: GITHUB_MCP_CLIENT_ID / EGOV_* 未設定。Google + lineworks のみ probe される。
    setupFetch();
    const env = createMockEnv();
    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(200);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("ok");
    expect(body.providers.github_mcp).toEqual({ configured: false });
    expect(body.providers.egov).toEqual({ configured: false });
  });

  it("reports skip for lineworks when ALC_API_ORIGIN is empty", async () => {
    setupFetch();
    const env = createMockEnv({ ALC_API_ORIGIN: "" });
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    expect(body.providers.lineworks).toEqual({ configured: false });
  });

  it("reports skip for egov when only EGOV_CLIENT_ID is set but EGOV_AUTH_BASE is missing", async () => {
    setupFetch();
    const env = createMockEnv({ EGOV_CLIENT_ID: "x" });
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    expect(body.providers.egov).toEqual({ configured: false });
  });

  it("reports skip for google when GOOGLE_CLIENT_ID is empty", async () => {
    setupFetch();
    const env = createMockEnv({ GOOGLE_CLIENT_ID: "" });
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    expect(body.providers.google).toEqual({ configured: false });
  });

  // -------------------------------------------------------------------------
  // google probe — client_id_check mode
  // -------------------------------------------------------------------------

  it("google: ok when 302 to /v3/signin/identifier (real happy-path)", async () => {
    setupFetch();
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google;
    if (!("ok" in g)) throw new Error("expected ok variant");
    expect(g.ok).toBe(true);
    expect(g.mode).toBe("client_id_check");
    expect(g.status).toBe(302);
  });

  it("google: degraded when 302 to /signin/oauth/error?authError= (real invalid_client)", async () => {
    setupFetch({
      google: new Response(null, {
        status: 302,
        headers: {
          Location:
            "https://accounts.google.com/signin/oauth/error?authError=Cg5pbnZhbGlkX2NsaWVudBI&flowName=GeneralOAuthFlow",
        },
      }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(503);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("degraded");
    const g = body.providers.google;
    if (!("ok" in g)) throw new Error("expected ok variant");
    expect(g.ok).toBe(false);
    expect(g.hint).toMatch(/client_id/);
  });

  it("google: degraded when Location has plain error= query (defensive)", async () => {
    setupFetch({
      google: new Response(null, {
        status: 302,
        headers: { Location: "https://accounts.google.com/o/oauth2/v2/auth?error=invalid_client" },
      }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(503);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google;
    if (!("ok" in g)) throw new Error("expected ok variant");
    expect(g.ok).toBe(false);
  });

  it("google: unknown when 30x redirects to an unexpected host", async () => {
    setupFetch({
      google: new Response(null, {
        status: 302,
        headers: { Location: "https://accounts.google.example/somewhere" },
      }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("unknown");
    const g = body.providers.google;
    if (!("unknown" in g)) throw new Error("expected unknown variant");
    expect(g.hint).toMatch(/accounts\.google\.example/);
  });

  it("google: unknown when 30x Location is a malformed URL", async () => {
    setupFetch({
      google: new Response(null, { status: 302, headers: { Location: "not a url" } }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google;
    if (!("unknown" in g)) throw new Error("expected unknown variant");
    expect(g.hint).toMatch(/malformed Location/);
  });

  it("google: degraded when 400 with 'OAuth client was not found' body (defensive)", async () => {
    setupFetch({
      google: new Response(
        "<html>Error 401 — The OAuth client was not found.</html>",
        { status: 400 },
      ),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google;
    if (!("ok" in g)) throw new Error("expected ok variant");
    expect(g.ok).toBe(false);
    expect(g.status).toBe(400);
  });

  it("google: degraded when 200 with invalid_client error body (defensive)", async () => {
    setupFetch({
      google: new Response("error=invalid_client", { status: 200 }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google;
    if (!("ok" in g)) throw new Error("expected ok variant");
    expect(g.ok).toBe(false);
  });

  it("google: unknown when status 2xx is non-redirect with no error markers", async () => {
    setupFetch({
      google: new Response("totally fine", { status: 200 }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("unknown");
    const g = body.providers.google;
    if (!("unknown" in g)) throw new Error("expected unknown variant");
    expect(g.hint).toMatch(/unexpected status 200/);
  });

  it("google: unknown when fetch itself throws (network/timeout)", async () => {
    setupFetch({ google: new Error("timeout") });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google;
    if (!("unknown" in g)) throw new Error("expected unknown variant");
    expect(g.hint).toMatch(/timeout/);
  });

  it("google: tolerates body.text() throwing when sniffing error body", async () => {
    const broken = new Response("placeholder", { status: 400 });
    (broken as unknown as { text: () => Promise<string> }).text = () => {
      throw new Error("body read failed");
    };
    setupFetch({ google: broken });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google;
    if (!("ok" in g)) throw new Error("expected ok variant");
    expect(g.ok).toBe(false);
  });

  it("google: unknown when 30x has no Location header at all", async () => {
    // 30x branch is gated by `loc` being non-empty; without Location we fall
    // through to the body-sniff path and end up as `unknown`.
    setupFetch({
      google: new Response("", { status: 302 }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google;
    if (!("unknown" in g)) throw new Error("expected unknown variant");
    expect(g.hint).toMatch(/unexpected status 302/);
  });

  it("google: handles fetch throwing a non-Error value", async () => {
    setupFetch({
      // simulate `throw "network down"` (string thrown, not Error)
      google: { _notError: true } as unknown as Error,
    });
    // The setupFetch helper only `throw`s when r instanceof Error, so we need
    // a different path: stub fetch directly so it rejects with a non-Error.
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw "network down";
    }));
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google;
    if (!("unknown" in g)) throw new Error("expected unknown variant");
    expect(g.hint).toContain("network down");
  });

  // -------------------------------------------------------------------------
  // google_secret probe — secret_check mode (POST /token with invalid code)
  // -------------------------------------------------------------------------

  it("google_secret: ok when token endpoint returns 400 invalid_grant (creds accepted)", async () => {
    setupFetch();
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google_secret as { ok: boolean; status: number };
    expect(g.ok).toBe(true);
    expect(g.status).toBe(400);
  });

  it("google_secret: degraded when token endpoint returns 401 invalid_client (creds drift)", async () => {
    setupFetch({
      google_token: new Response(
        JSON.stringify({ error: "invalid_client", error_description: "The OAuth client was not found." }),
        { status: 401, headers: { "Content-Type": "application/json" } },
      ),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(503);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google_secret as { ok: boolean; status: number; hint: string };
    expect(g.ok).toBe(false);
    expect(g.status).toBe(401);
    expect(g.hint).toContain("invalid_client");
  });

  it("google_secret: unknown when token endpoint returns unexpected status", async () => {
    setupFetch({
      google_token: new Response(JSON.stringify({ error: "server_error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google_secret as { unknown: boolean; hint: string };
    expect(g.unknown).toBe(true);
    expect(g.hint).toContain("500");
  });

  it("google_secret: unknown when token body is not JSON", async () => {
    setupFetch({
      google_token: new Response("not json", { status: 400 }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google_secret as { unknown: boolean };
    expect(g.unknown).toBe(true);
  });

  it("google_secret: unknown when fetch throws", async () => {
    setupFetch({ google_token: new Error("ECONNRESET") });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google_secret as { unknown: boolean; hint: string };
    expect(g.unknown).toBe(true);
    expect(g.hint).toContain("ECONNRESET");
  });

  it("google_secret: skip when GOOGLE_CLIENT_SECRET is empty", async () => {
    setupFetch();
    const env = envAllConfigured({ GOOGLE_CLIENT_SECRET: "" });
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    expect(body.providers.google_secret).toEqual({ configured: false });
  });

  // -------------------------------------------------------------------------
  // github_mcp probe — reachability only
  // -------------------------------------------------------------------------

  it("github_mcp: ok when 302 to github.com host (any path, reachability)", async () => {
    setupFetch();
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.github_mcp;
    if (!("ok" in g)) throw new Error("expected ok variant");
    expect(g.ok).toBe(true);
    expect(g.mode).toBe("reachability");
  });

  it("github_mcp: unknown when 30x redirects off github.com", async () => {
    setupFetch({
      github: new Response(null, {
        status: 302,
        headers: { Location: "https://something-else.example/foo" },
      }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.github_mcp;
    if (!("unknown" in g)) throw new Error("expected unknown variant");
    expect(g.hint).toMatch(/something-else\.example/);
  });

  it("github_mcp: unknown when Location is malformed URL", async () => {
    setupFetch({
      github: new Response(null, { status: 302, headers: { Location: "not-a-url" } }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.github_mcp;
    if (!("unknown" in g)) throw new Error("expected unknown variant");
    expect(g.hint).toMatch(/malformed Location/);
  });

  it("github_mcp: degraded when GitHub returns 5xx (provider down)", async () => {
    setupFetch({
      github: new Response("internal error", { status: 503 }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(503);
    const body = await res.json() as OAuthBody;
    const g = body.providers.github_mcp;
    if (!("ok" in g)) throw new Error("expected ok variant");
    expect(g.ok).toBe(false);
    expect(g.hint).toMatch(/expected 30x/);
  });

  it("github_mcp: unknown on fetch error", async () => {
    setupFetch({ github: new Error("conn reset") });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.github_mcp;
    if (!("unknown" in g)) throw new Error("expected unknown variant");
    expect(g.hint).toMatch(/conn reset/);
  });

  // -------------------------------------------------------------------------
  // github_mcp_secret probe — secret_check mode
  // -------------------------------------------------------------------------

  it("github_mcp_secret: ok when 200 bad_verification_code (creds accepted)", async () => {
    setupFetch();
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.github_mcp_secret as { ok: boolean; status: number };
    expect(g.ok).toBe(true);
    expect(g.status).toBe(200);
  });

  it("github_mcp_secret: degraded when 200 incorrect_client_credentials (creds drift)", async () => {
    setupFetch({
      github_token: new Response(
        JSON.stringify({ error: "incorrect_client_credentials" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(503);
    const body = await res.json() as OAuthBody;
    const g = body.providers.github_mcp_secret as { ok: boolean; hint: string };
    expect(g.ok).toBe(false);
    expect(g.hint).toContain("incorrect_client_credentials");
  });

  it("github_mcp_secret: unknown when body has unexpected error", async () => {
    setupFetch({
      github_token: new Response(JSON.stringify({ error: "unknown_error" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.github_mcp_secret as { unknown: boolean };
    expect(g.unknown).toBe(true);
  });

  it("github_mcp_secret: unknown on fetch error", async () => {
    setupFetch({ github_token: new Error("timeout") });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.github_mcp_secret as { unknown: boolean; hint: string };
    expect(g.unknown).toBe(true);
    expect(g.hint).toContain("timeout");
  });

  it("github_mcp_secret: skip when GITHUB_MCP_CLIENT_SECRET is missing", async () => {
    setupFetch();
    const env = envAllConfigured({ GITHUB_MCP_CLIENT_SECRET: undefined });
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    expect(body.providers.github_mcp_secret).toEqual({ configured: false });
  });

  // -------------------------------------------------------------------------
  // lineworks probe — reachability of rust-alc-api lineworks route
  // -------------------------------------------------------------------------

  it("lineworks: ok when rust-alc-api returns 400 (params missing — route alive)", async () => {
    setupFetch();
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const lw = body.providers.lineworks;
    if (!("ok" in lw)) throw new Error("expected ok variant");
    expect(lw.ok).toBe(true);
    expect(lw.mode).toBe("reachability");
    expect(lw.status).toBe(400);
  });

  it("lineworks: ok also on 422 (other validation framework)", async () => {
    setupFetch({ lineworks: new Response("validation error", { status: 422 }) });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const lw = body.providers.lineworks;
    if (!("ok" in lw)) throw new Error("expected ok variant");
    expect(lw.ok).toBe(true);
    expect(lw.status).toBe(422);
  });

  it("lineworks: degraded when rust-alc-api returns 404 (route missing)", async () => {
    setupFetch({ lineworks: new Response("not found", { status: 404 }) });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(503);
    const body = await res.json() as OAuthBody;
    const lw = body.providers.lineworks;
    if (!("ok" in lw)) throw new Error("expected ok variant");
    expect(lw.ok).toBe(false);
    expect(lw.hint).toMatch(/404/);
  });

  it("lineworks: degraded when rust-alc-api returns 5xx", async () => {
    setupFetch({ lineworks: new Response("oops", { status: 502 }) });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const lw = body.providers.lineworks;
    if (!("ok" in lw)) throw new Error("expected ok variant");
    expect(lw.ok).toBe(false);
  });

  it("lineworks: unknown for unexpected 2xx", async () => {
    setupFetch({ lineworks: new Response("ok", { status: 200 }) });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const lw = body.providers.lineworks;
    if (!("unknown" in lw)) throw new Error("expected unknown variant");
    expect(lw.hint).toMatch(/unexpected status 200/);
  });

  it("lineworks: unknown on fetch error", async () => {
    setupFetch({ lineworks: new Error("dns failure") });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const lw = body.providers.lineworks;
    if (!("unknown" in lw)) throw new Error("expected unknown variant");
    expect(lw.hint).toMatch(/dns failure/);
  });

  // -------------------------------------------------------------------------
  // egov probe — Keycloak well-known reachability + JSON shape
  // -------------------------------------------------------------------------

  it("egov: ok when well-known returns 200 with required OIDC fields", async () => {
    setupFetch();
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const e = body.providers.egov;
    if (!("ok" in e)) throw new Error("expected ok variant");
    expect(e.ok).toBe(true);
    expect(e.mode).toBe("reachability");
    expect(e.status).toBe(200);
  });

  it("egov: trims trailing slash from EGOV_AUTH_BASE", async () => {
    // 末尾 / があっても // にならず 1 リクエストで叩ける。
    const fetchSpy = vi.fn(async (_input: RequestInfo | URL) =>
      new Response(JSON.stringify({
        issuer: "i", authorization_endpoint: "a", token_endpoint: "t",
      }), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchSpy);
    const env = envAllConfigured({ EGOV_AUTH_BASE: "https://egov.test.example/auth/realms/test/" });
    await handleHealthOAuth(await authedRequest(), env);
    const calls: string[] = fetchSpy.mock.calls.map(([input]) =>
      typeof input === "string" ? input : input.toString(),
    );
    const egovCall = calls.find((u) => u.includes(".well-known/openid-configuration"));
    expect(egovCall).toBe(
      "https://egov.test.example/auth/realms/test/.well-known/openid-configuration",
    );
  });

  it("egov: degraded when well-known returns 4xx (realm misconfigured)", async () => {
    setupFetch({
      egov: new Response("not found", { status: 404 }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(503);
    const body = await res.json() as OAuthBody;
    const e = body.providers.egov;
    if (!("ok" in e)) throw new Error("expected ok variant");
    expect(e.ok).toBe(false);
    expect(e.hint).toMatch(/404/);
  });

  it("egov: unknown when well-known body is not JSON", async () => {
    setupFetch({
      egov: new Response("<html>oops</html>", {
        status: 200,
        headers: { "Content-Type": "text/html" },
      }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const e = body.providers.egov;
    if (!("unknown" in e)) throw new Error("expected unknown variant");
    expect(e.hint).toMatch(/not JSON/);
  });

  it("egov: degraded when well-known JSON misses issuer", async () => {
    setupFetch({
      egov: new Response(JSON.stringify({
        authorization_endpoint: "x", token_endpoint: "y",
        // issuer missing
      }), { status: 200 }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const e = body.providers.egov;
    if (!("ok" in e)) throw new Error("expected ok variant");
    expect(e.ok).toBe(false);
    expect(e.hint).toMatch(/missing required/);
  });

  it("egov: degraded when issuer is non-string", async () => {
    setupFetch({
      egov: new Response(JSON.stringify({
        issuer: 42, authorization_endpoint: "x", token_endpoint: "y",
      }), { status: 200 }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const e = body.providers.egov;
    if (!("ok" in e)) throw new Error("expected ok variant");
    expect(e.ok).toBe(false);
  });

  it("egov: unknown on fetch error", async () => {
    setupFetch({ egov: new Error("connection refused") });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const e = body.providers.egov;
    if (!("unknown" in e)) throw new Error("expected unknown variant");
    expect(e.hint).toMatch(/connection refused/);
  });

  it("egov: handles res.json() throwing a non-Error value", async () => {
    // Cover the `String(e)` branch in `well-known body is not JSON: ...`.
    const fake = new Response("ignored", { status: 200 });
    (fake as unknown as { json: () => Promise<unknown> }).json = () => {
      throw "raw string";
    };
    setupFetch({ egov: fake });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const e = body.providers.egov;
    if (!("unknown" in e)) throw new Error("expected unknown variant");
    expect(e.hint).toContain("raw string");
  });

  // -------------------------------------------------------------------------
  // overall aggregation
  // -------------------------------------------------------------------------

  it("overall: degraded when any provider has ok:false", async () => {
    setupFetch({
      egov: new Response("not found", { status: 404 }),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(503);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("degraded");
  });

  it("overall: unknown when only unknowns (no fail)", async () => {
    setupFetch({
      google: new Error("net down"),
      github: new Error("net down"),
      lineworks: new Error("net down"),
      egov: new Error("net down"),
    });
    const env = envAllConfigured();
    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(200);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("unknown");
  });
});
