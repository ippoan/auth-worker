/**
 * `GoogleGcpTokenEntrypoint#accessToken` と `lib/google-gcp-token` (issue #691) の test。
 * Google の token endpoint は `globalThis.fetch` を stub して模擬する。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GoogleGcpTokenEntrypoint } from "../src/google-gcp-token-entrypoint";
import { gcpRefreshTokenKey, storeGcpRefreshToken } from "../src/lib/google-gcp-token";
import { signMcpJwt } from "../src/lib/mcp-jwt";
import { createMockEnv, createMockKV, type MockKV } from "./helpers/mock-env";
import type { Env } from "../src/index";

const TEST_MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!";
const AUD = "github-mcp-server-rs";
const EMAIL = "claude@ippoan.org";

function setup(): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    MCP_JWT_SECRET: TEST_MCP_JWT_SECRET,
    AUTH_WORKER_ORIGIN: "https://auth.test.example",
  });
  return { env, kv };
}

function rpc(env: Env): GoogleGcpTokenEntrypoint {
  return new GoogleGcpTokenEntrypoint({} as unknown as ExecutionContext, env);
}

async function googleJwt(email = EMAIL): Promise<string> {
  return signMcpJwt({ sub: "google:1", email, scope: "mcp.read mcp.write", aud: AUD }, TEST_MCP_JWT_SECRET, 3600);
}

async function call(env: Env, token: string) {
  const out = await rpc(env).accessToken(token);
  return { status: out.status, body: JSON.parse(out.body) as Record<string, unknown> };
}

function googleResponds(status: number, body: Record<string, unknown>) {
  const fetchSpy = vi.fn(async () =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }),
  );
  globalThis.fetch = fetchSpy as unknown as typeof fetch;
  return fetchSpy;
}

describe("GoogleGcpTokenEntrypoint#accessToken (issue #691)", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("200: 保管した refresh token で取ったアクセストークンを返す (refresh token は返さない)", async () => {
    const { env, kv } = setup();
    await storeGcpRefreshToken(env, EMAIL, "rt-secret");
    // 保管は暗号化されている
    expect(kv._data[gcpRefreshTokenKey(EMAIL)]).toBeDefined();
    expect(kv._data[gcpRefreshTokenKey(EMAIL)]).not.toContain("rt-secret");

    const fetchSpy = googleResponds(200, { access_token: "ya29.x", expires_in: 3599 });
    const res = await call(env, await googleJwt());

    expect(res).toEqual({ status: 200, body: { access_token: "ya29.x", expires_in: 3599, email: EMAIL } });
    const [url, init] = fetchSpy.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://oauth2.googleapis.com/token");
    const form = new URLSearchParams(init.body as string);
    expect(form.get("grant_type")).toBe("refresh_token");
    expect(form.get("refresh_token")).toBe("rt-secret");
    expect(JSON.stringify(res.body)).not.toContain("rt-secret");
  });

  it("401: GitHub flow の JWT や不正な JWT では渡さない", async () => {
    const { env } = setup();
    await storeGcpRefreshToken(env, EMAIL, "rt-secret");
    const fetchSpy = googleResponds(200, { access_token: "ya29.x" });
    const github = await signMcpJwt(
      { sub: "github:alice", github_login: "alice", scope: "mcp.read", aud: AUD },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const forged = await signMcpJwt({ sub: "google:1", email: EMAIL, scope: "mcp.read", aud: AUD }, "other-secret-32chars-padding!!!", 3600);
    for (const token of [github, forged, "not-a-jwt", ""]) {
      expect(await call(env, token)).toEqual({ status: 401, body: { error: "unauthorized" } });
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("401 reauthorize_required: まだ /mcp/google-gcp でログインしていない", async () => {
    const { env } = setup();
    const fetchSpy = googleResponds(200, { access_token: "ya29.x" });
    expect(await call(env, await googleJwt())).toEqual({ status: 401, body: { error: "reauthorize_required" } });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("401 reauthorize_required: Google が invalid_grant (失効・Testing の 7 日切れ) なら保管分を消す", async () => {
    const { env, kv } = setup();
    await storeGcpRefreshToken(env, EMAIL, "rt-expired");
    googleResponds(400, { error: "invalid_grant" });
    expect(await call(env, await googleJwt())).toEqual({ status: 401, body: { error: "reauthorize_required" } });
    expect(kv._data[gcpRefreshTokenKey(EMAIL)]).toBeUndefined();
  });

  it("401 reauthorize_required: 復号できない保管分も消す", async () => {
    const { env, kv } = setup();
    kv._data[gcpRefreshTokenKey(EMAIL)] = "not-ciphertext";
    googleResponds(200, { access_token: "ya29.x" });
    expect(await call(env, await googleJwt())).toEqual({ status: 401, body: { error: "reauthorize_required" } });
    expect(kv._data[gcpRefreshTokenKey(EMAIL)]).toBeUndefined();
  });

  it("503: Google の一時的な失敗では保管分を残す", async () => {
    const { env, kv } = setup();
    await storeGcpRefreshToken(env, EMAIL, "rt-secret");
    googleResponds(500, { error: "backend_error" });
    expect(await call(env, await googleJwt())).toEqual({ status: 503, body: { error: "server_error" } });
    expect(kv._data[gcpRefreshTokenKey(EMAIL)]).toBeDefined();
  });

  it("email は大文字小文字を区別しない", async () => {
    const { env } = setup();
    await storeGcpRefreshToken(env, "Claude@IPPOAN.org", "rt-secret");
    googleResponds(200, { access_token: "ya29.x", expires_in: 3599 });
    expect((await call(env, await googleJwt("CLAUDE@ippoan.org"))).status).toBe(200);
  });

  it("503: MCP_JWT_SECRET が無い / 文字列以外が渡されたら 401", async () => {
    const { env } = setup();
    const noSecret = createMockEnv({ ...env, MCP_JWT_SECRET: undefined } as Partial<Env>);
    expect(await call(noSecret, await googleJwt())).toEqual({ status: 503, body: { error: "server_error" } });
    const out = await rpc(env).accessToken(42 as unknown as string);
    expect(out.status).toBe(401);
  });

  it("503: Google の応答に access_token が無い / 通信に失敗した", async () => {
    const { env } = setup();
    await storeGcpRefreshToken(env, EMAIL, "rt-secret");
    googleResponds(200, {});
    expect(await call(env, await googleJwt())).toEqual({ status: 503, body: { error: "server_error" } });
    globalThis.fetch = (async () => { throw new Error("network"); }) as unknown as typeof fetch;
    expect(await call(env, await googleJwt())).toEqual({ status: 503, body: { error: "server_error" } });
  });

  it("expires_in が無ければ 3600 とみなす", async () => {
    const { env } = setup();
    await storeGcpRefreshToken(env, EMAIL, "rt-secret");
    googleResponds(200, { access_token: "ya29.x" });
    expect((await call(env, await googleJwt())).body.expires_in).toBe(3600);
  });

  it("Google の応答が JSON でなくても server_error", async () => {
    const { env } = setup();
    await storeGcpRefreshToken(env, EMAIL, "rt-secret");
    globalThis.fetch = (async () => new Response("<html>", { status: 502 })) as unknown as typeof fetch;
    expect(await call(env, await googleJwt())).toEqual({ status: 503, body: { error: "server_error" } });
  });
});

describe("lib/google-gcp-token — 設定が無いとき", () => {
  it("SSO_ENCRYPTION_KEY が無ければ保管しない / 交換しない", async () => {
    const { env } = setup();
    const noKey = createMockEnv({ ...env, SSO_ENCRYPTION_KEY: undefined } as Partial<Env>);
    expect(await storeGcpRefreshToken(noKey, EMAIL, "rt")).toBe(false);
    const noKv = createMockEnv({ ...env, MCP_OAUTH_KV: undefined } as Partial<Env>);
    expect(await storeGcpRefreshToken(noKv, EMAIL, "rt")).toBe(false);
    const noClient = createMockEnv({ ...env, GOOGLE_CLIENT_ID: undefined } as Partial<Env>);
    expect(await call(noClient, await googleJwt())).toEqual({ status: 503, body: { error: "server_error" } });
  });
});
