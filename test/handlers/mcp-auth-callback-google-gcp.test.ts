/**
 * `handleMcpAuthCallbackGoogle` の GCP 委譲 surface (`/mcp/google-gcp`、issue #691) 分岐の test。
 * 共通の guard / ACL は `mcp-auth-callback-google.test.ts` が見る。
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { handleMcpAuthCallbackGoogle } from "../../src/handlers/mcp-auth-callback-google";
import { putAuthRequest, type AuthRequestRecord } from "../../src/lib/mcp-authcode";
import { decryptWithKey } from "../../src/lib/mcp-crypto";
import { gcpRefreshTokenKey } from "../../src/lib/google-gcp-token";
import { generateOAuthState } from "../../src/lib/security";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth.test.example";
const STATE_SECRET = "test-oauth-state-secret-32chars!";
const SSO_KEY = "test-sso-encryption-key";
const EMAIL = "claude@ippoan.org";
const CLOUD_PLATFORM = "https://www.googleapis.com/auth/cloud-platform";

function setup(): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_CONFIG: createMockKV({ "google-mcp-user-allowlist": JSON.stringify([EMAIL]) }),
    AUTH_WORKER_ORIGIN: ISSUER,
    OAUTH_STATE_SECRET: STATE_SECRET,
    SSO_ENCRYPTION_KEY: SSO_KEY,
  });
  return { env, kv };
}

async function startedFrom(env: Env, surfacePath: string): Promise<string> {
  const rec: AuthRequestRecord = {
    id: "ar-1",
    client_id: "c-1",
    redirect_uri: "https://claude.ai/cb",
    code_challenge: "abc",
    code_challenge_method: "S256",
    client_state: "csrf-1",
    scope: "mcp.read mcp.write",
    iss: `${ISSUER}${surfacePath}`,
    expires_at: Date.now() + 60_000,
  };
  await putAuthRequest(env, rec);
  return generateOAuthState(`${ISSUER}/mcp/auth_callback_google`, STATE_SECRET, {
    provider: "google_mcp_authcode",
    auth_request_id: "ar-1",
  });
}

function idToken(): string {
  const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${b64({ alg: "RS256" })}.${b64({ sub: "g-1", email: EMAIL, email_verified: true })}.sig`;
}

function googleTokenResponse(body: Record<string, unknown>) {
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({ id_token: idToken(), ...body }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })) as typeof fetch;
}

async function callback(env: Env, state: string): Promise<URL> {
  const u = new URL(`${ISSUER}/mcp/auth_callback_google`);
  u.searchParams.set("code", "google-code");
  u.searchParams.set("state", state);
  const res = await handleMcpAuthCallbackGoogle(new Request(u.toString()), env);
  expect(res.status).toBe(302);
  return new URL(res.headers.get("Location")!);
}

describe("handleMcpAuthCallbackGoogle — /mcp/google-gcp (issue #691)", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("cloud-platform に同意して refresh token が来たら、暗号化して保管し code を返す", async () => {
    const { env, kv } = setup();
    const state = await startedFrom(env, "/mcp/google-gcp");
    googleTokenResponse({ refresh_token: "rt-1", scope: `openid ${CLOUD_PLATFORM} https://www.googleapis.com/auth/userinfo.email` });

    const dest = await callback(env, state);
    expect(dest.searchParams.get("code")).toBeTruthy();
    expect(dest.searchParams.get("iss")).toBe(`${ISSUER}/mcp/google-gcp`);
    const stored = kv._data[gcpRefreshTokenKey(EMAIL)]!;
    expect(stored).not.toContain("rt-1");
    expect(await decryptWithKey(stored, SSO_KEY)).toBe("rt-1");
  });

  it("cloud-platform を外して同意したら access_denied (保管しない)", async () => {
    const { env, kv } = setup();
    const state = await startedFrom(env, "/mcp/google-gcp");
    googleTokenResponse({ refresh_token: "rt-1", scope: "openid https://www.googleapis.com/auth/userinfo.email" });

    const dest = await callback(env, state);
    expect(dest.searchParams.get("error")).toBe("access_denied");
    expect(dest.searchParams.get("code")).toBeNull();
    expect(kv._data[gcpRefreshTokenKey(EMAIL)]).toBeUndefined();
  });

  it("refresh token が来なければ access_denied", async () => {
    const { env, kv } = setup();
    const state = await startedFrom(env, "/mcp/google-gcp");
    googleTokenResponse({ scope: `openid ${CLOUD_PLATFORM}` });

    const dest = await callback(env, state);
    expect(dest.searchParams.get("error")).toBe("access_denied");
    expect(kv._data[gcpRefreshTokenKey(EMAIL)]).toBeUndefined();
  });

  it("/mcp/google (委譲しない surface) からは、refresh token が来ても保管しない", async () => {
    const { env, kv } = setup();
    const state = await startedFrom(env, "/mcp/google");
    googleTokenResponse({ refresh_token: "rt-1", scope: `openid ${CLOUD_PLATFORM}` });

    const dest = await callback(env, state);
    expect(dest.searchParams.get("code")).toBeTruthy();
    expect(kv._data[gcpRefreshTokenKey(EMAIL)]).toBeUndefined();
  });

  it("refresh token を保管できなければ (鍵が無い) server_error で code を出さない", async () => {
    const { env, kv } = setup();
    const noKey = createMockEnv({ ...env, SSO_ENCRYPTION_KEY: undefined } as Partial<Env>);
    const state = await startedFrom(noKey, "/mcp/google-gcp");
    googleTokenResponse({ refresh_token: "rt-1", scope: `openid ${CLOUD_PLATFORM}` });

    const dest = await callback(noKey, state);
    expect(dest.searchParams.get("error")).toBe("server_error");
    expect(dest.searchParams.get("code")).toBeNull();
    expect(kv._data[gcpRefreshTokenKey(EMAIL)]).toBeUndefined();
  });
});
