/**
 * `getGitHubToken(env)` — single read entrypoint for consumer Workers.
 *
 * Flow:
 *   1. KV `auth-client-worker:gh-token` cache check (~55 min) — most calls
 *      return here in O(KV).
 *   2. Cache miss → fetch a valid access_token via `getValidAccessToken`
 *      (transparent refresh_token rotation if expired).
 *   3. POST `/mcp/introspect` with the access_token + INTERNAL_SHARED_SECRET.
 *      auth-worker decodes the JWT, looks up the encrypted github_token in
 *      its KV (`github_token:{sub}`), decrypts, returns.
 *   4. Cache the resolved github_token, return.
 *
 * The github_token cache TTL is bounded by the JWT's own `exp` so we never
 * keep a token alive longer than the upstream authorization.
 */

import type { AuthClientWorkerEnv } from "./env";
import { getValidAccessToken, type TokenExchangeOpts } from "./tokens";
import { getOrRegisterDcrClient } from "./dcr";

const GH_TOKEN_CACHE_KEY = "auth-client-worker:gh-token";
// 55 min — bounded by the access_token's 1 h TTL plus a 5 min headroom.
const GH_TOKEN_CACHE_TTL_SECONDS = 55 * 60;
const GH_TOKEN_REFRESH_BEFORE_EXPIRY_MS = 60 * 1000;

interface CachedGithubToken {
  token: string;
  expires_at_ms: number;
}

interface IntrospectResponse {
  active: boolean;
  github_token?: string;
  github_login?: string;
  exp?: number;
  scope?: string;
  error?: string;
}

export interface GetGitHubTokenOpts {
  /** auth-worker origin. Defaults to `https://auth.ippoan.org`. */
  authWorkerOrigin?: string;
  /** redirect_uri this consumer registered with. Required so refresh_token
   *  rotation can identify the original DCR client for the token endpoint
   *  (auth-worker's refresh grant doesn't strictly need it, but the helper
   *  reuses `TokenExchangeOpts` for consistency). */
  redirectUri?: string;
  /** Override KV binding when the consumer's name isn't `CI_STATUS`. */
  kv?: KVNamespace;
}

const DEFAULT_AUTH_WORKER_ORIGIN = "https://auth.ippoan.org";

export async function getGitHubToken(
  env: AuthClientWorkerEnv,
  opts: GetGitHubTokenOpts = {},
): Promise<string> {
  const kv = opts.kv ?? env.CI_STATUS;
  const authWorkerOrigin = opts.authWorkerOrigin ?? DEFAULT_AUTH_WORKER_ORIGIN;

  // 1) KV cache hit
  const cached = (await kv.get(GH_TOKEN_CACHE_KEY, "json")) as CachedGithubToken | null;
  if (cached && cached.expires_at_ms > Date.now() + GH_TOKEN_REFRESH_BEFORE_EXPIRY_MS) {
    return cached.token;
  }

  // 2) Resolve a valid access_token (refresh transparently if needed)
  //    We need the DCR client_id / redirect_uri for refresh_token rotation
  //    to use consistent params — fetch them from the cached DCR record so
  //    we never re-register here (re-registration is the responsibility of
  //    the login flow). If no record exists, the operator hasn't logged in
  //    yet; getValidAccessToken throws below.
  const dcr = await readDcrFromKv(kv);
  if (!dcr) {
    throw new Error(
      "No DCR client registered. Visit /oauth/login first to register and authorize.",
    );
  }
  const tokenOpts: TokenExchangeOpts = {
    authWorkerOrigin,
    clientId: dcr.client_id,
    redirectUri: opts.redirectUri ?? dcr.redirect_uri,
    kv,
  };
  const accessToken = await getValidAccessToken(tokenOpts);
  const sharedSecret = await env.INTERNAL_SHARED_SECRET.get();

  // 3) /mcp/introspect → github_token
  const res = await fetch(`${authWorkerOrigin}/mcp/introspect`, {
    method: "POST",
    headers: {
      Authorization: sharedSecret,
      "Content-Type": "application/json",
      "User-Agent": "auth-client-worker",
    },
    body: JSON.stringify({ token: accessToken }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`auth-worker /mcp/introspect failed (${res.status}): ${text}`);
  }
  const data = (await res.json()) as IntrospectResponse;
  if (!data.active || !data.github_token) {
    throw new Error(
      `auth-worker reports JWT inactive (${data.error ?? "no reason given"}). ` +
        "Re-run /oauth/login to refresh authorization.",
    );
  }

  // 4) Cache (bounded by JWT exp so we never outlive the upstream session)
  const expFromJwt = data.exp ? data.exp * 1000 : Number.MAX_SAFE_INTEGER;
  const ttlCap = Date.now() + GH_TOKEN_CACHE_TTL_SECONDS * 1000;
  const entry: CachedGithubToken = {
    token: data.github_token,
    expires_at_ms: Math.min(expFromJwt, ttlCap),
  };
  await kv.put(GH_TOKEN_CACHE_KEY, JSON.stringify(entry), {
    expirationTtl: GH_TOKEN_CACHE_TTL_SECONDS,
  });
  return data.github_token;
}

// Reach into dcr.ts's cache without re-registering. `getOrRegisterDcrClient`
// is the registering path; for read-only access we inline the key here to
// avoid the round-trip side effect.
const DCR_CACHE_KEY = "auth-client-worker:dcr-client";

async function readDcrFromKv(
  kv: KVNamespace,
): Promise<{ client_id: string; redirect_uri: string; issued_at_ms: number } | null> {
  return (await kv.get(DCR_CACHE_KEY, "json")) as {
    client_id: string;
    redirect_uri: string;
    issued_at_ms: number;
  } | null;
}

// Re-export so callers needing to ensure registration before introspect
// (e.g. cron warmup) can drive it.
export { getOrRegisterDcrClient };
