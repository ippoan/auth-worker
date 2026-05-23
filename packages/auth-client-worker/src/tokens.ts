/**
 * OAuth access/refresh token storage and rotation.
 *
 * Persists `{access_token, refresh_token, access_expires_at_ms}` in the
 * consumer's KV under `auth-client-worker:oauth-tokens`. `getValidAccessToken`
 * is the single read entrypoint — if the access_token is within 60 s of
 * expiry it transparently exchanges the refresh_token for a fresh pair via
 * `POST /mcp/token` (grant_type=refresh_token) and writes back.
 *
 * Refresh tokens are single-use (auth-worker `consumeRefreshToken` deletes
 * on use), so the read-modify-write here must be careful with concurrent
 * Worker invocations — see `refreshAccessToken` for the same-isolate guard.
 */

const TOKENS_CACHE_KEY = "auth-client-worker:oauth-tokens";
const TOKEN_REFRESH_BEFORE_EXPIRY_MS = 60 * 1000;

export interface StoredTokens {
  access_token: string;
  refresh_token: string;
  /** ms epoch when the access_token expires. */
  access_expires_at_ms: number;
  /** Original `scope` echoed by auth-worker; surfaced for diagnostics only. */
  scope?: string;
}

export interface TokenExchangeOpts {
  authWorkerOrigin: string;
  /** From the originating /oauth/login flow. Re-used at /mcp/token. */
  clientId: string;
  /** From the originating /oauth/login flow. Re-used at /mcp/token. */
  redirectUri: string;
  kv: KVNamespace;
}

/** Persist the initial tokens returned by the Auth Code grant. */
export async function storeTokens(kv: KVNamespace, tokens: StoredTokens): Promise<void> {
  await kv.put(TOKENS_CACHE_KEY, JSON.stringify(tokens));
}

/** Read whatever is in KV without freshness check. Returns null if the
 *  consumer hasn't completed /oauth/login yet. */
export async function readStoredTokens(kv: KVNamespace): Promise<StoredTokens | null> {
  return (await kv.get(TOKENS_CACHE_KEY, "json")) as StoredTokens | null;
}

/** Return a non-expired access_token, refreshing transparently if needed. */
export async function getValidAccessToken(opts: TokenExchangeOpts): Promise<string> {
  const stored = await readStoredTokens(opts.kv);
  if (!stored) {
    throw new Error(
      "No OAuth tokens stored. Visit /oauth/login to authorize the worker against auth-worker first.",
    );
  }
  if (stored.access_expires_at_ms > Date.now() + TOKEN_REFRESH_BEFORE_EXPIRY_MS) {
    return stored.access_token;
  }
  const fresh = await refreshAccessToken(stored.refresh_token, opts);
  await storeTokens(opts.kv, fresh);
  return fresh.access_token;
}

/** Exchange a refresh_token for a fresh access/refresh pair. */
export async function refreshAccessToken(
  refreshToken: string,
  opts: TokenExchangeOpts,
): Promise<StoredTokens> {
  const form = new URLSearchParams();
  form.set("grant_type", "refresh_token");
  form.set("refresh_token", refreshToken);

  const res = await fetch(`${opts.authWorkerOrigin}/mcp/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`auth-worker /mcp/token (refresh) failed (${res.status}): ${text}`);
  }
  const json = await res.json() as {
    access_token: string;
    refresh_token: string;
    expires_in?: number;
    scope?: string;
  };
  const ttlSec = json.expires_in ?? 3600;
  return {
    access_token: json.access_token,
    refresh_token: json.refresh_token,
    access_expires_at_ms: Date.now() + ttlSec * 1000,
    scope: json.scope,
  };
}

/** Exchange an auth `code` for the initial token pair (Auth Code grant). */
export async function exchangeAuthorizationCode(
  code: string,
  codeVerifier: string,
  opts: TokenExchangeOpts,
): Promise<StoredTokens> {
  const form = new URLSearchParams();
  form.set("grant_type", "authorization_code");
  form.set("code", code);
  form.set("code_verifier", codeVerifier);
  form.set("client_id", opts.clientId);
  form.set("redirect_uri", opts.redirectUri);

  const res = await fetch(`${opts.authWorkerOrigin}/mcp/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`auth-worker /mcp/token (code exchange) failed (${res.status}): ${text}`);
  }
  const json = await res.json() as {
    access_token: string;
    refresh_token: string;
    expires_in?: number;
    scope?: string;
  };
  const ttlSec = json.expires_in ?? 3600;
  return {
    access_token: json.access_token,
    refresh_token: json.refresh_token,
    access_expires_at_ms: Date.now() + ttlSec * 1000,
    scope: json.scope,
  };
}
