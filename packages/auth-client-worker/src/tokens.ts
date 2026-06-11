/**
 * OAuth access/refresh token storage and rotation.
 *
 * Persists `{access_token, refresh_token, access_expires_at_ms}` in the
 * consumer's KV under `auth-client-worker:oauth-tokens`. `getValidAccessToken`
 * is the single read entrypoint — if the access_token is within 60 s of
 * expiry it transparently exchanges the refresh_token for a fresh pair via
 * `POST /mcp/token` (grant_type=refresh_token) and writes back.
 *
 * Refresh tokens rotate on use, so the read-modify-write here must be careful
 * with concurrent Worker invocations. `getValidAccessToken` holds an
 * **isolate-scoped single-flight**: when the access_token is stale, only the
 * first concurrent caller performs the `/mcp/token` exchange; the rest await
 * its result. Without this, a single request's parallel fan-out (e.g.
 * `Promise.all` over many GitHub calls) fired N simultaneous refreshes against
 * the same refresh_token and tripped `invalid_grant: already used`, killing the
 * delegation session (Refs ippoan/auth-worker#270). Cross-isolate / cross-colo
 * races that escape the single-flight are absorbed by auth-worker's 60 s
 * refresh grace (PR1) plus the `invalid_grant` → KV re-read fallback below.
 */

const TOKENS_CACHE_KEY = "auth-client-worker:oauth-tokens";
const TOKEN_REFRESH_BEFORE_EXPIRY_MS = 60 * 1000;

/**
 * Isolate-scoped single-flight guard for the refresh exchange. Shared across
 * all `getValidAccessToken` callers in the same Worker isolate so a parallel
 * fan-out performs at most one `/mcp/token` refresh. Cleared in `finally`.
 *
 * One variable suffices because a given consumer Worker binds a single OAuth
 * KV namespace (one delegation session per isolate). Tests that exercise this
 * module state should `vi.resetModules()` between cases.
 */
let inflightRefresh: Promise<StoredTokens> | null = null;

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

/** Return a non-expired access_token, refreshing transparently if needed.
 *  Concurrent callers in the same isolate share one refresh (single-flight). */
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

  // Single-flight: 既に refresh 中なら勝者の結果を待つ (KV を読み直さないので
  // eventual consistency の影響を受けない)。`inflightRefresh` の check→set 間に
  // await が無いので isolate 内では確実に 1 本に収束する。
  if (inflightRefresh) {
    return (await inflightRefresh).access_token;
  }
  inflightRefresh = refreshAndStore(stored.refresh_token, opts);
  try {
    return (await inflightRefresh).access_token;
  } finally {
    inflightRefresh = null;
  }
}

/** refresh exchange + KV write-back。`invalid_grant` (= 別 isolate / colo が先に
 *  rotate 済み、or grace 超過) なら KV を 1 回だけ読み直し、別経路が書いた fresh な
 *  新 pair があればそれを採用する (cross-isolate 敗者の安価な救済、Refs #270)。 */
async function refreshAndStore(
  refreshToken: string,
  opts: TokenExchangeOpts,
): Promise<StoredTokens> {
  try {
    const fresh = await refreshAccessToken(refreshToken, opts);
    await storeTokens(opts.kv, fresh);
    return fresh;
  } catch (err: unknown) {
    if (isInvalidGrant(err)) {
      const reread = await readStoredTokens(opts.kv);
      if (
        reread &&
        reread.refresh_token !== refreshToken &&
        reread.access_expires_at_ms > Date.now() + TOKEN_REFRESH_BEFORE_EXPIRY_MS
      ) {
        return reread;
      }
    }
    throw err;
  }
}

/** refreshAccessToken の throw する Error message (status + body) から
 *  invalid_grant を検出する。 */
function isInvalidGrant(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /invalid_grant/.test(msg);
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
