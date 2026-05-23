/**
 * Dynamic Client Registration (RFC 7591) — manages the consumer Worker's
 * client_id with auth-worker so each `/oauth/login` round-trip has a valid
 * registered client.
 *
 * Why DCR (instead of a static client_id):
 *   auth-worker's `/mcp/authorize` validates client_id + redirect_uri against
 *   a KV-stored DCR record (`dcr:client:{id}`). Static client_ids aren't
 *   supported by the authorize endpoint at the moment, only the device-flow
 *   token endpoint. So browser-flow consumers must register.
 *
 * TTL handling:
 *   auth-worker stores DCR records with a 90-day TTL. We cache the
 *   `{client_id, redirect_uri, issued_at_ms}` in the consumer's KV with our
 *   own 80-day soft cap — when the cached record is older than 80 days we
 *   re-register before the upstream record can expire mid-flow. Existing
 *   refresh_tokens are NOT tied to the client_id (auth-worker
 *   `handleRefreshGrant` doesn't validate client_id), so a re-registration
 *   doesn't invalidate active sessions.
 */

const DCR_CACHE_KEY = "auth-client-worker:dcr-client";
// 80 d — safely under auth-worker's 90 d TTL so we re-register before the
// upstream record expires. Sub-day clock drift between worker isolates is
// irrelevant at this scale.
const DCR_CACHE_TTL_SECONDS = 80 * 24 * 60 * 60;
const DCR_REFRESH_BEFORE_MS = 10 * 24 * 60 * 60 * 1000; // re-register if <10d left
const DCR_REGISTER_DEFAULT_SCOPE = "mcp.write";

export interface DcrClient {
  client_id: string;
  redirect_uri: string;
  issued_at_ms: number;
}

export interface GetOrRegisterDcrClientOpts {
  /** auth-worker origin, e.g. `https://auth.ippoan.org`. */
  authWorkerOrigin: string;
  /** Single redirect_uri this consumer expects (must match `/oauth/callback`). */
  redirectUri: string;
  /** Space-separated MCP scopes to request (`mcp.write mcp.workflow mcp.project`). */
  scope?: string;
  /** Optional client_name echoed by auth-worker (no semantic use, audit only). */
  clientName?: string;
  /** Override KV namespace when the consumer's binding isn't `CI_STATUS`. */
  kv: KVNamespace;
}

/** Return a usable DCR client record. Hits auth-worker `/mcp/register` only
 *  on cache miss or near-expiry. */
export async function getOrRegisterDcrClient(opts: GetOrRegisterDcrClientOpts): Promise<DcrClient> {
  const { kv } = opts;
  const cached = await kv.get(DCR_CACHE_KEY, "json") as DcrClient | null;
  if (cached) {
    const ageMs = Date.now() - cached.issued_at_ms;
    // Re-register only when within DCR_REFRESH_BEFORE_MS of the 90 d
    // upstream TTL AND the cached redirect_uri still matches (config drift
    // → force re-register).
    const upstreamTtlMs = 90 * 24 * 60 * 60 * 1000;
    if (ageMs < upstreamTtlMs - DCR_REFRESH_BEFORE_MS && cached.redirect_uri === opts.redirectUri) {
      return cached;
    }
  }

  const body: Record<string, unknown> = {
    redirect_uris: [opts.redirectUri],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    scope: opts.scope ?? DCR_REGISTER_DEFAULT_SCOPE,
  };
  if (opts.clientName) body.client_name = opts.clientName;

  const res = await fetch(`${opts.authWorkerOrigin}/mcp/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`auth-worker /mcp/register failed (${res.status}): ${text}`);
  }
  const json = await res.json() as { client_id?: string };
  if (!json.client_id) {
    throw new Error("auth-worker /mcp/register returned no client_id");
  }

  const record: DcrClient = {
    client_id: json.client_id,
    redirect_uri: opts.redirectUri,
    issued_at_ms: Date.now(),
  };
  await kv.put(DCR_CACHE_KEY, JSON.stringify(record), { expirationTtl: DCR_CACHE_TTL_SECONDS });
  return record;
}
