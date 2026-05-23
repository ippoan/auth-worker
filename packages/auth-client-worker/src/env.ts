/**
 * Env shape required by `@ippoan/auth-client-worker`. Consumer Workers extend
 * their own `Env` with this interface so all helpers in the package can be
 * called as `getGitHubToken(env)` / `handleOAuthLogin(req, env, opts)` without
 * passing bindings explicitly.
 *
 * Why these specific bindings:
 *   - `CI_STATUS` (KV): holds the DCR client_id, PKCE state, OAuth tokens,
 *     and the introspect-result github_token cache. Single namespace per
 *     consumer so the consumer chooses where to put it (any KV binding name
 *     works in practice; we pick `CI_STATUS` here only because that's the
 *     name in ci-dashboard — see note on `kv` field below).
 *   - `INTERNAL_SHARED_SECRET` (Secrets Store): pre-shared key used as the
 *     `Authorization` header on `/mcp/introspect`. Matches the value held by
 *     auth-worker; rotation is a coordinated change.
 *
 * Note on KV binding name: if your Worker's KV binding is NOT `CI_STATUS`,
 * pass `opts.kv` explicitly to the helpers (e.g. `handleOAuthLogin(req, env,
 * { kv: env.MY_KV, ... })`). The default lookup at `env.CI_STATUS` is only
 * a convenience for ci-dashboard.
 */
export interface AuthClientWorkerEnv {
  CI_STATUS: KVNamespace;
  INTERNAL_SHARED_SECRET: SecretsStoreSecret;
}
