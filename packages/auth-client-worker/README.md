# @ippoan/auth-client-worker

OAuth client SDK for Cloudflare Worker consumers of [`ippoan/auth-worker`](https://github.com/ippoan/auth-worker).

Pairs with [`@ippoan/auth-client`](../auth-client) (Nuxt Vue components). Where that one handles browser-side login UX, this package implements the **server-to-server credential delegation** via the MCP OAuth Provider browser-consumer flow (Auth Code + PKCE + DCR).

## Why

Consumer Workers (`ci-dashboard`, future `secrets-inventory`, etc.) need GitHub API access without storing PAT / App PEM / OAuth Client Secret. This SDK delegates everything to `auth-worker`:

```
[Worker consumer] ──(JWT)──> [auth-worker] ──(github_token)──> [api.github.com]
                                  ▲
                                  └ owns GitHub OAuth App
                                    + per-user encrypted KV
```

The Worker holds only:
- `INTERNAL_SHARED_SECRET` (Secrets Store) — shared with auth-worker for `/mcp/introspect`
- Browser-issued OAuth tokens (KV, auto-rotating refresh_token)

GitHub credentials (App PEM / Client Secret) live exclusively in auth-worker.

## Install

```bash
npm install @ippoan/auth-client-worker
```

## Use

### 1. Env shape

Extend your Worker `Env` with the SDK's required bindings:

```ts
// src/index.ts
import type { AuthClientWorkerEnv } from "@ippoan/auth-client-worker";

export interface Env extends AuthClientWorkerEnv {
  // your other bindings
  CI_HUB: DurableObjectNamespace;
}
```

`AuthClientWorkerEnv` requires:

| binding | type | from |
|---|---|---|
| `CI_STATUS` | `KVNamespace` | your existing KV (rename via `opts.kv` if your binding has a different name) |
| `INTERNAL_SHARED_SECRET` | `SecretsStoreSecret` | Cloudflare Secrets Store, value matches auth-worker's own `INTERNAL_SHARED_SECRET` |

### 2. Wire up routes (Hono example)

```ts
import {
  handleOAuthLogin,
  handleOAuthCallback,
  getGitHubToken,
} from "@ippoan/auth-client-worker";

const oauthOpts = {
  authWorkerOrigin: "https://auth.ippoan.org",
  redirectUri: "https://ci-dashboard.ippoan.org/oauth/callback",
  scope: "mcp.write mcp.workflow mcp.project",
  clientName: "ci-dashboard",
};

app.get("/oauth/login", c =>
  handleOAuthLogin(c.req.raw, c.env, oauthOpts));

app.get("/oauth/callback", c =>
  handleOAuthCallback(c.req.raw, c.env, oauthOpts));

// runtime — call from any route that needs a GitHub token
app.get("/issues", async c => {
  const token = await getGitHubToken(c.env);
  const res = await fetch("https://api.github.com/search/issues?q=...", {
    headers: { Authorization: `Bearer ${token}` },
  });
  // ...
});
```

### 3. First-time setup

After deploying, visit `https://<your-worker>/oauth/login` in a browser:

1. SDK auto-registers the Worker via `POST /mcp/register` (DCR)
2. PKCE-protected redirect to `auth.ippoan.org/mcp/authorize`
3. Approve the GitHub OAuth consent screen
4. `/oauth/callback` exchanges the auth code for tokens, stores in KV
5. `getGitHubToken(env)` works on subsequent requests

No CLI / `curl` / manual secret-store editing required.

## KV keys used

All under whatever KV binding the SDK is configured with (default `CI_STATUS`):

| key | TTL | content |
|---|---|---|
| `auth-client-worker:dcr-client` | 80 days | DCR-registered `{client_id, redirect_uri, issued_at_ms}` |
| `auth-client-worker:oauth-pkce:<state>` | 10 min | `{code_verifier, return_to}` per in-flight login |
| `auth-client-worker:oauth-tokens` | persistent | `{access_token, refresh_token, access_expires_at_ms}` |
| `auth-client-worker:gh-token` | 55 min | resolved `github_token` cache from `/mcp/introspect` |

## Token rotation

Fully automatic:
- `access_token` expires in 1 h → SDK refreshes on next `getGitHubToken` call using the stored `refresh_token`
- `refresh_token` rotates on each refresh (auth-worker `consumeRefreshToken` is single-use)
- DCR client_id auto-re-registers when within 10 d of the 90 d upstream TTL
- Existing refresh_tokens survive DCR client_id re-registration (auth-worker's refresh grant doesn't validate client_id, by design)

## API

See `src/index.ts` for the full re-export list. Most consumers only need:

- `handleOAuthLogin(req, env, opts)`
- `handleOAuthCallback(req, env, opts)`
- `getGitHubToken(env, opts?)`
