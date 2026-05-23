/**
 * `/oauth/login` and `/oauth/callback` route handlers, packaged for direct
 * wiring into a consumer Worker's router. Both return `Response` objects
 * shaped for Hono / native `fetch` use.
 *
 * Flow:
 *
 *   GET /oauth/login
 *     1. Ensure DCR client registered (getOrRegisterDcrClient).
 *     2. Generate `code_verifier` + `state`.
 *     3. KV `auth-client-worker:oauth-pkce:<state>` ← { code_verifier, return_to }.
 *     4. 302 to `${authWorkerOrigin}/mcp/authorize?...`.
 *
 *   GET /oauth/callback?code=&state=
 *     1. KV lookup by state → code_verifier (delete on read to prevent
 *        replay).
 *     2. POST `${authWorkerOrigin}/mcp/token` (grant_type=authorization_code).
 *     3. KV `auth-client-worker:oauth-tokens` ← {access, refresh, exp}.
 *     4. 303 to the original `return_to` (or `/`).
 */

import type { AuthClientWorkerEnv } from "./env";
import {
  generateCodeVerifier,
  generateState,
  computeCodeChallenge,
} from "./pkce";
import { getOrRegisterDcrClient } from "./dcr";
import { exchangeAuthorizationCode, storeTokens } from "./tokens";

export interface OAuthHandlerOpts {
  /** auth-worker origin. Defaults to `https://auth.ippoan.org`. */
  authWorkerOrigin?: string;
  /** Fully-qualified callback URL. Must match a registered redirect_uri. */
  redirectUri: string;
  /** Space-separated MCP scopes (`mcp.write mcp.workflow mcp.project`). */
  scope: string;
  /** Audit-only client name. */
  clientName?: string;
  /** Override KV binding when the consumer's name isn't `CI_STATUS`. */
  kv?: KVNamespace;
}

const DEFAULT_AUTH_WORKER_ORIGIN = "https://auth.ippoan.org";
const PKCE_KEY_PREFIX = "auth-client-worker:oauth-pkce:";
// 10 min is the spec-recommended ceiling for an authorization request's
// session lifetime; well under any reasonable browser idle.
const PKCE_TTL_SECONDS = 10 * 60;

interface PkceStateRecord {
  code_verifier: string;
  return_to: string;
}

export async function handleOAuthLogin(
  request: Request,
  env: AuthClientWorkerEnv,
  opts: OAuthHandlerOpts,
): Promise<Response> {
  const kv = opts.kv ?? env.CI_STATUS;
  const authWorkerOrigin = opts.authWorkerOrigin ?? DEFAULT_AUTH_WORKER_ORIGIN;

  // Optional `?return_to=/path` so the user lands back on the page that
  // triggered the login. Default to `/` for simple "log in then see
  // dashboard" flows. Validate to a same-origin path so an attacker can't
  // craft `/oauth/login?return_to=https://evil.example.com`.
  const url = new URL(request.url);
  const returnTo = sanitizeReturnTo(url.searchParams.get("return_to"));

  const dcr = await getOrRegisterDcrClient({
    authWorkerOrigin,
    redirectUri: opts.redirectUri,
    scope: opts.scope,
    clientName: opts.clientName,
    kv,
  });

  const code_verifier = generateCodeVerifier();
  const code_challenge = await computeCodeChallenge(code_verifier);
  const state = generateState();

  const pkceRecord: PkceStateRecord = { code_verifier, return_to: returnTo };
  await kv.put(PKCE_KEY_PREFIX + state, JSON.stringify(pkceRecord), {
    expirationTtl: PKCE_TTL_SECONDS,
  });

  const authorize = new URL(`${authWorkerOrigin}/mcp/authorize`);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("client_id", dcr.client_id);
  authorize.searchParams.set("redirect_uri", opts.redirectUri);
  authorize.searchParams.set("code_challenge", code_challenge);
  authorize.searchParams.set("code_challenge_method", "S256");
  authorize.searchParams.set("scope", opts.scope);
  authorize.searchParams.set("state", state);

  return Response.redirect(authorize.toString(), 302);
}

export async function handleOAuthCallback(
  request: Request,
  env: AuthClientWorkerEnv,
  opts: OAuthHandlerOpts,
): Promise<Response> {
  const kv = opts.kv ?? env.CI_STATUS;
  const authWorkerOrigin = opts.authWorkerOrigin ?? DEFAULT_AUTH_WORKER_ORIGIN;

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  // auth-worker can redirect with `?error=` (e.g. user denied consent).
  // Surface to the operator without exchange.
  if (error) {
    return new Response(
      `OAuth error from auth-worker: ${error}${
        url.searchParams.get("error_description")
          ? ": " + url.searchParams.get("error_description")
          : ""
      }`,
      { status: 400, headers: { "Content-Type": "text/plain; charset=utf-8" } },
    );
  }

  if (!code || !state) {
    return new Response("Missing code or state in /oauth/callback", {
      status: 400,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  const stateKey = PKCE_KEY_PREFIX + state;
  const pkce = (await kv.get(stateKey, "json")) as PkceStateRecord | null;
  if (!pkce) {
    // State unknown or expired → CSRF-defense path. Avoid hinting at internals.
    return new Response("Invalid or expired state. Restart /oauth/login.", {
      status: 400,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }
  // Single-use: delete before the token exchange so a replayed callback
  // can't double-spend the PKCE record (the auth code itself is also
  // single-use upstream).
  await kv.delete(stateKey);

  // The DCR record is needed for `client_id` + `redirect_uri` at the token
  // endpoint. Re-using getOrRegisterDcrClient is safe (it's a read on the
  // happy path) but we accept that an aggressive re-registration before
  // callback would invalidate this code — operationally rare.
  const dcr = await getOrRegisterDcrClient({
    authWorkerOrigin,
    redirectUri: opts.redirectUri,
    scope: opts.scope,
    clientName: opts.clientName,
    kv,
  });

  const tokens = await exchangeAuthorizationCode(code, pkce.code_verifier, {
    authWorkerOrigin,
    clientId: dcr.client_id,
    redirectUri: opts.redirectUri,
    kv,
  });
  await storeTokens(kv, tokens);

  return Response.redirect(new URL(pkce.return_to, request.url).toString(), 303);
}

/** Restrict `return_to` to a same-origin absolute path (`/...`). Anything
 *  else falls back to `/` so an attacker can't craft an open-redirect URL. */
function sanitizeReturnTo(raw: string | null): string {
  if (!raw) return "/";
  if (!raw.startsWith("/") || raw.startsWith("//")) return "/";
  return raw;
}
