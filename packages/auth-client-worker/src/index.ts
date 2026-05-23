/**
 * `@ippoan/auth-client-worker` — OAuth client SDK for Cloudflare Worker
 * consumers of `ippoan/auth-worker`.
 *
 * Pairs with the Nuxt-side `@ippoan/auth-client` package. Where that one
 * provides Vue composables for browser-side login UX, this package provides
 * Worker-side helpers for server-to-server credential delegation via the MCP
 * OAuth Provider browser-consumer flow (Auth Code + PKCE + DCR).
 *
 * Quick start — see README.md for a full ci-dashboard-style integration.
 */

export {
  handleOAuthLogin,
  handleOAuthCallback,
  type OAuthHandlerOpts,
} from "./handlers";

export {
  getGitHubToken,
  getOrRegisterDcrClient,
  type GetGitHubTokenOpts,
} from "./introspect";

export {
  getValidAccessToken,
  readStoredTokens,
  refreshAccessToken,
  exchangeAuthorizationCode,
  storeTokens,
  type StoredTokens,
  type TokenExchangeOpts,
} from "./tokens";

export {
  generateCodeVerifier,
  computeCodeChallenge,
  generateState,
  base64UrlEncode,
} from "./pkce";

export type { DcrClient, GetOrRegisterDcrClientOpts } from "./dcr";

export type { AuthClientWorkerEnv } from "./env";
