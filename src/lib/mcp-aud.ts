/**
 * Shared MCP audience allowlist.
 *
 * 旧来は `/mcp/introspect` (#198) と `/u/:user/connect`
 * (`mcp-relay-connect.ts`) が独自に `expectedAud = "github-mcp-server-rs"` を
 * 持っており、`ref-files-mcp-server-rs` を accept する fix を片方にしか入れ
 * 損ねて WS upgrade が 401 で reject される片肺事故 (mcp-relay-rs#15) を
 * 引き起こした。本モジュールは両 path の source of truth を 1 箇所に集める。
 *
 * `wrangler.toml` の `[vars] MCP_JWT_AUDIENCE_ALLOWLIST = "a,b,c"` で env
 * 上書き可能。未設定時の fallback が `MCP_AUD_LEGACY`。
 *
 * URL-form aud (claude.ai DCR resource origin) は `mcp-introspect.ts` 側
 * `audPredicate` で別途扱う。本モジュールは literal aud のみを返す。
 */

import type { Env } from "../index";

/** binary が `/mcp/token` で mint される access JWT の `aud` claim 候補。
 *  `MCP_JWT_AUDIENCE_ALLOWLIST` env 未設定時の default。 */
export const MCP_AUD_LEGACY: readonly string[] = [
  "github-mcp-server-rs",
  "ref-files-mcp-server-rs",
];

/** env override (`MCP_JWT_AUDIENCE_ALLOWLIST`) があれば優先、なければ legacy 値。
 *  caller は `verifyMcpJwt(token, secret, getLiteralAudAllowlist(env))` で使う。 */
export function getLiteralAudAllowlist(env: Env): readonly string[] {
  const raw = (env as Env & { MCP_JWT_AUDIENCE_ALLOWLIST?: string })
    .MCP_JWT_AUDIENCE_ALLOWLIST;
  const parsed = (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return parsed.length > 0 ? parsed : MCP_AUD_LEGACY;
}
