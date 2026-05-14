/**
 * MCP relay origin / OAuth challenge URL helpers (issue #126 / Phase 4).
 *
 * MCP Authorization spec ([2025-06-18](https://spec.modelcontextprotocol.io/specification/2025-06-18/basic/authorization/))
 * では resource server (= mcp(-staging).ippoan.org) と authorization server
 * (= auth(-staging).ippoan.org) の URL を客が discovery できる必要がある。
 *
 * - `mcpRelayOrigin(env)`: AS origin から RS origin を導出する
 *   (`auth.ippoan.org` ↔ `mcp.ippoan.org` / `auth-staging.*` ↔ `mcp-staging.*`)
 * - `resourceMetadataUrl(env)`: client が WWW-Authenticate の `resource_metadata`
 *   から踏むべき URL (= AS 側 `/.well-known/oauth-protected-resource`)
 * - `wwwAuthenticateValue(env)`: 401 応答に積む header value
 *
 * AS 側に metadata を置く理由 (cf. issue #126 議論):
 * - 既存の AS metadata (`oauth-authorization-server`) と同じ host にまとめると
 *   実装・運用が一貫
 * - RS 側 `mcp(-staging).*` はそもそも auth-worker と同 script の custom domain
 *   なので、route だけ追加するか / AS host のみに限定するかは routing 上の選択。
 *   本 PR では **AS host のみ** に置き、`WWW-Authenticate.resource_metadata` で
 *   client を AS host に誘導する。
 */

import type { Env } from "../index";

/** AS origin から MCP relay (RS) origin を導出。env 追加なしで prod / staging 両対応。 */
export function mcpRelayOrigin(env: Env): string {
  const auth = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
  // `https://auth(-staging)?.<rest>` → `https://mcp(-staging)?.<rest>`
  // - 一致しない host (test fixture 等) はそのまま返す (caller 側で意味付け)
  return auth.replace(
    /^(https:\/\/)auth(-[a-z0-9]+)?(\.)/,
    (_m, scheme: string, suffix: string | undefined, dot: string) =>
      `${scheme}mcp${suffix ?? ""}${dot}`,
  );
}

/** `WWW-Authenticate.resource_metadata` が指す URL (AS host 上 `/.well-known/oauth-protected-resource`)。 */
export function resourceMetadataUrl(env: Env): string {
  const auth = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
  return `${auth}/.well-known/oauth-protected-resource`;
}

/**
 * MCP Authorization spec で要求される 401 応答用 `WWW-Authenticate` header value。
 *
 * ```
 * Bearer realm="MCP", resource_metadata="https://auth-staging.ippoan.org/.well-known/oauth-protected-resource"
 * ```
 *
 * client (Anthropic Claude.ai backend / VSCode MCP Inspector etc.) はこれを見て
 * AS の metadata 一式を発見し OAuth Device Flow を開始する。
 */
export function wwwAuthenticateValue(env: Env): string {
  return `Bearer realm="MCP", resource_metadata="${resourceMetadataUrl(env)}"`;
}
