/**
 * MCP OAuth Provider — 抽象 MCP scope ⇄ GitHub OAuth scope の翻訳。
 *
 * `/mcp/device_authorization` `/mcp/authorize` で consumer から受け取る抽象 scope
 * (`mcp.read` / `mcp.write` / `offline_access`) を GitHub `/login/oauth/authorize`
 * の `scope` パラメータ (`read:user` / `read:user repo`) に翻訳する単一の map。
 *
 * 下位互換: scope 省略 / unknown 値のみの場合は `mcp.read` に decay (issue #130)。
 * github-mcp-server-rs は scope 未指定で device_authorization を叩くため、従来の
 * `read:user` 挙動が維持される。
 *
 * Out of scope:
 *   - `offline_access` は現状 token endpoint が常に refresh_token を発行している
 *     ため no-op。将来 RFC 6749 §1.5 準拠 (要求時のみ refresh) に変えるときの fork。
 */

/** AS metadata `scopes_supported` と一致させる canonical な順序。 */
export const MCP_SCOPES_SUPPORTED = [
  "mcp.read",
  "mcp.write",
  "offline_access",
] as const;

const ALLOWED: ReadonlySet<string> = new Set<string>(MCP_SCOPES_SUPPORTED);

/**
 * space-separated raw scope 文字列を whitelist 通過済 set に変換。
 * 結果が空 set の場合 (= raw 全て unknown / 空文字) は `{"mcp.read"}` を返す
 * (下位互換 default)。
 *
 * RFC 6749 §3.3: "values not understood by the server SHOULD be ignored".
 */
export function parseMcpScope(raw: string): Set<string> {
  const out = new Set<string>();
  for (const tok of raw.split(/\s+/)) {
    if (tok && ALLOWED.has(tok)) out.add(tok);
  }
  if (out.size === 0) out.add("mcp.read");
  return out;
}

/**
 * KV 保存 / `scope` echo 用の正規化済文字列。`MCP_SCOPES_SUPPORTED` の順で
 * deterministic に並ぶため、テスト assertion / cache key が安定する。
 */
export function normalizeMcpScope(raw: string): string {
  const parsed = parseMcpScope(raw);
  return MCP_SCOPES_SUPPORTED.filter((s) => parsed.has(s)).join(" ");
}

/**
 * MCP scope set → GitHub OAuth scope 文字列。
 *
 * - `mcp.write` ∈ scopes → `"read:user repo"` (Issues r/w + private repo 含む完全アクセス)
 * - その他                  → `"read:user"`  (login 取得用最小権限)
 *
 * `read:user` は GitHub `/user` で `login` を取るのに必須なので常に含む。
 * `repo` scope は GitHub OAuth (classic) の粒度の制約上 Issues 単独 scope がない
 * ため private repo Issues 操作を許可する最小選択肢として採用 (issue #130 Q&A)。
 */
export function mcpToGithubScope(scopes: ReadonlySet<string>): string {
  return scopes.has("mcp.write") ? "read:user repo" : "read:user";
}
