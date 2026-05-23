/**
 * MCP OAuth Provider — 抽象 MCP scope ⇄ GitHub OAuth scope の翻訳。
 *
 * `/mcp/device_authorization` `/mcp/authorize` で consumer から受け取る抽象 scope
 * (`mcp.read` / `mcp.write` / `mcp.admin` / `mcp.workflow` / `mcp.project` /
 * `offline_access`) を GitHub `/login/oauth/authorize` の `scope` パラメータ
 * (`read:user` / `read:user repo` / `workflow` / `project`) に翻訳する単一の map。
 *
 * 下位互換: scope 省略 / unknown 値のみの場合は `mcp.read` に decay (issue #130)。
 * github-mcp-server-rs は scope 未指定で device_authorization を叩くため、従来の
 * `read:user` 挙動が維持される。
 *
 * Out of scope:
 *   - `offline_access` は現状 token endpoint が常に refresh_token を発行している
 *     ため no-op。将来 RFC 6749 §1.5 準拠 (要求時のみ refresh) に変えるときの fork。
 */

/** AS metadata `scopes_supported` と一致させる canonical な順序。
 *
 *  `mcp.admin` は internal-only (`/mcp/elevate` 経由でだけ付与、`scopes_supported`
 *  には**意図的に advertise しない**) — `mcp-as-metadata.ts` 側で削除される。
 *
 *  `mcp.workflow` / `mcp.project` は public、consumer が device flow / authcode
 *  で要求できる。`repo` scope (classic OAuth) に含まれない GitHub の独立 scope
 *  `workflow` / `project` を抽象化する (issue #184)。 */
export const MCP_SCOPES_SUPPORTED = [
  "mcp.read",
  "mcp.write",
  "mcp.admin",
  "mcp.workflow",
  "mcp.project",
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
 * 翻訳ルール (additive):
 *
 *   - `read:user`  常に追加 (`/user` で login を取得するため)
 *   - `repo`       `mcp.write` または `mcp.admin` ∈ scopes
 *   - `workflow`   `mcp.workflow` ∈ scopes (issue #184)
 *   - `project`    `mcp.project` ∈ scopes (issue #184)
 *
 * `repo` scope は GitHub OAuth (classic) の粒度の制約上 Issues 単独 scope がない
 * ため private repo Issues 操作を許可する最小選択肢として採用 (issue #130 Q&A)。
 *
 * `mcp.admin` (branch protection 系) も classic OAuth 上では `repo` scope に含まれる
 * ため `mcp.write` と同じ翻訳で十分。binary 側 (github-mcp-server-rs) の scope
 * factory が tool surface を branch_protection 3 個だけに絞ることで、token が広い
 * GitHub scope を持っても MCP tool 経由での副作用は最小化される。fine-grained
 * `Administration:write` への移行は別議題。
 *
 * `workflow` / `project` は `repo` に含まれない GitHub の独立 scope。ci-dashboard
 * のように Actions workflow dispatch (`tag-release.yml`) / Projects v2 mutation
 * (`add_issue_to_project` 等) を行う consumer は `mcp.workflow` / `mcp.project` を
 * 明示要求する必要がある (least privilege)。cc-relay / github-mcp-server-rs は
 * これらを要求しないため翻訳結果は不変 (後方互換、issue #184)。
 */
export function mcpToGithubScope(scopes: ReadonlySet<string>): string {
  const gh = new Set<string>(["read:user"]);
  if (scopes.has("mcp.write") || scopes.has("mcp.admin")) gh.add("repo");
  if (scopes.has("mcp.workflow")) gh.add("workflow");
  if (scopes.has("mcp.project")) gh.add("project");
  return [...gh].join(" ");
}
