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
 * 同 metadata endpoint の per-resource variant URL。`/.well-known/oauth-protected-
 * resource/<slug>` 形式で、resource server が複数 (= MCP relay 以外に
 * `security-inventory` 等の独立 worker) ある場合に、各 RS が自分用の metadata
 * URL を `WWW-Authenticate.resource_metadata` に載せて宣言できる。
 *
 * slug は `MCP_RESOURCE_ORIGINS_ALLOWLIST` 内 URL の hostname 先頭 label を
 * そのまま使う (例: `https://security-inventory.ippoan.org` → `security-inventory`)。
 */
export function resourceMetadataUrlFor(slug: string, env: Env): string {
  const auth = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
  return `${auth}/.well-known/oauth-protected-resource/${slug}`;
}

/**
 * `/authorize` / `/mcp/token` が受理する resource origin の許可集合。
 *
 * - `mcpRelayOrigin(env)` (= mcp(-staging).ippoan.org) — auth-worker 自身が
 *   front door として相手する MCP relay
 * - `MCP_RESOURCE_ORIGINS_ALLOWLIST` env (comma-sep) に並ぶ追加 RS origin —
 *   secrets-inventory (= security-inventory.ippoan.org) 等の独立 worker
 *
 * 旧来 `mcp-authorize.ts` は前者のみを許容し、後者 origin の resource を
 * `invalid_target` で reject していた (= secrets-inventory MCP に対する
 * RFC 8707 audience binding が成立せず client が token を使えない問題)。
 * 本 helper を通すことで両者を統一許容する。confused-deputy 防止は
 * allowlist env で明示的に絞ることで担保する (任意 URL は通さない)。
 */
export function allowedResourceOrigins(env: Env): Set<string> {
  const relayOrigin = mcpRelayOrigin(env);
  const extra = ((env as Env & { MCP_RESOURCE_ORIGINS_ALLOWLIST?: string })
    .MCP_RESOURCE_ORIGINS_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return new Set<string>([relayOrigin, ...extra]);
}

/** `allowedResourceOrigins` に origin が含まれるか。 */
export function isAllowedResourceOrigin(origin: string, env: Env): boolean {
  return allowedResourceOrigins(env).has(origin);
}

/**
 * `MCP_RESOURCE_ORIGINS_ALLOWLIST` から slug → origin map を作る。slug は
 * hostname の先頭 label (= `security-inventory.ippoan.org` → `security-inventory`)。
 * `mcpRelayOrigin` 自身は含めない (= per-resource metadata の対象は extra RS のみ、
 * relay 用 metadata は無印 path で配信する設計)。
 */
export function resourceOriginBySlug(env: Env): Map<string, string> {
  const map = new Map<string, string>();
  const extra = ((env as Env & { MCP_RESOURCE_ORIGINS_ALLOWLIST?: string })
    .MCP_RESOURCE_ORIGINS_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  for (const origin of extra) {
    try {
      // valid URL なら hostname は必ず非空、その first label を slug に使う
      // (例: `security-inventory.ippoan.org` → `security-inventory`)。
      // `split(".")[0]` の戻り型は `string | undefined` (array index 規約)
      // だが空文字 hostname は URL ctor が throw 済みなので必ず string 確定。
      // `??` で fallback を書くと coverage 100% gate の未到達 branch になる
      // ため non-null assertion を使う。
      const slug = new URL(origin).hostname.split(".")[0]!;
      map.set(slug, origin);
    } catch {
      // skip malformed entries (= URL ctor が throw)
    }
  }
  return map;
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
