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

/**
 * Google IdP surface (issue #438) の path prefix。
 *
 * claude.ai の「カスタムコネクタを追加」は `/mcp/authorize` に RFC 8707 `resource`
 * パラメータを送らない (実ログ確認済み) ため、resource origin ベースの
 * `mcpIdpForResourceOrigin` では Google IdP に振れない。そこで auth-worker 自身の
 * native MCP endpoint (`/mcp/tools` 相当) の別名として `<origin>/mcp/google` を
 * 用意し、この surface 経由の OAuth discovery chain (401 WWW-Authenticate →
 * PRM → AS metadata → `/mcp/google/authorize`) では resource 未指定でも Google を
 * 既定 IdP にする。既定 surface (`/mcp/authorize`) は GitHub 既定のまま不変。
 */
export const MCP_GOOGLE_SURFACE_PATH = "/mcp/google";

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
  // issue #438: auth-worker 自身の origin も許可する。Google IdP surface の PRM は
  // `resource: <auth origin>/mcp/google` を advertise するため、client がそれを
  // RFC 8707 resource として echo してきた時に invalid_target で落とさない。
  // AS 自身 = RS (native /mcp/tools・/mcp/google) の構成なので confused-deputy には
  // ならない (別サーバーへの audience 誤 bind が起きない)。
  const authOrigin = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
  const extra = ((env as Env & { MCP_RESOURCE_ORIGINS_ALLOWLIST?: string })
    .MCP_RESOURCE_ORIGINS_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return new Set<string>([relayOrigin, authOrigin, ...extra]);
}

/** `allowedResourceOrigins` に origin が含まれるか。 */
export function isAllowedResourceOrigin(origin: string, env: Env): boolean {
  return allowedResourceOrigins(env).has(origin);
}

/**
 * `resource` origin ごとに `/mcp/authorize` が使う IdP を選ぶ (issue: MCP OAuth に
 * Google IdP を追加)。
 *
 * デフォルトは `"github"` — 既存 consumer (github-mcp-server-rs / gmail-mcp /
 * cf-access-mcp 例 / secrets-inventory 等) は挙動不変。`MCP_RESOURCE_GOOGLE_ORIGINS`
 * env (comma-sep origin list) に列挙された origin だけ `"google"` を返す。
 *
 * この origin は `MCP_RESOURCE_ORIGINS_ALLOWLIST` にも含まれている必要がある
 * (resource 自体の許可は従来通りそちらが担う。本 helper は「許可された resource の
 * うちどの IdP を使うか」のみを決める)。
 */
export function mcpIdpForResourceOrigin(
  origin: string,
  env: Env,
): "github" | "google" {
  const googleOrigins = ((env as Env & { MCP_RESOURCE_GOOGLE_ORIGINS?: string })
    .MCP_RESOURCE_GOOGLE_ORIGINS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return googleOrigins.includes(origin) ? "google" : "github";
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
export function wwwAuthenticateValue(
  env: Env,
  surface: "default" | "google" = "default",
): string {
  // issue #438: Google IdP surface (`POST /mcp/google`) の 401 は surface 専用の
  // PRM (`/.well-known/oauth-protected-resource/mcp/google`) に誘導する。client は
  // そこから issuer `<origin>/mcp/google` の AS metadata → `/mcp/google/authorize`
  // に到達し、resource 未指定でも Google IdP 既定になる。
  const md =
    surface === "google"
      ? `${resourceMetadataUrl(env)}${MCP_GOOGLE_SURFACE_PATH}`
      : resourceMetadataUrl(env);
  return `Bearer realm="MCP", resource_metadata="${md}"`;
}
