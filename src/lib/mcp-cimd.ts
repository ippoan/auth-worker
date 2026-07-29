/**
 * MCP OAuth Provider — Client ID Metadata Documents (CIMD) 受け入れ (issue #449 PR-B)。
 *
 * SEP-991 / draft-ietf-oauth-client-id-metadata-document-00 (MCP Authorization
 * spec 2025-11-25 で採用、2026-07-28 で DCR を置き換える既定に格上げ):
 * client_id が HTTPS URL のとき、その URL が指す JSON 文書を AS が取得して
 * DCR record の代わりに使う。AS 側に登録ストレージが要らないため、DCR 503
 * (prod で実稼働 AS が auth-staging に退避している問題) の恒久解決経路でもある。
 *
 * 検証 (MCP spec の MUST):
 *   - 文書は valid JSON で `client_id` / `client_name` / `redirect_uris` を含む
 *   - 文書内 `client_id` は URL と完全一致 (単純文字列比較)
 *   - authorize request の redirect_uri は文書の `redirect_uris` と照合 (呼び出し側)
 *
 * SSRF / DoS ガード:
 *   - https + path 必須、fragment / userinfo 禁止 (draft §3.1)
 *   - localhost / private / link-local ホストは拒否 (Workers egress では元々
 *     到達不能だが belt-and-braces)
 *   - redirect 追跡なし (`redirect: "error"`)、タイムアウト 5s、本文 64KB 上限
 *
 * キャッシュ: KV `cimd:client:<url>` に Cache-Control max-age を [60s, 24h] に
 * clamp して保存 (spec の SHOULD "cache metadata respecting HTTP cache headers")。
 * 未指定は 300s。
 */

import type { Env } from "../index";

/** authorize が必要とする client 情報 (DcrClientRecord の CIMD 版サブセット)。 */
export interface CimdClient {
  /** = metadata document URL (完全一致検証済み) */
  client_id: string;
  redirect_uris: string[];
  client_name: string;
  scope?: string;
}

export const CIMD_FETCH_TIMEOUT_MS = 5_000;
export const CIMD_MAX_BODY_BYTES = 64 * 1024;
const CACHE_TTL_MIN_SEC = 60;
const CACHE_TTL_MAX_SEC = 60 * 60 * 24;
const CACHE_TTL_DEFAULT_SEC = 300;

/** private / loopback / link-local / 内部 TLD を拒否 (SSRF belt-and-braces)。 */
function isForbiddenHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h.endsWith(".local") || h.endsWith(".internal")) return true;
  // IPv6 literal (URL.hostname は [] を保持する)
  if (h.startsWith("[")) return true;
  // IPv4 literal の private / loopback / link-local / unspecified
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  return false;
}

/**
 * client_id が CIMD URL 形式か (draft §3.1: https スキーム + path 成分必須)。
 * false = 従来どおり DCR lookup に回す (UUID 形式の既存 client と共存)。
 */
export function isCimdClientId(client_id: string): boolean {
  if (!client_id.startsWith("https://")) return false;
  let u: URL;
  try {
    u = new URL(client_id);
  } catch {
    return false;
  }
  // `https://` prefix 確認済みなので protocol は常に https: — 再チェック不要
  if (u.username !== "" || u.password !== "") return false;
  if (u.hash !== "") return false;
  // https URL の pathname は最低 "/" — path 成分必須 (draft §3.1)
  if (u.pathname === "/") return false;
  if (isForbiddenHost(u.hostname)) return false;
  return true;
}

/** Cache-Control: max-age=N を [60s, 24h] に clamp。無指定 / 不正は 300s。 */
export function cacheTtlSecFromHeader(cacheControl: string | null): number {
  const m = /max-age=(\d+)/.exec(cacheControl ?? "");
  if (!m) return CACHE_TTL_DEFAULT_SEC;
  const n = Number(m[1]);
  return Math.min(CACHE_TTL_MAX_SEC, Math.max(CACHE_TTL_MIN_SEC, n));
}

function parseCimdDocument(clientId: string, raw: string): CimdClient | null {
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return null;
  const d = doc as Record<string, unknown>;
  // MUST: 文書の client_id は document URL と完全一致 (単純文字列比較、正規化なし)
  if (d["client_id"] !== clientId) return null;
  // MUST: client_name / redirect_uris を含む (MCP spec の required properties)
  if (typeof d["client_name"] !== "string" || d["client_name"] === "") return null;
  const uris = d["redirect_uris"];
  if (!Array.isArray(uris) || uris.length === 0) return null;
  if (!uris.every((x) => typeof x === "string")) return null;
  // 本 AS は public client のみ (DCR と同じ)。他の auth 方式を要求する文書は拒否
  const tam = d["token_endpoint_auth_method"];
  if (tam !== undefined && tam !== "none") return null;
  const scope = d["scope"];
  return {
    client_id: clientId,
    client_name: d["client_name"],
    redirect_uris: uris as string[],
    ...(typeof scope === "string" ? { scope } : {}),
  };
}

/**
 * CIMD 文書を取得・検証して返す。失敗 (取得不能 / 検証 NG) は null —
 * 呼び出し側 (`/authorize`) は DCR 不明 client と同じ `invalid_client` 400 にする。
 *
 * @param fetchImpl テスト注入用 (binding-jwt の `introspectFetch` と同じ流儀)
 */
export async function fetchCimdClient(
  env: Env,
  clientId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<CimdClient | null> {
  const kv = env.MCP_OAUTH_KV;
  const cacheKey = `cimd:client:${clientId}`;
  if (kv) {
    const cached = await kv.get(cacheKey);
    if (cached) {
      const parsed = parseCimdDocument(clientId, cached);
      if (parsed) return parsed;
      // cache が壊れていたら fetch し直す (fallthrough)
    }
  }

  let resp: Response;
  try {
    resp = await fetchImpl(clientId, {
      redirect: "error",
      signal: AbortSignal.timeout(CIMD_FETCH_TIMEOUT_MS),
      headers: {
        Accept: "application/json",
        "User-Agent": "auth-worker-cimd",
      },
    });
  } catch {
    return null;
  }
  if (!resp.ok) return null;
  const contentLength = Number(resp.headers.get("content-length") ?? "0");
  if (contentLength > CIMD_MAX_BODY_BYTES) return null;
  let raw: string;
  try {
    raw = await resp.text();
  } catch {
    return null;
  }
  if (raw.length > CIMD_MAX_BODY_BYTES) return null;

  const client = parseCimdDocument(clientId, raw);
  if (!client) return null;

  if (kv) {
    await kv.put(cacheKey, raw, {
      expirationTtl: cacheTtlSecFromHeader(resp.headers.get("cache-control")),
    });
  }
  return client;
}
