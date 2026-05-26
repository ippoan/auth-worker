/**
 * MCP OAuth Provider — 1-click pair flow KV layer (issue #144 / #157 /
 * consumer: ippoan/github-mcp-server-rs#42, #57 — archived; monorepo successor: ippoan/mcp-relay-rs)。
 *
 * Device flow と並行する代替認証経路で、binary は CLI prompt 無しで pair_code
 * を取得し、ブラウザは auth-worker 側 sticky cookie session で「自分が誰か」を
 * 1 click で証明する。binary 側 WS upgrade は Bearer <pair_code> を一時 JWT
 * 代替として受け取り、KV record の status=approved を確認してから本物の
 * binding_jwt に内部置換して接続する (`mcp-relay-connect.ts` 側で扱う)。
 *
 * issue #157 で「30 日間 0 click」を加えるため、approve 時に 30 日 TTL の
 * opaque refresh_token を mint して `mcp/pair_refresh/<sha256>` に格納する。
 * binary は WS upgrade 101 response の `Pair-Refresh-Token` header で受け取り、
 * 次回 fresh container 起動時に `POST /mcp/pair/grant` でそのまま 24h binding_jwt
 * に交換する。refresh_token は不可逆 hash で保存し、KV 漏洩時にも逆引き不可。
 *
 * KV schema:
 *   - `mcp/pair/<code>`           → JSON PairRecord (TTL 300s)
 *   - `mcp/pair_refresh/<sha256>` → JSON PairRefreshRecord (TTL 30d)
 *   - `mcp/pair_grant_rate/<sha256>/<minute>` → counter (TTL 120s, 10/min)
 *
 * status:
 *   - "pending"  — `POST /mcp/pair/new` で生成された直後
 *   - "approved" — ブラウザが `GET /mcp/pair/<code>` で session_github_login と
 *                  claim_login の一致を確認し、binding_jwt が焼かれた状態
 */

import type { Env } from "../index";

export interface PairRecord {
  pair_code: string;
  claim_login: string;
  binary_version: string;
  created_at: number; // ms epoch
  expires_at: number; // ms epoch (created_at + 300_000)
  status: "pending" | "approved";
  /** approve 後の MCP access JWT (aud=github-mcp-server-rs, ttl=24h)。
   *  WS upgrade で pair_code を受け取った時に内部的にこれへ置換する。 */
  binding_jwt: string | null;
  /**
   * binding_jwt に焼き込む MCP scope。pair_code 発行時にクライアントが
   * `POST /mcp/pair/new` の `requested_scope` で要求した値を normalize した
   * space-separated 文字列。
   *
   * legacy record (この field が無い) は `"mcp.read mcp.write"` 相当として扱う
   * (backward compat — `mcp-pair-claim.ts` 側で `??` 補完)。
   *
   * 例:
   *  - `"mcp.read mcp.write"` (default) — 既存 binary の挙動
   *  - `"mcp.admin"`                   — branch protection 専用 token
   *                                       (binary 側 factory が 3 tools のみ expose)
   */
  requested_scope?: string;
  /**
   * issue #157: 30 日 refresh_token (opaque, base64url 43 char)。
   * approve 直後に mint され、WS upgrade 101 の `Pair-Refresh-Token` header で
   * binary に渡る。pair record は 5 min で消えるが、refresh_token 本体は
   * 別 key (`mcp/pair_refresh/<hash>`) に 30 日保持される。
   * legacy / pre-#157 record はこの field を持たない。
   */
  refresh_token?: string;
  /** ms epoch (= refresh_token_issued_at + 30d)。`mcp/pair_refresh/<hash>` の
   *  `expires_at` と同じ値。binary 側が事前に切替判定するためにも返す。 */
  refresh_token_expires_at?: number;
}

/**
 * `mcp/pair_refresh/<sha256(token)>` に保存される 30 日 refresh_token 記録
 * (issue #157)。token そのものは保持せず、sha256 を key にする (KV 漏洩耐性)。
 *
 * - `github_login` — grant 時に binding_jwt の `github_login` claim に使う
 * - `requested_scope` — 元 pair で焼いた binding_jwt と同じ scope を再現する
 *                       (rotate 無しの MVP では grant 毎に同じ scope が出る)
 * - `created_at` / `expires_at` — 30 日 hard expiry
 * - `last_used_at` — grant 毎に bump (sliding window 観測用)
 * - `revoked` — Phase C の revoke 経路で `true` に書く (今 PR では reader 側のみ)
 */
export interface PairRefreshRecord {
  github_login: string;
  requested_scope: string;
  created_at: number; // ms epoch
  expires_at: number; // ms epoch
  last_used_at: number | null;
  revoked: boolean;
}

/** issue #144 spec: 5 min。binary 側 polling (2s 間隔 / 最大 5 min) と一致。 */
export const PAIR_CODE_TTL_SEC = 300;

/** issue #157 spec: 30 日 hard expiry。grant 毎に伸びない (rotation も MVP では無し)。 */
export const PAIR_REFRESH_TTL_SEC = 30 * 24 * 60 * 60;

export async function putPair(env: Env, rec: PairRecord): Promise<void> {
  if (!env.MCP_OAUTH_KV) throw new Error("MCP_OAUTH_KV not bound");
  await env.MCP_OAUTH_KV.put(`mcp/pair/${rec.pair_code}`, JSON.stringify(rec), {
    expirationTtl: PAIR_CODE_TTL_SEC,
  });
}

export async function getPair(
  env: Env,
  pair_code: string,
): Promise<PairRecord | null> {
  if (!env.MCP_OAUTH_KV) return null;
  const json = await env.MCP_OAUTH_KV.get(`mcp/pair/${pair_code}`);
  if (!json) return null;
  try {
    return JSON.parse(json) as PairRecord;
  } catch {
    return null;
  }
}

/**
 * status="approved" + binding_jwt を atomic に書き込む。残 TTL を保つ。
 * issue #157: `refresh_token` / `refresh_token_expires_at` が渡された場合は
 * 同 record に焼き込む (WS upgrade で binary に渡すため)。
 * record 不在 / KV 未 bind → null。
 */
export async function approvePair(
  env: Env,
  pair_code: string,
  binding_jwt: string,
  refresh?: { token: string; expires_at: number },
): Promise<PairRecord | null> {
  if (!env.MCP_OAUTH_KV) return null;
  const rec = await getPair(env, pair_code);
  if (!rec) return null;
  const updated: PairRecord = {
    ...rec,
    status: "approved",
    binding_jwt,
    ...(refresh
      ? {
          refresh_token: refresh.token,
          refresh_token_expires_at: refresh.expires_at,
        }
      : {}),
  };
  // KV expirationTtl の minimum は 60s。残 TTL がそれ未満なら 60s に丸める。
  const remainingSec = Math.max(
    60,
    Math.floor((rec.expires_at - Date.now()) / 1000),
  );
  await env.MCP_OAUTH_KV.put(
    `mcp/pair/${pair_code}`,
    JSON.stringify(updated),
    { expirationTtl: remainingSec },
  );
  return updated;
}

/** WS upgrade 成功後に 1 回限り削除する (pair_code 再利用防止)。 */
export async function deletePair(env: Env, pair_code: string): Promise<void> {
  if (!env.MCP_OAUTH_KV) return;
  await env.MCP_OAUTH_KV.delete(`mcp/pair/${pair_code}`);
}

/**
 * 同一 IP からの POST /mcp/pair/new を 1 分窓で 10 回までに制限する。
 * Cloudflare KV の eventual consistency 上、厳密 limit ではないが
 * abuse 抑止 (botnet による pair_code 大量生成) には十分。
 *
 * 戻り値: 制限を越えていれば false (= reject)。bind 不在は許容 (true)。
 */
export async function checkAndBumpRateLimit(
  env: Env,
  ip: string,
  now: number,
  limitPerMinute = 10,
): Promise<boolean> {
  if (!env.MCP_OAUTH_KV) return true;
  const minute = Math.floor(now / 60_000);
  const key = `mcp/pair_rate/${ip}/${minute}`;
  const cur = await env.MCP_OAUTH_KV.get(key);
  const n = cur ? Number.parseInt(cur, 10) : 0;
  if (!Number.isFinite(n) || n >= limitPerMinute) return false;
  await env.MCP_OAUTH_KV.put(key, String(n + 1), { expirationTtl: 120 });
  return true;
}

// ────────────────────────────────────────────────────────────────────────
// issue #157 — 30 日 refresh_token grant flow helpers
// ────────────────────────────────────────────────────────────────────────

/**
 * Opaque refresh_token 生成。32 byte (256 bit) を base64url encode して
 * 43 char。pair_code (30 byte → 40 char) と被らない長さなので
 * `mcp-relay-connect.ts` の PAIR_CODE_REGEX (`{30,60}`) との衝突可能性は無視できる。
 *
 * `Pair-Refresh-Token` header / `POST /mcp/pair/grant` の Bearer に直接乗る
 * 形式なので URL-safe charset を守る。
 */
export function generatePairRefreshToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] as number);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * `refresh_token` の SHA-256 を hex で返す。KV key の左半分に使う
 * (token そのものは KV に書かない — leak 耐性のため)。
 *
 * 同じ token なら同じ hash が出るので、grant 時の lookup も `POST` body / header の
 * 生 token を hash して KV key を組み立てる。
 */
export async function hashRefreshToken(token: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const bytes = new Uint8Array(buf);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i] as number).toString(16).padStart(2, "0");
  }
  return hex;
}

export async function putPairRefresh(
  env: Env,
  tokenHash: string,
  rec: PairRefreshRecord,
): Promise<void> {
  if (!env.MCP_OAUTH_KV) throw new Error("MCP_OAUTH_KV not bound");
  // expirationTtl は秒。expires_at は ms。残り < 60s ならそもそも mint する意味が
  // 無いが、防御的に 60s 下限を入れる。30 日 TTL を直接渡すと CF KV の最大値
  // (約 365 日) 余裕で内側。
  const remainingSec = Math.max(60, Math.floor((rec.expires_at - Date.now()) / 1000));
  await env.MCP_OAUTH_KV.put(
    `mcp/pair_refresh/${tokenHash}`,
    JSON.stringify(rec),
    { expirationTtl: remainingSec },
  );
}

export async function getPairRefresh(
  env: Env,
  tokenHash: string,
): Promise<PairRefreshRecord | null> {
  if (!env.MCP_OAUTH_KV) return null;
  const json = await env.MCP_OAUTH_KV.get(`mcp/pair_refresh/${tokenHash}`);
  if (!json) return null;
  try {
    return JSON.parse(json) as PairRefreshRecord;
  } catch {
    return null;
  }
}

/**
 * `last_used_at` を `now` に更新して KV に書き戻す。残り TTL を再計算して
 * 保つ (= grant 毎に TTL を伸ばさない — 30 日 hard expiry を守る)。
 * record 不在 → 何もしない。
 */
export async function touchPairRefresh(
  env: Env,
  tokenHash: string,
  now: number,
): Promise<PairRefreshRecord | null> {
  if (!env.MCP_OAUTH_KV) return null;
  const rec = await getPairRefresh(env, tokenHash);
  if (!rec) return null;
  const updated: PairRefreshRecord = { ...rec, last_used_at: now };
  const remainingSec = Math.max(60, Math.floor((rec.expires_at - now) / 1000));
  await env.MCP_OAUTH_KV.put(
    `mcp/pair_refresh/${tokenHash}`,
    JSON.stringify(updated),
    { expirationTtl: remainingSec },
  );
  return updated;
}

/**
 * `POST /mcp/pair/grant` の per-refresh_token rate limit (10/min)。
 * `checkAndBumpRateLimit` (per-IP) と別 keyspace。
 *
 * 同じ refresh_token を持つ複数 container が同時に大量 grant を叩いた場合の
 * abuse 抑止。bind 不在は true (best-effort)。
 */
export async function checkAndBumpGrantRateLimit(
  env: Env,
  tokenHash: string,
  now: number,
  limitPerMinute = 10,
): Promise<boolean> {
  if (!env.MCP_OAUTH_KV) return true;
  const minute = Math.floor(now / 60_000);
  const key = `mcp/pair_grant_rate/${tokenHash}/${minute}`;
  const cur = await env.MCP_OAUTH_KV.get(key);
  const n = cur ? Number.parseInt(cur, 10) : 0;
  if (!Number.isFinite(n) || n >= limitPerMinute) return false;
  await env.MCP_OAUTH_KV.put(key, String(n + 1), { expirationTtl: 120 });
  return true;
}
