/**
 * MCP OAuth Provider — 1-click pair flow KV layer (issue #144 / consumer:
 * ippoan/github-mcp-server-rs#42)。
 *
 * Device flow と並行する代替認証経路で、binary は CLI prompt 無しで pair_code
 * を取得し、ブラウザは auth-worker 側 sticky cookie session で「自分が誰か」を
 * 1 click で証明する。binary 側 WS upgrade は Bearer <pair_code> を一時 JWT
 * 代替として受け取り、KV record の status=approved を確認してから本物の
 * binding_jwt に内部置換して接続する (`mcp-relay-connect.ts` 側で扱う)。
 *
 * KV schema:
 *   - `mcp/pair/<code>` → JSON PairRecord (TTL 300s)
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
}

/** issue #144 spec: 5 min。binary 側 polling (2s 間隔 / 最大 5 min) と一致。 */
export const PAIR_CODE_TTL_SEC = 300;

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
 * record 不在 / KV 未 bind → null。
 */
export async function approvePair(
  env: Env,
  pair_code: string,
  binding_jwt: string,
): Promise<PairRecord | null> {
  if (!env.MCP_OAUTH_KV) return null;
  const rec = await getPair(env, pair_code);
  if (!rec) return null;
  const updated: PairRecord = { ...rec, status: "approved", binding_jwt };
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
