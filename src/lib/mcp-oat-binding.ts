/**
 * Anthropic OAT (`sk-ant-oat01-...`) → github_login binding KV layer
 * (issue ippoan/auth-worker#174)。
 *
 * CCoW container 内に存在する OAT は Anthropic identity endpoint (例:
 * `/v1/organizations/me`) で **403 "Authentication method not allowed"** を
 * 返すため、OAT alone で auth-worker が user identity を引く path は無い。
 * 本 layer は OAT の sha256 hash を key にして、別経路で確立した github_login
 * (issue #174 設計: GitHub issue comment の `comment.user.login` を root-of-trust
 * とする `POST /mcp/pair/register-via-github-comment`) を 30 日 TTL で記録する。
 *
 * Fresh container 起動時の流れ:
 *   1. install-mcp-relay hook が `POST /mcp/pair/grant-via-oat` を OAT で叩く
 *   2. auth-worker は OAT_hash を本 layer で lookup → github_login を引く
 *   3. 引けたら binding_jwt を mint、引けなかったら 404 (= register が必要)
 *
 * KV schema:
 *   - `oat_hash:<sha256(oat)>` → JSON OatBindingRecord (TTL 30d)
 *
 * Token そのものは KV に書かない (leak 耐性のため、`mcp/pair_refresh/<hash>`
 * と同じ思想)。OAT rotation 時は単に 30 日 TTL で expire させて再 binding。
 */

import type { Env } from "../index";

export interface OatBindingRecord {
  /** GitHub OAuth identity (root-of-trust: register endpoint 経由で
   *  `comment.user.login` から取得済み)。 */
  github_login: string;
  /** ms epoch — binding 確立時刻。 */
  bound_at: number;
  /** ms epoch (= bound_at + OAT_BINDING_TTL_SEC * 1000)。 */
  expires_at: number;
}

/** 30 日 hard expiry。OAT rotation 間隔 (Anthropic 公式 docs では明示無いが
 *  実測 90 日以上) + α を吸収。grant 毎に伸びない (rotation 無しの MVP)。 */
export const OAT_BINDING_TTL_SEC = 30 * 24 * 60 * 60;

/**
 * Anthropic OAT の SHA-256 を hex で返す。KV key の `oat_hash:<hex>` 部分に使う。
 * Token そのものは KV に書かないため、leak 時にも逆引き不可。
 *
 * `mcp-pair.ts` の `hashRefreshToken` と同じアルゴリズムだが、用途を区別する
 * ため別関数として export する (mismatch 防止 + 将来 OAT format が変わった時に
 * 局所変更しやすい)。
 */
export async function hashOat(token: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const bytes = new Uint8Array(buf);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i] as number).toString(16).padStart(2, "0");
  }
  return hex;
}

export async function getOatBinding(
  env: Env,
  oatHash: string,
): Promise<OatBindingRecord | null> {
  if (!env.MCP_OAUTH_KV) return null;
  const json = await env.MCP_OAUTH_KV.get(`oat_hash:${oatHash}`);
  if (!json) return null;
  try {
    return JSON.parse(json) as OatBindingRecord;
  } catch {
    return null;
  }
}

export async function putOatBinding(
  env: Env,
  oatHash: string,
  rec: OatBindingRecord,
): Promise<void> {
  if (!env.MCP_OAUTH_KV) throw new Error("MCP_OAUTH_KV not bound");
  // KV expirationTtl 最小値 60s を尊重。expires_at が極端に近い (test fixture
  // のような) 場合でも 60s 下限を入れる。
  const remainingSec = Math.max(60, Math.floor((rec.expires_at - Date.now()) / 1000));
  await env.MCP_OAUTH_KV.put(
    `oat_hash:${oatHash}`,
    JSON.stringify(rec),
    { expirationTtl: remainingSec },
  );
}
