/**
 * Anthropic OAT / org_uuid → github_login binding KV layer
 * (issues ippoan/auth-worker#174, #176)。
 *
 * CCoW container 内に存在する OAT は Anthropic identity endpoint (例:
 * `/v1/organizations/me`) で **403 "Authentication method not allowed"** を
 * 返すため、OAT alone で auth-worker が user identity を引く path は無い。
 * 本 layer は OAT の sha256 hash と、`/v1/models` response header から得られる
 * `anthropic-organization-id` (= account-stable な UUID) の両方を key にして、
 * 別経路で確立した github_login (issue #174 設計: GitHub issue comment の
 * `comment.user.login` を root-of-trust とする
 * `POST /mcp/pair/register-via-github-comment`) を 30 日 TTL で記録する。
 *
 * KV schema:
 *   - `org_uuid:<uuid>`      → JSON OatBindingRecord (TTL 30d) — primary key,
 *                              container reclaim 越し stable (= #176 silent path)
 *   - `oat_hash:<sha256(oat)>` → JSON OatBindingRecord (TTL 30d) — legacy/compat key,
 *                                container 単位で rotate (= #174 path)
 *
 * Fresh container 起動時の流れ (post-#176):
 *   1. install.sh / hook が `POST /mcp/pair/grant-via-oat` を OAT で叩く
 *   2. auth-worker が `/v1/models` を OAT で叩いて `anthropic-organization-id`
 *      header から org_uuid を取得
 *   3. `org_uuid:<uuid>` を lookup → hit なら binding_jwt mint
 *   4. miss なら `oat_hash:<hash>` を fallback lookup (#174 migration 用)
 *      hit なら同時に `org_uuid:<uuid>` に write-through (lazy migration)
 *   5. 両方 miss なら 404 (= register が必要)
 *
 * Token そのものは KV に書かない (leak 耐性のため、`mcp/pair_refresh/<hash>`
 * と同じ思想)。OAT rotation 時は org_uuid が変わらないので binding 維持。
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

/** Strict v4 / v8 UUID 形式 (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` lowercase
 *  hex)。Anthropic が attach する `anthropic-organization-id` header の値が
 *  unsanitized で KV key に concat される箇所があるため、format validation で
 *  KV key injection を遮断する。 */
const ORG_UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function isValidOrgUuid(uuid: string): boolean {
  return ORG_UUID_RE.test(uuid);
}

export async function getOrgBinding(
  env: Env,
  orgUuid: string,
): Promise<OatBindingRecord | null> {
  if (!env.MCP_OAUTH_KV) return null;
  if (!isValidOrgUuid(orgUuid)) return null;
  const json = await env.MCP_OAUTH_KV.get(`org_uuid:${orgUuid}`);
  if (!json) return null;
  try {
    return JSON.parse(json) as OatBindingRecord;
  } catch {
    return null;
  }
}

export async function putOrgBinding(
  env: Env,
  orgUuid: string,
  rec: OatBindingRecord,
): Promise<void> {
  if (!env.MCP_OAUTH_KV) throw new Error("MCP_OAUTH_KV not bound");
  if (!isValidOrgUuid(orgUuid)) {
    throw new Error(`invalid org_uuid format: ${orgUuid}`);
  }
  const remainingSec = Math.max(60, Math.floor((rec.expires_at - Date.now()) / 1000));
  await env.MCP_OAUTH_KV.put(
    `org_uuid:${orgUuid}`,
    JSON.stringify(rec),
    { expirationTtl: remainingSec },
  );
}

/**
 * Anthropic API response から `anthropic-organization-id` header を抽出し、
 * UUID 形式を validate して返す。
 *
 * `/v1/models` を Bearer OAT で叩くと response に server-side で attach される
 * (= env spoofing 不可、OAT に紐付く account-stable な org UUID)。本関数は
 * `mcp-pair-grant-via-oat.ts` / `mcp-pair-register-via-github-comment.ts` の
 * 両方で OAT verification と同 fetch から再利用する。
 *
 * 不正 (header 欠落 / UUID 形式違反) は null を返す。caller 側で legacy oat_hash
 * fallback path に流すか 502 で返すかを決める。
 */
export function extractOrgUuidFromResponse(res: Response): string | null {
  const raw = res.headers.get("anthropic-organization-id");
  if (!raw) return null;
  const normalized = raw.trim().toLowerCase();
  return isValidOrgUuid(normalized) ? normalized : null;
}
