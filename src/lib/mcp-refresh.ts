/**
 * MCP OAuth Provider — refresh_token issue / consume (KV-backed rotation).
 *
 * RFC 6749 §6 refresh token grant の補助。Phase 3 `/mcp/token` で device_code grant の
 * 成功時 + refresh_token grant の rotation 時に発行 / 消費する。
 *
 * Design:
 *  - Token: 256bit (32B) ランダム hex 文字列。client 側にのみ raw 値を返す
 *  - KV key: `refresh:{sha256(token) hex}` ※ raw token は KV に書かない
 *  - KV value: JSON `{ sub, scope, github_login, expires_at, rotated_from? }`
 *  - TTL: 30 日 (REFRESH_TTL_SEC)
 *  - Rotation: consume は旧 record を **grace record (60s) へ置換**する。
 *    rotation 直後の旧 token 再使用 (= 並列 fan-out / 応答消失 retry / KV
 *    eventual consistency の stale read) には **同じ新 pair をそのまま返す**
 *    ことで session 永続死を防ぐ (Refs #270)。
 *
 * 旧実装は **delete-first** で、rotation 直後に旧 token を再提示すると
 * `invalid_grant: already used` で session が死んでいた。delete-first は
 * 「server が新 pair を返したが client 側 fetch が timeout / waitUntil cancel
 * で storeTokens に到達しない」応答消失でも (並列が無くても) 確率的に session
 * を永続破壊する。grace 再使用がこの両方の解毒剤。
 *
 * KV は atomic でないため、grace 置換が書かれる前に 2 並列が同時に通常 record
 * を読むと double-rotation (= 2 つの有効な新 pair) は依然起き得る。これは
 * SDK 側の single-flight (Refs #270 PR2) で発生率を消す。server grace は
 * cross-isolate / cross-colo / 応答消失の残りを吸収する役割。
 */

import type { Env } from "../index";

export const REFRESH_TTL_SEC = 60 * 60 * 24 * 30; // 30 days
// rotation 直後の旧 token を受理する grace window。KV expirationTtl の最小値
// (60s) かつ KV 伝播遅延 (~60s) と整合させる。
export const GRACE_TTL_SEC = 60;

export interface RefreshRecord {
  sub: string;
  scope: string;
  github_login: string;
  /**
   * 初回発行時の JWT `aud` claim を保存しておき、rotation 時にそのまま継承する。
   * Authorization Code flow + RFC 8707 Resource Indicator なら MCP server origin、
   * Device Code flow (Rust binary) なら legacy `"github-mcp-server-rs"`。
   * 旧 KV value (Phase 3 deploy 前) には無いので optional。読み取り時に
   * fallback を caller 側で持つ。
   */
  aud?: string;
  expires_at: number; // ms epoch
  rotated_from?: string; // 旧 refresh hash (audit / double-spend 検出ログ用)
  /** consume が caller に返す用 (KV value には書かない、in-memory only) */
  hash: string;
}

/**
 * rotation 済みの旧 hash slot に書く grace record (Refs #270)。`refresh:{旧hash}`
 * の value を通常 record からこれに置換する (TTL = GRACE_TTL_SEC)。grace 窓内に
 * 旧 token が再提示されたら、ここに保存した **同一の新 pair** をそのまま返す。
 * 新 pair を再発行すると divergence (有効な refresh chain が枝分かれ) を再生産
 * するため、必ず保存済みの値を返すこと。
 *
 * raw refresh_token を KV に置くのは通常 record の方針 (raw を書かない) からの
 * 意図的な逸脱だが、TTL 60s の短命露出に留める。KV value を読める攻撃者は元々
 * record を偽造して同等のことが可能なので脅威モデル上は許容範囲。
 */
export interface RefreshGraceRecord {
  rotated: true;
  grace_until: number; // ms epoch
  access_token: string;
  refresh_token: string; // raw (新 pair)
  scope: string;
}

export type ConsumeResult =
  | { kind: "record"; record: RefreshRecord } // 通常 — caller が rotate + grace mark する
  | { kind: "grace"; grace: RefreshGraceRecord }; // rotation 直後の再使用 — 同一 pair を返す

function isGraceRecord(v: unknown): v is RefreshGraceRecord {
  return typeof v === "object" && v !== null && (v as { rotated?: unknown }).rotated === true;
}

/**
 * 新 refresh_token を発行して KV に `refresh:{hash}` で保存し、raw token を返す。
 * `rotated_from` を指定すると KV value に audit 用 hash を残す。
 */
export async function issueRefreshToken(
  env: Env,
  args: {
    sub: string;
    scope: string;
    github_login: string;
    aud?: string;
    rotated_from?: string;
  },
): Promise<string> {
  if (!env.MCP_OAUTH_KV) throw new Error("MCP_OAUTH_KV not bound");
  const raw = randomHex(32); // 256bit
  const hash = await sha256Hex(raw);
  const value: Omit<RefreshRecord, "hash"> = {
    sub: args.sub,
    scope: args.scope,
    github_login: args.github_login,
    expires_at: Date.now() + REFRESH_TTL_SEC * 1000,
    ...(args.aud ? { aud: args.aud } : {}),
    ...(args.rotated_from ? { rotated_from: args.rotated_from } : {}),
  };
  await env.MCP_OAUTH_KV.put(`refresh:${hash}`, JSON.stringify(value), {
    expirationTtl: REFRESH_TTL_SEC,
  });
  return raw;
}

/**
 * refresh_token を hash → KV lookup し、rotation 用に解決する (Refs #270)。
 *
 *  - 通常 record (未 rotate)      → `{kind:"record"}`。**delete しない**。caller が
 *    新 pair を発行した後 `markRefreshRotated` で旧 hash を grace record に置換する。
 *  - grace record (rotation 直後) → grace 窓内なら `{kind:"grace"}` (caller は保存済み
 *    の同一 pair を返す)。grace 超過なら slot を消して `null`。
 *  - 不在 / expired / parse 失敗  → `null` (invalid_grant)。
 *
 * delete-first を廃したことで、rotation 直後の旧 token 再提示が grace で救済される。
 */
export async function consumeRefreshToken(
  env: Env,
  token: string,
): Promise<ConsumeResult | null> {
  if (!env.MCP_OAUTH_KV) throw new Error("MCP_OAUTH_KV not bound");
  const hash = await sha256Hex(token);
  const json = await env.MCP_OAUTH_KV.get(`refresh:${hash}`);
  if (!json) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }

  if (isGraceRecord(parsed)) {
    // rotation 直後の旧 token 再使用。grace 窓内なら同一 pair を返す。
    if (parsed.grace_until < Date.now()) {
      // grace 超過。slot を掃除して invalid_grant に倒す。
      await env.MCP_OAUTH_KV.delete(`refresh:${hash}`);
      return null;
    }
    return { kind: "grace", grace: parsed };
  }

  const record = parsed as Omit<RefreshRecord, "hash">;
  if (typeof record.expires_at !== "number" || record.expires_at < Date.now()) {
    return null;
  }
  return { kind: "record", record: { ...record, hash } };
}

/**
 * rotation で旧 hash slot を grace record (TTL GRACE_TTL_SEC) に置換する (Refs #270)。
 * これ以降 grace 窓内に旧 token が再提示されたら同一の新 pair が返る。
 * 旧 record の 30 日 TTL は上書きされ、grace 超過 (60s) で slot は自然消滅する。
 */
export async function markRefreshRotated(
  env: Env,
  oldHash: string,
  replacement: { access_token: string; refresh_token: string; scope: string },
): Promise<void> {
  if (!env.MCP_OAUTH_KV) throw new Error("MCP_OAUTH_KV not bound");
  const grace: RefreshGraceRecord = {
    rotated: true,
    grace_until: Date.now() + GRACE_TTL_SEC * 1000,
    access_token: replacement.access_token,
    refresh_token: replacement.refresh_token,
    scope: replacement.scope,
  };
  await env.MCP_OAUTH_KV.put(`refresh:${oldHash}`, JSON.stringify(grace), {
    expirationTtl: GRACE_TTL_SEC,
  });
}

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}
