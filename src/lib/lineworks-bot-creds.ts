/**
 * LINE WORKS Bot の access token を alc-lineworks worker (Service Binding `ALC_LINEWORKS`) から取る。
 *
 * Client Secret と Private Key を扱うのは alc-lineworks だけで、auth-worker は受け取らない
 * (以前は rust-alc-api の bot config の秘密の取り出し口から 4 値を取り、JWT を自分で署名
 * していた。Refs ohishi-exp/rust-leave-worker#1)。Rich Menu と MCP tool `lineworks_get` が
 * ここを共有する。
 *
 * token の口 (`POST /api/internal/lineworks/token`) は認証も role の検査も持たない
 * (届くのはこの binding だけ)。tenant は呼び手の JWT を検証して auth-worker が付ける
 * `X-Tenant-ID` で決まり、**tenant の管理者だけに限る検査はここで行う** (rust の秘密の取り出し口が
 * `role == "admin"` を課していたのと同じ線)。
 *
 * 戻り値の `BotAccess` は access token を含む。**応答やログに出さないこと。**
 */

import type { Env } from "../index";
import type { BotConfigListResponse } from "../types/alc-api";
import type { BotAccess } from "./lineworks-bot-api";
import { buildAdminForwardHeaders } from "./admin-proxy";
import { verifyJwt } from "./jwt";
import { resolveSecret } from "./secret";

/** alc-lineworks の token の口 (host はダミー。binding は URL の host で経路が決まらない)。 */
const TOKEN_URL = "https://alc-lineworks/api/internal/lineworks/token";

async function adminHeaders(env: Env, token: string, event: string): Promise<Record<string, string>> {
  const headers = await buildAdminForwardHeaders(token, env, event);
  if (!headers) throw new Error("Unauthorized");
  return headers;
}

/**
 * caller の tenant の `botConfigId` の Bot で、`scope` の access token を取る
 * (`scope` は今の呼び手の値をそのまま: Rich Menu = `bot`、`lineworks_get` = `board.read` /
 * `directory.read`。許可リストは alc-lineworks の側に在る)。
 *
 * 失敗はすべて throw: JWT が検証できない → `Unauthorized` / 管理者でない → `Forbidden` /
 * binding 未定義 → `LINE WORKS worker not bound` / token の口が非 200 →
 * `Failed to get LINE WORKS token: <status> <error の語>` (上流の本文はそのまま載せない)。
 */
export async function getBotAccess(
  env: Env,
  token: string,
  botConfigId: string,
  scope = "bot",
): Promise<BotAccess> {
  const secret = await resolveSecret(env.JWT_SECRET);
  const claims = secret ? await verifyJwt(token, secret, env.WORKER_ENV) : null;
  if (!claims) throw new Error("Unauthorized");
  if (claims.role !== "admin") throw new Error("Forbidden");
  const binding = env.ALC_LINEWORKS;
  if (!binding) throw new Error("LINE WORKS worker not bound");

  const resp = await binding.fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "X-Tenant-ID": String(claims.tenant_id ?? ""),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ bot_config_id: botConfigId, scope }),
    redirect: "manual",
  });
  if (!resp.ok) {
    // alc-lineworks の失敗は `{error, message}`。載せるのは固定の語 (`error`) だけにする。
    const body = (await resp.json().catch(() => null)) as { error?: unknown } | null;
    const code = typeof body?.error === "string" ? body.error : "";
    throw new Error(`Failed to get LINE WORKS token: ${resp.status} ${code}`.trimEnd());
  }
  const data = (await resp.json()) as { access_token?: unknown; bot_id?: unknown };
  if (typeof data.access_token !== "string" || typeof data.bot_id !== "string") {
    throw new Error("Failed to get LINE WORKS token: malformed response");
  }
  return { accessToken: data.access_token, botId: data.bot_id };
}

/**
 * caller の tenant の LINE WORKS Bot (`provider == "lineworks"` かつ enabled) の id。
 * 複数あれば rust の一覧の順 (`ORDER BY name`) の先頭 — rust の `resolve_lineworks_config`
 * と同じ選び方に揃える (TS 側で並べ替えると照合順序がずれ、rust と別の Bot で叩いた
 * 結果を見ることになる)。無ければ null。
 */
export async function pickLineworksBotConfigId(env: Env, token: string): Promise<string | null> {
  const headers = await adminHeaders(env, token, "bot_config_list");
  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/bot/configs`, { headers });
  if (!resp.ok) {
    throw new Error(`Failed to list bot configs: ${resp.status}`);
  }
  const data = (await resp.json()) as BotConfigListResponse;
  const hit = data.configs.find((c) => c.provider === "lineworks" && c.enabled);
  return hit ? hit.id : null;
}
