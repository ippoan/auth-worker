/**
 * LINE WORKS Bot の認証情報 (Service Account の秘密鍵を含む) を rust-alc-api から取る。
 *
 * rust の `/api/admin/bot/configs*` は #434 lockdown 後 `require_tenant_header` 配下で、
 * `X-Tenant-ID` 等の identity header と OIDC transport が要る。token (browser JWT か
 * dev JWT) を `buildAdminForwardHeaders` で検証して転送する (api-bot-config.ts と同じ作法)。
 * 以前 api-rich-menu.ts が raw Bearer で直 fetch していた版は、tenant header が無く 401 に
 * なっていた。Rich Menu と MCP tool `lineworks_get` がここを共有する。
 *
 * 戻り値の `BotCredentials` は秘密鍵を含む。**応答やログに出さないこと。**
 */

import type { Env } from "../index";
import type { BotConfigListResponse } from "../types/alc-api";
import type { BotCredentials } from "./lineworks-bot-api";
import { buildAdminForwardHeaders } from "./admin-proxy";

async function adminHeaders(env: Env, token: string, event: string): Promise<Record<string, string>> {
  const headers = await buildAdminForwardHeaders(token, env, event);
  if (!headers) throw new Error("Unauthorized");
  return headers;
}

/** `botConfigId` の復号済み認証情報を返す (rust 側で caller の tenant に絞られる)。 */
export async function getCredsFromConfig(
  env: Env,
  token: string,
  botConfigId: string,
): Promise<BotCredentials> {
  const headers = await adminHeaders(env, token, "bot_config_secrets");
  const resp = await fetch(
    `${env.ALC_API_ORIGIN}/api/admin/bot/configs/${encodeURIComponent(botConfigId)}/secrets`,
    { headers },
  );
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Failed to get bot config: ${resp.status} ${text}`);
  }
  const c = (await resp.json()) as {
    client_id: string;
    client_secret: string;
    service_account: string;
    private_key: string;
    bot_id: string;
  };
  return {
    clientId: c.client_id,
    clientSecret: c.client_secret,
    serviceAccount: c.service_account,
    privateKey: c.private_key,
    botId: c.bot_id,
  };
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
