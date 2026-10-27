/**
 * GCP 委譲 surface (`/mcp/google-gcp`、issue #691) の refresh token 保管と、
 * それを使った短命アクセストークンの発行。
 *
 * - refresh token は `SSO_ENCRYPTION_KEY` で暗号化して `MCP_OAUTH_KV` の
 *   `google_gcp_rt:<email>` に置く (GitHub トークン `github_token:<sub>` と同じ方式)
 * - 外に出すのはアクセストークン (1 時間) だけ。refresh token は auth-worker の外に出さない
 * - Google が `invalid_grant` を返したら (失効・取り消し・Testing の 7 日切れ) 保管分を消し、
 *   `reauthorize_required` を返す。呼び手は「MCP を繋ぎ直す」案内を出す
 *
 * 値 (refresh / access token) は log に出さない。
 */
import type { Env } from "../index";
import { decryptWithKey, encryptWithKey } from "./mcp-crypto";
import { resolveSecret } from "./secret";

const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";

export function gcpRefreshTokenKey(email: string): string {
  return `google_gcp_rt:${email.toLowerCase()}`;
}

/** refresh token を暗号化して保管する。鍵が無ければ false (呼び手は認可を失敗させる)。 */
export async function storeGcpRefreshToken(
  env: Env,
  email: string,
  refreshToken: string,
): Promise<boolean> {
  const ssoKey = await resolveSecret(env.SSO_ENCRYPTION_KEY);
  if (!ssoKey || !env.MCP_OAUTH_KV) return false;
  await env.MCP_OAUTH_KV.put(gcpRefreshTokenKey(email), await encryptWithKey(refreshToken, ssoKey));
  return true;
}

export type GcpAccessTokenResult =
  | { ok: true; accessToken: string; expiresIn: number }
  | { ok: false; error: "reauthorize_required" | "server_error" };

/** 保管した refresh token で Google から短命アクセストークンを取る。 */
export async function exchangeGcpAccessToken(
  env: Env,
  email: string,
  fetchImpl: typeof fetch = fetch,
): Promise<GcpAccessTokenResult> {
  const [ssoKey, clientId, clientSecret] = await Promise.all([
    resolveSecret(env.SSO_ENCRYPTION_KEY),
    resolveSecret(env.GOOGLE_CLIENT_ID),
    resolveSecret(env.GOOGLE_CLIENT_SECRET),
  ]);
  if (!ssoKey || !clientId || !clientSecret || !env.MCP_OAUTH_KV) {
    return { ok: false, error: "server_error" };
  }
  const key = gcpRefreshTokenKey(email);
  const encrypted = await env.MCP_OAUTH_KV.get(key);
  if (!encrypted) return { ok: false, error: "reauthorize_required" };

  let refreshToken: string;
  try {
    refreshToken = await decryptWithKey(encrypted, ssoKey);
  } catch {
    // 鍵が入れ替わった等。持っていても使えないので消して繋ぎ直してもらう
    await env.MCP_OAUTH_KV.delete(key);
    return { ok: false, error: "reauthorize_required" };
  }

  let res: Response;
  try {
    res = await fetchImpl(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });
  } catch {
    return { ok: false, error: "server_error" };
  }
  const body = (await res.json().catch(() => ({}))) as {
    access_token?: string;
    expires_in?: number;
    error?: string;
  };
  if (!res.ok) {
    if (body.error === "invalid_grant") {
      await env.MCP_OAUTH_KV.delete(key);
      return { ok: false, error: "reauthorize_required" };
    }
    return { ok: false, error: "server_error" };
  }
  if (!body.access_token) return { ok: false, error: "server_error" };
  return { ok: true, accessToken: body.access_token, expiresIn: body.expires_in ?? 3600 };
}
