/**
 * `POST /dev-login/token` (issue #424)
 *
 * `issue_dev_login_url` MCP tool が返す
 * `http://localhost:<port>/__dev/callback?code=...` を人間が開くと、consumer
 * 側 (`__dev/callback`、issue #425 / `@ippoan/auth-client`、本ファイルのスコープ
 * 外) がこの endpoint を edge 上から server-to-server で叩いて code → dev JWT
 * に交換する。
 *
 * code は60秒 TTL・単回使用 (`consumeDevLoginCode`、get→delete)。dev JWT 自体は
 * `issue_dev_login_url` 発行時点で mint 済みのものをそのまま返す (再ミントし
 * ない) ので、`expires_in` は token 自身の `exp` claim から逆算する。
 */
import type { Env } from "../index";
import { consumeDevLoginCode, DEV_TOKEN_TTL_SEC } from "../lib/dev-login";
import { jsonResponse } from "../lib/errors";
import { decodeJwtPayload } from "../lib/jwt";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export async function handleDevLoginToken(request: Request, env: Env): Promise<Response> {
  if (!env.MCP_OAUTH_KV) {
    return jsonResponse(
      { error: "server_error", error_description: "dev-login not configured" },
      503,
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonResponse(
      { error: "invalid_request", error_description: "expected JSON body" },
      400,
    );
  }
  const code = isObject(body) && typeof body["code"] === "string" ? body["code"] : "";
  if (!code) {
    return jsonResponse(
      { error: "invalid_request", error_description: "code is required" },
      400,
    );
  }

  const token = await consumeDevLoginCode(env, code);
  if (!token) {
    return jsonResponse(
      { error: "invalid_grant", error_description: "code is invalid, expired, or already used" },
      400,
    );
  }

  const claims = decodeJwtPayload(token);
  const nowSec = Math.floor(Date.now() / 1000);
  const expiresIn =
    typeof claims?.exp === "number" ? Math.max(0, claims.exp - nowSec) : DEV_TOKEN_TTL_SEC;

  return jsonResponse({
    access_token: token,
    token_type: "Bearer",
    expires_in: expiresIn,
  });
}
