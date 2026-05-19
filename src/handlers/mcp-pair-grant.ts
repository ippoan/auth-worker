/**
 * `POST /mcp/pair/grant` (issue #157 Phase B) — refresh_token → binding_jwt 交換。
 *
 * Phase A (`mcp-pair-claim.ts` / `mcp-relay-connect.ts`) で配布された 30 日
 * opaque refresh_token を提示すると、ブラウザ click 無しで 24h binding_jwt と
 * MCP relay URL を再発行する。CCoW container が立つたびに browser を踏ませない
 * のが目的 (= 「初回 1 click → 30 日間 0 click」)。
 *
 * Auth model:
 *   Headers: Authorization: Bearer <opaque refresh_token>
 *   Body:    { binary_version, binary_fingerprint? }
 *
 * Response:
 *   200 → {
 *     binding_jwt:  <24h MCP JWT aud=github-mcp-server-rs>,
 *     refresh_token: <same opaque token — MVP では rotation 無し>,
 *     mcp_url:      "https://mcp(-staging).ippoan.org/u/<login>/mcp",
 *     github_login: "<login>",
 *     expires_in:   86400
 *   }
 *   400 → invalid_request (Authorization 欠落 / body parse 失敗)
 *   401 → invalid_grant   (token 未知 / revoked)
 *   410 → expired         (refresh_token_expires_at < now、再 pair が必要)
 *   429 → rate_limited    (10/min per refresh_token)
 *   503 → server_error    (env 未設定)
 *
 * Refresh rotation は MVP では未実装 (issue #157 §3 spec)。後付け時は旧 token を
 * 60s grace で受理する (RFC 6819 §5.2.2.3)。
 */

import type { Env } from "../index";
import { jsonResponse } from "../lib/errors";
import { signMcpJwt } from "../lib/mcp-jwt";
import { mcpRelayOrigin } from "../lib/mcp-origins";
import {
  checkAndBumpGrantRateLimit,
  hashRefreshToken,
  touchPairRefresh,
  getPairRefresh,
} from "../lib/mcp-pair";

/** Phase A と同じ — binding_jwt は 24h。consumer (binary) は expires_in を見て
 *  半分を過ぎたら eager refresh を試みる前提 (issue #157 §1 design)。 */
const BINDING_JWT_TTL_SEC = 60 * 60 * 24;
const MCP_AUD = "github-mcp-server-rs";

interface GrantRequest {
  binary_version?: unknown;
  binary_fingerprint?: unknown;
}

export async function handleMcpPairGrant(
  request: Request,
  env: Env,
): Promise<Response> {
  // ── env guard ────────────────────────────────────────────────────────
  if (!env.MCP_OAUTH_KV || !env.MCP_JWT_SECRET || !env.AUTH_WORKER_ORIGIN) {
    return jsonResponse(
      { error: "server_error", error_description: "MCP OAuth Provider not configured" },
      503,
    );
  }

  // ── parse Authorization ─────────────────────────────────────────────
  const authz = request.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(authz);
  if (!m || !m[1]) {
    return jsonResponse(
      { error: "invalid_request", error_description: "Authorization: Bearer <refresh_token> required" },
      400,
    );
  }
  const refreshToken = m[1];

  // ── parse body (binary_version / fingerprint は log 用、本処理に影響無し) ─
  // body は optional 扱いだが、JSON だけど中身空でも OK。malformed なら 400。
  if (request.headers.get("Content-Length") !== "0") {
    try {
      const body = (await request.json()) as GrantRequest;
      // 値の検証はしない (log 出すだけ)。型注釈のために touch。
      void body;
    } catch {
      return jsonResponse(
        { error: "invalid_request", error_description: "invalid JSON body" },
        400,
      );
    }
  }

  // ── rate limit (per refresh_token, 10/min) ──────────────────────────
  const tokenHash = await hashRefreshToken(refreshToken);
  const now = Date.now();
  const ok = await checkAndBumpGrantRateLimit(env, tokenHash, now);
  if (!ok) {
    return jsonResponse(
      { error: "rate_limited", error_description: "too many grant requests; retry in 1 minute" },
      429,
    );
  }

  // ── refresh_token lookup ────────────────────────────────────────────
  const rec = await getPairRefresh(env, tokenHash);
  if (!rec || rec.revoked) {
    return jsonResponse(
      { error: "invalid_grant", error_description: "unknown or revoked refresh_token" },
      401,
    );
  }
  if (rec.expires_at <= now) {
    // 30 日 hard expiry。再 pair (browser click) が必要。
    return jsonResponse(
      { error: "expired_token", error_description: "refresh_token expired; re-pair required" },
      410,
    );
  }

  // ── mint fresh binding_jwt ──────────────────────────────────────────
  const bindingJwt = await signMcpJwt(
    {
      sub: `github:${rec.github_login}`,
      github_login: rec.github_login,
      scope: rec.requested_scope,
      aud: MCP_AUD,
    },
    env.MCP_JWT_SECRET,
    BINDING_JWT_TTL_SEC,
  );

  // ── bump last_used_at (sliding window 観測用、TTL は伸ばさない) ──────
  await touchPairRefresh(env, tokenHash, now);

  const mcpUrl = `${mcpRelayOrigin(env)}/u/${rec.github_login}/mcp`;

  return jsonResponse({
    binding_jwt: bindingJwt,
    // MVP: rotation 無し — 同じ refresh_token を返す。consumer 側は
    // identity-compare せず必ず response の値を新しい canonical として保存する。
    refresh_token: refreshToken,
    mcp_url: mcpUrl,
    github_login: rec.github_login,
    expires_in: BINDING_JWT_TTL_SEC,
  });
}
