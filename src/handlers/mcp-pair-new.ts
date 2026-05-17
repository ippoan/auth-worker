/**
 * `POST /mcp/pair/new` (issue #144) — 1-click pair の起点。
 *
 * binary 側 (`github-mcp-server-rs` `pair` subcommand) が起動時に呼ぶ匿名 endpoint。
 * 短期 pair_code を発行し、ブラウザが踏むべき `pair_url` を返す。
 *
 * Request body (JSON):
 *   {
 *     "claim_login": "yhonda-ohishi",    // user 自身が公開する値 (cf. github username)
 *     "binary_version": "v0.0.13"        // optional, debug 用
 *   }
 *
 * Response (JSON):
 *   {
 *     "pair_code": "<base64url 40 char>",
 *     "pair_url": "https://auth.ippoan.org/mcp/pair/<pair_code>",
 *     "expires_in": 300
 *   }
 *
 * Rate-limit: 同一 source IP から 10/min (`cf-connecting-ip`)。bind 不在は許容。
 */

import type { Env } from "../index";
import { jsonResponse } from "../lib/errors";
import { generatePairCode } from "../lib/mcp-codes";
import {
  PAIR_CODE_TTL_SEC,
  checkAndBumpRateLimit,
  putPair,
  type PairRecord,
} from "../lib/mcp-pair";

interface PairNewRequest {
  claim_login?: unknown;
  binary_version?: unknown;
}

export async function handleMcpPairNew(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!env.MCP_OAUTH_KV) {
    return jsonResponse(
      { error: "server_error", error_description: "MCP OAuth Provider not configured" },
      503,
    );
  }
  if (!env.AUTH_WORKER_ORIGIN) {
    return jsonResponse(
      { error: "server_error", error_description: "AUTH_WORKER_ORIGIN not configured" },
      503,
    );
  }

  // ── parse body ────────────────────────────────────────────────────────
  let body: PairNewRequest;
  try {
    body = (await request.json()) as PairNewRequest;
  } catch {
    return jsonResponse(
      { error: "invalid_request", error_description: "invalid JSON body" },
      400,
    );
  }
  if (typeof body.claim_login !== "string" || !body.claim_login) {
    return jsonResponse(
      { error: "invalid_request", error_description: "claim_login is required" },
      400,
    );
  }
  const claim_login = body.claim_login;
  const binary_version =
    typeof body.binary_version === "string" ? body.binary_version : "unknown";

  // ── rate limit ────────────────────────────────────────────────────────
  const ip = request.headers.get("cf-connecting-ip") ?? "anon";
  const ok = await checkAndBumpRateLimit(env, ip, Date.now());
  if (!ok) {
    return jsonResponse(
      { error: "rate_limited", error_description: "too many pair requests; retry in 1 minute" },
      429,
    );
  }

  // ── mint pair_code + persist ──────────────────────────────────────────
  const pair_code = generatePairCode();
  const now = Date.now();
  const rec: PairRecord = {
    pair_code,
    claim_login,
    binary_version,
    created_at: now,
    expires_at: now + PAIR_CODE_TTL_SEC * 1000,
    status: "pending",
    binding_jwt: null,
  };
  await putPair(env, rec);

  return jsonResponse({
    pair_code,
    pair_url: `${env.AUTH_WORKER_ORIGIN}/mcp/pair/${pair_code}`,
    expires_in: PAIR_CODE_TTL_SEC,
  });
}
