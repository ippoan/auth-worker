/**
 * `POST /mcp/pair/grant-via-oat` — Anthropic OAT を identity proof として
 * binding_jwt を 1 発で mint する endpoint (issue ippoan/auth-worker#174)。
 *
 * CCoW container 内には GitHub credential も browser cookie も存在せず、
 * Anthropic OAT (`sk-ant-oat01-...`、`/home/claude/.claude/remote/.oauth_token`)
 * だけが install-mcp-relay hook 段階で参照可能。OAT 自体は Anthropic identity
 * endpoint で 403 reject されるため、OAT alone では login を引けない。
 *
 * 設計: 別経路 (`POST /mcp/pair/register-via-github-comment`) で OAT_hash →
 * github_login 対応を KV に bind しておけば、本 endpoint は OAT を hash して
 * lookup するだけで silent に binding_jwt を返せる。bootstrap の唯一の click は
 * register endpoint を 1 回叩く初回のみ (= GitHub issue comment の投稿)。
 *
 * Auth model:
 *   Headers:
 *     Authorization: Bearer <Anthropic OAT>   (sk-ant-oat01-...)
 *   Body (optional JSON):
 *     {
 *       "aud":             "github-mcp-server-rs"
 *                          | "ref-files-mcp-server-rs",
 *       "scope":           "mcp.read mcp.write",
 *       "binary_version":  string
 *     }
 *
 * Response:
 *   200 → {
 *     binding_jwt:   "<24h MCP JWT>",
 *     mcp_url:       "https://mcp(-staging).ippoan.org/u/<login>/mcp",
 *     github_login:  "<verified login bound to OAT>",
 *     aud:           "<echo>",
 *     scope:         "<echo>",
 *     expires_in:    86400
 *   }
 *   400 → invalid_request   (Authorization 欠落 / body JSON 不正)
 *   401 → invalid_token     (Anthropic API が OAT を reject)
 *   403 → forbidden_scope   (mcp.admin / aud allowlist 外)
 *   404 → not_bound         (oat_hash:* が KV に無い → register 必要)
 *   429 → rate_limited      (10/min per OAT_hash)
 *   502 → upstream_error    (api.anthropic.com 5xx / network)
 *   503 → server_error      (env / KV 未設定)
 *
 * Security:
 *   - OAT 自体は KV に保存しない (hash のみ key として使う、leak 耐性)。
 *   - `mcp.admin` scope は本 path で発行**しない** (`/mcp/elevate` 経由のみ)。
 *   - rate limit は OAT_hash で per-token bucketing。`/mcp/pair/grant-via-github`
 *     と同じ `checkAndBumpGrantRateLimit` を sha256 衝突無視で共用する。
 *   - OAT validity check を Anthropic API (`/v1/models`) に渡し、revoked OAT で
 *     stale binding を引かれて binding_jwt を盗まれる経路を塞ぐ。
 */

import type { Env } from "../index";
import { jsonResponse } from "../lib/errors";
import { signMcpJwt } from "../lib/mcp-jwt";
import { getOatBinding, hashOat } from "../lib/mcp-oat-binding";
import { mcpRelayOrigin } from "../lib/mcp-origins";
import { checkAndBumpGrantRateLimit } from "../lib/mcp-pair";

const BINDING_JWT_TTL_SEC = 60 * 60 * 24;
const DEFAULT_AUD = "github-mcp-server-rs";
const FORBIDDEN_SCOPES = new Set(["mcp.admin"]);
const DEFAULT_ALLOWED_AUDIENCES = ["github-mcp-server-rs", "ref-files-mcp-server-rs"];
const REGISTER_ENDPOINT = "/mcp/pair/register-via-github-comment";

interface GrantViaOatRequest {
  aud?: unknown;
  scope?: unknown;
  binary_version?: unknown;
}

function parseAllowedAudiences(env: Env): readonly string[] {
  const raw = (env as Env & { MCP_JWT_AUDIENCE_ALLOWLIST?: string })
    .MCP_JWT_AUDIENCE_ALLOWLIST;
  if (!raw) return DEFAULT_ALLOWED_AUDIENCES;
  const items = raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return items.length > 0 ? items : DEFAULT_ALLOWED_AUDIENCES;
}

export async function handleMcpPairGrantViaOat(
  request: Request,
  env: Env,
): Promise<Response> {
  // ── env / KV guard ───────────────────────────────────────────────────
  if (!env.MCP_JWT_SECRET || !env.AUTH_WORKER_ORIGIN) {
    return jsonResponse(
      {
        error: "server_error",
        error_description: "MCP_JWT_SECRET / AUTH_WORKER_ORIGIN not configured",
      },
      503,
    );
  }
  if (!env.MCP_OAUTH_KV) {
    return jsonResponse(
      { error: "server_error", error_description: "MCP_OAUTH_KV not bound" },
      503,
    );
  }

  // ── parse Authorization ─────────────────────────────────────────────
  const authz = request.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(authz);
  if (!m || !m[1]) {
    return jsonResponse(
      {
        error: "invalid_request",
        error_description: "Authorization: Bearer <Anthropic OAT> required",
      },
      400,
    );
  }
  const oat = m[1].trim();

  // ── parse body (all fields optional) ────────────────────────────────
  let requestedAud = DEFAULT_AUD;
  let requestedScope = "mcp.read mcp.write";
  if (request.headers.get("Content-Length") !== "0") {
    try {
      const ct = request.headers.get("Content-Type") ?? "";
      if (ct.includes("application/json")) {
        const body = (await request.json()) as GrantViaOatRequest;
        if (typeof body.aud === "string" && body.aud.length > 0) {
          requestedAud = body.aud;
        }
        if (typeof body.scope === "string" && body.scope.length > 0) {
          requestedScope = body.scope;
        }
      }
    } catch {
      return jsonResponse(
        { error: "invalid_request", error_description: "invalid JSON body" },
        400,
      );
    }
  }

  // ── audience allowlist check ────────────────────────────────────────
  const allowed = parseAllowedAudiences(env);
  if (!allowed.includes(requestedAud)) {
    return jsonResponse(
      {
        error: "forbidden_scope",
        error_description: `aud=${requestedAud} not in allowlist (${allowed.join(",")})`,
      },
      403,
    );
  }

  // ── scope check (mcp.admin 禁止) ─────────────────────────────────────
  const scopeTokens = requestedScope.split(/\s+/).filter((s) => s.length > 0);
  for (const s of scopeTokens) {
    if (FORBIDDEN_SCOPES.has(s)) {
      return jsonResponse(
        {
          error: "forbidden_scope",
          error_description: `scope=${s} requires browser elevate flow, cannot be granted via OAT`,
        },
        403,
      );
    }
  }

  // ── rate limit (per OAT hash, 10/min) ───────────────────────────────
  const oatHash = await hashOat(oat);
  const now = Date.now();
  const okRate = await checkAndBumpGrantRateLimit(env, oatHash, now);
  if (!okRate) {
    return jsonResponse(
      {
        error: "rate_limited",
        error_description: "too many grant requests; retry in 1 minute",
      },
      429,
    );
  }

  // ── verify OAT against Anthropic API (revoked / forged OAT を弾く) ──
  try {
    const res = await fetch("https://api.anthropic.com/v1/models", {
      headers: {
        Authorization: `Bearer ${oat}`,
        "anthropic-version": "2023-06-01",
        "User-Agent": "ippoan-auth-worker/mcp-pair-grant-via-oat",
      },
    });
    if (res.status === 401 || res.status === 403) {
      return jsonResponse(
        {
          error: "invalid_token",
          error_description: `Anthropic rejected OAT (status=${res.status})`,
        },
        401,
      );
    }
    if (!res.ok) {
      return jsonResponse(
        {
          error: "upstream_error",
          error_description: `api.anthropic.com status=${res.status}`,
        },
        502,
      );
    }
  } catch (e) {
    return jsonResponse(
      {
        error: "upstream_error",
        error_description: `api.anthropic.com fetch failed: ${(e as Error).message}`,
      },
      502,
    );
  }

  // ── lookup binding ───────────────────────────────────────────────────
  const binding = await getOatBinding(env, oatHash);
  if (!binding) {
    return jsonResponse(
      {
        error: "not_bound",
        error_description:
          "OAT not bound to any github_login; POST register endpoint first",
        register_endpoint: REGISTER_ENDPOINT,
      },
      404,
    );
  }

  // ── mint binding_jwt ────────────────────────────────────────────────
  const bindingJwt = await signMcpJwt(
    {
      sub: `github:${binding.github_login}`,
      github_login: binding.github_login,
      scope: requestedScope,
      aud: requestedAud,
    },
    env.MCP_JWT_SECRET,
    BINDING_JWT_TTL_SEC,
  );

  const mcpUrl = `${mcpRelayOrigin(env)}/u/${binding.github_login}/mcp`;

  return jsonResponse({
    binding_jwt: bindingJwt,
    mcp_url: mcpUrl,
    github_login: binding.github_login,
    aud: requestedAud,
    scope: requestedScope,
    expires_in: BINDING_JWT_TTL_SEC,
  });
}
