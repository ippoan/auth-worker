/**
 * `POST /mcp/pair/grant-via-github` — GitHub OAuth token を identity proof として
 * binding_jwt を 1 発で mint する endpoint (issue ippoan/mcp-relay-rs#15、本 PR)。
 *
 * 既存 `/mcp/pair/grant` (refresh_token → binding_jwt) や `/mcp/pair/new` →
 * browser click → WS upgrade の経路はどちらも「先に 1 度 auth.ippoan.org の
 * cookie session に user を bind する」step を要求するため、CCoW container の
 * ように **browser cookie が存在せず**、かつ **env に PAT/token を pre-stage できない**
 * 環境では bootstrap が成立しない。本 endpoint は GitHub 自体を IdP として直接
 * 信頼し、claim_login と GitHub OAuth token を atomic に検証することで、claim
 * の root-of-trust を `api.github.com/user` の応答に置き換える。
 *
 * Auth model:
 *   Headers:
 *     Authorization: Bearer <github-oauth-token>   (PAT, OAuth App token,
 *                                                   fine-grained token 何でも可。
 *                                                   `read:user` scope (or `user`
 *                                                   `user:email` 等の上位) を含むこと)
 *   Body (optional JSON):
 *     {
 *       "aud":             "github-mcp-server-rs"     // default。
 *                          | "ref-files-mcp-server-rs", // multiplex 内のどちら向け
 *       "scope":           "mcp.read mcp.write",     // default; `mcp.admin` は不可
 *       "binary_version":  string                    // log 用
 *     }
 *
 * Response:
 *   200 → {
 *     binding_jwt:   "<24h MCP JWT aud=<requested>>",
 *     mcp_url:       "https://mcp(-staging).ippoan.org/u/<login>/mcp",
 *     github_login:  "<verified login from api.github.com/user>",
 *     github_id:     <verified id>,
 *     aud:           "<echo>",
 *     scope:         "<echo>",
 *     expires_in:    86400
 *   }
 *   400 → invalid_request   (Authorization 欠落 / body JSON 不正)
 *   401 → invalid_token     (GitHub token が api.github.com で reject)
 *   403 → forbidden_scope   (`mcp.admin` を要求した、または aud が allowlist 外)
 *   429 → rate_limited      (10/min per github_token hash)
 *   502 → upstream_error    (api.github.com が 5xx / network)
 *   503 → server_error      (MCP_JWT_SECRET 等 env 未設定)
 *
 * Security:
 *   - 「GitHub OAuth token == user identity assertion」を trust する。これは
 *     auth-worker が既に `/mcp/authorize` の GitHub callback で行っている trust
 *     と等価。直接 token を受ける代わりに browser redirect を skip する。
 *   - Token 自体は KV に保存しない (passthrough verify のみ)。binding_jwt mint
 *     後は GitHub token は捨てる。
 *   - `mcp.admin` scope は本 path で発行**しない** (browser elevate flow #149
 *     経由でのみ付与する仕様を維持)。
 *   - rate limit は github_token の sha256 で per-token bucketing (per-IP に
 *     比べて token 流出時の blast radius を絞れる)。
 *
 * Why this exists (#15):
 *   CCoW container 内で MCP relay binary を bootstrap する際、claim_login が
 *   不明 + browser 不在 = pair flow が成立しない。GitHub PAT を本 endpoint に
 *   POST すれば binding_jwt が 1 発で取れるため、binary の token cache を直接
 *   hydrate でき、pair URL 発行 ↔ click ↔ WS handshake の 3 ラウンドを省略
 *   して relay mode に直行できる。
 */

import type { Env } from "../index";
import { jsonResponse } from "../lib/errors";
import { signMcpJwt } from "../lib/mcp-jwt";
import { mcpRelayOrigin } from "../lib/mcp-origins";
import { checkAndBumpGrantRateLimit, hashRefreshToken } from "../lib/mcp-pair";

/** binding_jwt の TTL — `/mcp/pair/grant` (refresh_token 経路) と揃える。
 *  consumer は expires_in を見て 12h 経過時点で eager 再 grant する想定。 */
const BINDING_JWT_TTL_SEC = 60 * 60 * 24;

/** default audience — single-binary 時代の back-compat。`/mcp/pair/grant` と同じ。
 *  Multiplex 環境 (mcp-relay-rs Option C) では body で明示的に上書きする。 */
const DEFAULT_AUD = "github-mcp-server-rs";

/** mcp.admin は本 path で発行しない (browser elevate を必須に維持)。 */
const FORBIDDEN_SCOPES = new Set(["mcp.admin"]);

/** allowed audience — env 未設定時の fallback。`MCP_JWT_AUDIENCE_ALLOWLIST` env
 *  と揃えて、新 binary を足す時の change point を 1 箇所に集約する設計。 */
const DEFAULT_ALLOWED_AUDIENCES = ["github-mcp-server-rs", "ref-files-mcp-server-rs"];

interface GrantViaGithubRequest {
  aud?: unknown;
  scope?: unknown;
  binary_version?: unknown;
}

interface GithubUserResponse {
  login: string;
  id: number;
}

function parseAllowedAudiences(env: Env): readonly string[] {
  // wrangler.toml の `[vars] MCP_JWT_AUDIENCE_ALLOWLIST = "a,b,c"` を読む。
  // mcp-relay-bridge と同じ仕様を踏襲して、env 未設定時は default に fall back。
  const raw = (env as Env & { MCP_JWT_AUDIENCE_ALLOWLIST?: string })
    .MCP_JWT_AUDIENCE_ALLOWLIST;
  if (!raw) return DEFAULT_ALLOWED_AUDIENCES;
  const items = raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return items.length > 0 ? items : DEFAULT_ALLOWED_AUDIENCES;
}

export async function handleMcpPairGrantViaGithub(
  request: Request,
  env: Env,
): Promise<Response> {
  // ── env guard ────────────────────────────────────────────────────────
  if (!env.MCP_JWT_SECRET || !env.AUTH_WORKER_ORIGIN) {
    return jsonResponse(
      {
        error: "server_error",
        error_description: "MCP_JWT_SECRET / AUTH_WORKER_ORIGIN not configured",
      },
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
        error_description: "Authorization: Bearer <github-oauth-token> required",
      },
      400,
    );
  }
  const githubToken = m[1].trim();

  // ── parse body (all fields optional) ────────────────────────────────
  let requestedAud = DEFAULT_AUD;
  let requestedScope = "mcp.read mcp.write";
  if (request.headers.get("Content-Length") !== "0") {
    try {
      const ct = request.headers.get("Content-Type") ?? "";
      if (ct.includes("application/json")) {
        const body = (await request.json()) as GrantViaGithubRequest;
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

  // ── audience allowlist check (公開 scope は MCP_JWT_AUDIENCE_ALLOWLIST のみ) ──
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

  // ── scope check (mcp.admin はこの path で発行禁止 #149 design) ────────
  const scopeTokens = requestedScope.split(/\s+/).filter((s) => s.length > 0);
  for (const s of scopeTokens) {
    if (FORBIDDEN_SCOPES.has(s)) {
      return jsonResponse(
        {
          error: "forbidden_scope",
          error_description: `scope=${s} requires browser elevate flow, cannot be granted via github token`,
        },
        403,
      );
    }
  }

  // ── rate limit (per github_token hash, 10/min) ──────────────────────
  const tokenHash = await hashRefreshToken(githubToken);
  const now = Date.now();
  const okRate = await checkAndBumpGrantRateLimit(env, tokenHash, now);
  if (!okRate) {
    return jsonResponse(
      {
        error: "rate_limited",
        error_description: "too many grant requests; retry in 1 minute",
      },
      429,
    );
  }

  // ── verify GitHub token by calling api.github.com/user ─────────────
  let ghUser: GithubUserResponse;
  try {
    const ghRes = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${githubToken}`,
        "User-Agent": "ippoan-auth-worker/mcp-pair-grant-via-github",
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });
    if (ghRes.status === 401 || ghRes.status === 403) {
      return jsonResponse(
        {
          error: "invalid_token",
          error_description: `GitHub rejected token (status=${ghRes.status})`,
        },
        401,
      );
    }
    if (!ghRes.ok) {
      return jsonResponse(
        {
          error: "upstream_error",
          error_description: `api.github.com status=${ghRes.status}`,
        },
        502,
      );
    }
    const parsed = (await ghRes.json()) as Partial<GithubUserResponse>;
    if (typeof parsed.login !== "string" || typeof parsed.id !== "number") {
      return jsonResponse(
        {
          error: "upstream_error",
          error_description: "api.github.com/user response missing login/id",
        },
        502,
      );
    }
    ghUser = { login: parsed.login, id: parsed.id };
  } catch (e) {
    return jsonResponse(
      {
        error: "upstream_error",
        error_description: `api.github.com fetch failed: ${(e as Error).message}`,
      },
      502,
    );
  }

  // ── mint binding_jwt ────────────────────────────────────────────────
  // sub / github_login の両方を埋める (`/mcp/pair/grant` と同じ shape)。
  // consumer (binary) 側の `/mcp/introspect` は両方を読むため。
  const bindingJwt = await signMcpJwt(
    {
      sub: `github:${ghUser.login}`,
      github_login: ghUser.login,
      scope: requestedScope,
      aud: requestedAud,
    },
    env.MCP_JWT_SECRET,
    BINDING_JWT_TTL_SEC,
  );

  const mcpUrl = `${mcpRelayOrigin(env)}/u/${ghUser.login}/mcp`;

  return jsonResponse({
    binding_jwt: bindingJwt,
    mcp_url: mcpUrl,
    github_login: ghUser.login,
    github_id: ghUser.id,
    aud: requestedAud,
    scope: requestedScope,
    expires_in: BINDING_JWT_TTL_SEC,
  });
}
