/**
 * `POST /mcp/admin/exec` — admin proxy endpoint (Phase 1 admin auth).
 *
 * binary (github-mcp-server-rs) からのみ叩かれる。MCP JWT による user 認証 +
 * KV elevate flag による 2nd factor (browser-confirmed within 15min) で gate
 * したうえで、ユーザーが pair flow 時に KV に保存した GitHub OAuth token
 * (`github_token:{sub}`) を復号して branch protection 系の REST 操作を実行する。
 *
 * Why use the user's stored OAuth token instead of a GitHub App installation token:
 *   - GitHub App の `Administration:write` permission は本来必要な
 *     branch protection write に加えて `delete_repo` まで内包しており、
 *     scope として広すぎる (repo 全削除権限を proxy が持ってしまう)。
 *   - ユーザーが既に保有する `repo` OAuth scope は branch protection write
 *     には十分で、かつ `delete_repo` を含まない (narrower)。proxy が誤って
 *     repo 削除を発火することを構造的に防ぐ。
 *   - 本 proxy 経由なら token は Cloudflare 側に閉じ、binary はせいぜい
 *     `elevate` 中の MCP JWT (15min window) しか持たないので影響を局所化できる。
 *
 * Tool allowlist は branch protection 系の 3 つに絞る (initial Phase 1 scope)。
 * `args.owner` は ALLOWED_ADMIN_ORGS で更に絞り込む (現状は `ippoan` 固定)。
 */

import type { Env } from "../index";
import { resolveMcpJwtSecret, verifyMcpJwt } from "../lib/mcp-jwt";
import { mcpRelayOrigin } from "../lib/mcp-origins";
import { decryptWithKey } from "../lib/mcp-crypto";
import { resolveSecret } from "../lib/secret";

const MCP_AUD_LEGACY = "github-mcp-server-rs";
const GITHUB_API = "https://api.github.com";
const GITHUB_UA = "ippoan-auth-worker";

/** Phase 1: branch protection 系のみ。issue ごとに将来 tool を追加する。 */
const ALLOWED_TOOLS = [
  "set_branch_protection",
  "get_branch_protection",
  "delete_branch_protection",
] as const;
type AdminTool = typeof ALLOWED_TOOLS[number];

/**
 * Phase 1 では owner を ippoan org に限定する。将来は env 経由の JSON 配列
 * (`ADMIN_ALLOWED_ORGS`) に切り替えるが、最小実装として hard-code する。
 */
const ALLOWED_ADMIN_ORGS = ["ippoan"];

interface ElevateFlag {
  elevated_at: number;
  expires_at: number;
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function isAllowedTool(t: unknown): t is AdminTool {
  return typeof t === "string" && (ALLOWED_TOOLS as readonly string[]).includes(t);
}

interface AdminArgs {
  owner: string;
  repo: string;
  branch: string;
  rest: Record<string, unknown>;
}

function validateArgs(args: unknown): AdminArgs | null {
  if (typeof args !== "object" || args === null || Array.isArray(args)) {
    return null;
  }
  const a = args as Record<string, unknown>;
  const owner = typeof a.owner === "string" ? a.owner : "";
  const repo = typeof a.repo === "string" ? a.repo : "";
  const branch = typeof a.branch === "string" ? a.branch : "";
  if (!owner || !repo || !branch) return null;
  const rest: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(a)) {
    if (k !== "owner" && k !== "repo" && k !== "branch") rest[k] = v;
  }
  return { owner, repo, branch, rest };
}

export async function handleMcpAdminExec(
  request: Request,
  env: Env,
): Promise<Response> {
  const jwtSecret = await resolveMcpJwtSecret(env.MCP_JWT_SECRET);
  const ssoKey = await resolveSecret(env.SSO_ENCRYPTION_KEY);
  if (
    !env.MCP_OAUTH_KV ||
    !jwtSecret ||
    !ssoKey ||
    !env.AUTH_WORKER_ORIGIN
  ) {
    return jsonResponse(
      { ok: false, error: "server_error", error_description: "admin exec not configured" },
      503,
    );
  }

  const authz = request.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(authz);
  if (!m || !m[1]) {
    return jsonResponse({ ok: false, error: "missing_authorization" }, 401);
  }
  const relayOrigin = mcpRelayOrigin(env);
  const payload = await verifyMcpJwt(m[1], jwtSecret, (aud) => {
    if (aud === MCP_AUD_LEGACY) return true;
    try { return new URL(aud).origin === relayOrigin; } catch { return false; }
  });
  if (!payload) {
    return jsonResponse({ ok: false, error: "invalid_jwt" }, 401);
  }
  const login = payload.github_login;

  // elevate flag check (browser-confirmed within 15min)
  const elevateRaw = await env.MCP_OAUTH_KV.get(`elevate:${login}`);
  let elevateOk = false;
  if (elevateRaw) {
    try {
      const flag = JSON.parse(elevateRaw) as ElevateFlag;
      if (
        typeof flag.expires_at === "number" &&
        flag.expires_at > Math.floor(Date.now() / 1000)
      ) {
        elevateOk = true;
      }
    } catch {
      elevateOk = false;
    }
  }
  if (!elevateOk) {
    return jsonResponse(
      {
        ok: false,
        error: "not_elevated",
        elevate_url: `${env.AUTH_WORKER_ORIGIN}/mcp/elevate`,
      },
      403,
    );
  }

  // body parse
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonResponse(
      { ok: false, error: "invalid_request", details: "json_parse" },
      400,
    );
  }
  if (typeof body !== "object" || body === null) {
    return jsonResponse(
      { ok: false, error: "invalid_request", details: "json_parse" },
      400,
    );
  }
  const reqBody = body as { tool?: unknown; args?: unknown };
  if (!isAllowedTool(reqBody.tool)) {
    return jsonResponse({ ok: false, error: "unknown_tool" }, 400);
  }
  const tool: AdminTool = reqBody.tool;
  const args = validateArgs(reqBody.args);
  if (!args) {
    return jsonResponse(
      { ok: false, error: "invalid_request", details: "missing_fields" },
      400,
    );
  }
  if (!ALLOWED_ADMIN_ORGS.includes(args.owner)) {
    return jsonResponse({ ok: false, error: "forbidden_owner" }, 400);
  }

  // KV に保存済みのユーザー GitHub OAuth token (repo scope) を復号して使う。
  // Administration:write を持つ GitHub App token と違って delete_repo を含まない
  // ため、proxy 経由で repo 全削除が誤って走ることを構造的に防げる。
  const encrypted = await env.MCP_OAUTH_KV.get(`github_token:${payload.sub}`);
  if (!encrypted) {
    return jsonResponse(
      {
        ok: false,
        error: "github_token_unavailable",
        details: "Stored GitHub OAuth token not found. Re-run the MCP pair flow to refresh.",
      },
      502,
    );
  }
  let userGithubToken: string;
  try {
    userGithubToken = await decryptWithKey(encrypted, ssoKey);
  } catch {
    return jsonResponse(
      {
        ok: false,
        error: "github_token_unavailable",
        details: "Failed to decrypt stored GitHub OAuth token. Re-run the MCP pair flow.",
      },
      502,
    );
  }

  // dispatch GitHub REST call
  const ownerEsc = encodeURIComponent(args.owner);
  const repoEsc = encodeURIComponent(args.repo);
  const branchEsc = encodeURIComponent(args.branch);
  const path = `/repos/${ownerEsc}/${repoEsc}/branches/${branchEsc}/protection`;
  const ghHeaders: Record<string, string> = {
    Authorization: `Bearer ${userGithubToken}`,
    Accept: "application/vnd.github+json",
    "User-Agent": GITHUB_UA,
    "X-GitHub-Api-Version": "2022-11-28",
  };

  let ghResp: Response;
  if (tool === "set_branch_protection") {
    ghResp = await fetch(`${GITHUB_API}${path}`, {
      method: "PUT",
      headers: { ...ghHeaders, "Content-Type": "application/json" },
      body: JSON.stringify(args.rest),
    });
  } else if (tool === "get_branch_protection") {
    ghResp = await fetch(`${GITHUB_API}${path}`, {
      method: "GET",
      headers: ghHeaders,
    });
  } else {
    ghResp = await fetch(`${GITHUB_API}${path}`, {
      method: "DELETE",
      headers: ghHeaders,
    });
  }

  const ghBodyText = await ghResp.text();
  console.log(JSON.stringify({
    event: "admin_exec",
    login,
    tool,
    owner: args.owner,
    repo: args.repo,
    branch: args.branch,
    github_status: ghResp.status,
  }));

  if (!ghResp.ok) {
    return jsonResponse(
      { ok: false, error: "github_api_error", status: ghResp.status, body: ghBodyText },
      502,
    );
  }
  let result: unknown = null;
  if (ghBodyText) {
    try {
      result = JSON.parse(ghBodyText);
    } catch {
      result = ghBodyText;
    }
  }
  return jsonResponse({ ok: true, result }, 200);
}
