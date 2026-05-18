/**
 * `POST /mcp/admin/exec` — admin proxy endpoint (Phase 1 admin auth).
 *
 * binary (github-mcp-server-rs) からのみ叩かれる。MCP JWT による user 認証 +
 * KV elevate flag による 2nd factor (browser-confirmed within 15min) で gate
 * したうえで、GitHub App installation token を使った branch protection 系の
 * REST 操作を実行する。
 *
 * Why this design (vs returning admin-scoped GitHub token to binary):
 *   - admin GitHub token を binary が持つと「漏洩した PAT が直接 GitHub への
 *     admin write 権限を持つ」状態になる。
 *   - 本 proxy 経由なら admin token は Cloudflare 側に閉じ、binary はせいぜい
 *     `elevate` 中の MCP JWT (15min window) しか持たないので影響を局所化できる。
 *
 * Tool allowlist は branch protection 系の 3 つに絞る (initial Phase 1 scope)。
 * `args.owner` は ALLOWED_ADMIN_ORGS で更に絞り込む (現状は `ippoan` 固定)。
 */

import type { Env } from "../index";
import { verifyMcpJwt } from "../lib/mcp-jwt";
import { mcpRelayOrigin } from "../lib/mcp-origins";

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
  if (
    !env.MCP_OAUTH_KV ||
    !env.MCP_JWT_SECRET ||
    !env.INSTALLATION_TOKEN_DO ||
    !env.GITHUB_APP_INSTALLATION_ID ||
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
  const payload = await verifyMcpJwt(m[1], env.MCP_JWT_SECRET, (aud) => {
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

  // installation token 取得 (DO 経由 cache)
  let installationToken: string;
  try {
    const doId = env.INSTALLATION_TOKEN_DO.idFromName(env.GITHUB_APP_INSTALLATION_ID);
    const doStub = env.INSTALLATION_TOKEN_DO.get(doId);
    const tokResp = await doStub.fetch("https://do.internal/get");
    if (!tokResp.ok) {
      const txt = await tokResp.text();
      return jsonResponse(
        { ok: false, error: "installation_token_failed", status: tokResp.status, body: txt },
        502,
      );
    }
    const tokJson = (await tokResp.json()) as { token?: string };
    if (!tokJson.token) {
      return jsonResponse(
        { ok: false, error: "installation_token_failed", status: 502, body: "no token in DO response" },
        502,
      );
    }
    installationToken = tokJson.token;
  } catch (e) {
    return jsonResponse(
      { ok: false, error: "installation_token_failed", status: 502, body: e instanceof Error ? e.message : String(e) },
      502,
    );
  }

  // dispatch GitHub REST call
  const ownerEsc = encodeURIComponent(args.owner);
  const repoEsc = encodeURIComponent(args.repo);
  const branchEsc = encodeURIComponent(args.branch);
  const path = `/repos/${ownerEsc}/${repoEsc}/branches/${branchEsc}/protection`;
  const ghHeaders: Record<string, string> = {
    Authorization: `Bearer ${installationToken}`,
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
