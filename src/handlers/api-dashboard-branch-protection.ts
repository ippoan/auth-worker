/**
 * `/api/dashboard/repos*` endpoints (issue #159 Phase 1).
 *
 *   - GET    /api/dashboard/repos
 *   - POST   /api/dashboard/repos/:owner/:repo/protection
 *   - DELETE /api/dashboard/repos/:owner/:repo/protection
 *
 * Auth: `mcp_pair_session` cookie + `elevate:<login>` KV flag
 * (`authenticateDashboard`). API path なので 401/403 を JSON で返す
 * (HTML redirect は frontend 側で `window.location` に飛ばす)。
 *
 * `:owner` は Phase 1 では `ippoan` 固定だが、admin-exec の `ALLOWED_ADMIN_ORGS`
 * を import して同じ allowlist を共有する。
 *
 * GitHub API は `src/lib/branch-protection-github.ts` の helper 経由で叩く。
 * preset 適用は `branch-protection-presets.ts` の payload を `set_branch_protection`
 * helper にそのまま渡す。
 */

import type { Env } from "../index";
import { jsonResponse } from "../lib/errors";
import {
  authenticateDashboard,
  verifyCsrfHeader,
} from "./dashboard-branch-protection";
import {
  buildPayload,
  isPresetId,
  type PresetId,
} from "../lib/branch-protection-presets";
import {
  deleteBranchProtection,
  fetchProtectionRows,
  listOwnedRepos,
  loadGithubToken,
  setBranchProtection,
} from "../lib/branch-protection-github";

/** Phase 1: owner allowlist は admin-exec と揃える (hard-code `ippoan` のみ)。 */
export const ALLOWED_DASHBOARD_OWNERS = ["ippoan"] as const;

/**
 * In-process cache for `/api/dashboard/repos` results. Cloudflare Workers
 * isolate-scoped state lives for the isolate's lifetime, so this gives a
 * cheap "30s per session" approximation without a KV round-trip. Worst case
 * (isolate churn) we just refetch — same as cold start.
 *
 * Key: github_login. We only cache the response shape; not the underlying
 * GitHub token, to avoid leaking it via debug logs.
 */
interface CachedRepos {
  expires_at: number;
  body: unknown;
}
const REPOS_CACHE = new Map<string, CachedRepos>();
const REPOS_CACHE_TTL_MS = 30_000;

export function _clearReposCache(): void {
  REPOS_CACHE.clear();
}

interface AuthOkContext {
  login: string;
  token: string;
}

async function gateAndLoadToken(
  request: Request,
  env: Env,
  opts: { requireCsrf: boolean },
): Promise<AuthOkContext | Response> {
  const auth = await authenticateDashboard(request, env);
  if (!auth.ok) {
    if (auth.status === 503) {
      return jsonResponse(
        { ok: false, error: "server_error", error_description: "dashboard not configured" },
        503,
      );
    }
    return jsonResponse({ ok: false, error: auth.reason }, auth.status);
  }
  if (opts.requireCsrf) {
    const ok = await verifyCsrfHeader(
      request,
      auth.login,
      env.SESSION_COOKIE_SECRET as string,
    );
    if (!ok) return jsonResponse({ ok: false, error: "csrf_mismatch" }, 403);
  }
  const sub = `github:${auth.login}`;
  const token = await loadGithubToken(env, sub);
  if (!token) {
    return jsonResponse(
      {
        ok: false,
        error: "github_token_unavailable",
        details: "Re-run the MCP pair flow to refresh the stored GitHub OAuth token.",
      },
      502,
    );
  }
  return { login: auth.login, token };
}

export async function handleApiDashboardListRepos(
  request: Request,
  env: Env,
): Promise<Response> {
  const ctx = await gateAndLoadToken(request, env, { requireCsrf: false });
  if (ctx instanceof Response) return ctx;

  const now = Date.now();
  const cached = REPOS_CACHE.get(ctx.login);
  if (cached && cached.expires_at > now) {
    return jsonResponse(cached.body, 200);
  }

  let repos;
  try {
    repos = await listOwnedRepos(ctx.token, ALLOWED_DASHBOARD_OWNERS);
  } catch (e) {
    return jsonResponse(
      {
        ok: false,
        error: "github_user_repos_failed",
        details: e instanceof Error ? e.message : String(e),
      },
      502,
    );
  }
  const rows = await fetchProtectionRows(ctx.token, repos);
  const body = { repos: rows };
  REPOS_CACHE.set(ctx.login, { expires_at: now + REPOS_CACHE_TTL_MS, body });
  return jsonResponse(body, 200);
}

interface ApplyBody {
  preset: PresetId;
  required_status_checks?: string[] | null;
}

function validateApplyBody(body: unknown): ApplyBody | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return null;
  }
  const b = body as Record<string, unknown>;
  if (!isPresetId(b.preset)) return null;
  let checks: string[] | null | undefined = undefined;
  if (b.required_status_checks === null) checks = null;
  else if (Array.isArray(b.required_status_checks)) {
    if (!b.required_status_checks.every((s) => typeof s === "string")) return null;
    checks = b.required_status_checks as string[];
  } else if (b.required_status_checks !== undefined) {
    return null;
  }
  return { preset: b.preset, required_status_checks: checks };
}

export async function handleApiDashboardApplyProtection(
  request: Request,
  env: Env,
  owner: string,
  repo: string,
): Promise<Response> {
  if (!(ALLOWED_DASHBOARD_OWNERS as readonly string[]).includes(owner)) {
    return jsonResponse({ ok: false, error: "forbidden_owner" }, 400);
  }
  const ctx = await gateAndLoadToken(request, env, { requireCsrf: true });
  if (ctx instanceof Response) return ctx;

  let parsed: unknown;
  try {
    parsed = await request.json();
  } catch {
    return jsonResponse({ ok: false, error: "invalid_request", details: "json_parse" }, 400);
  }
  const body = validateApplyBody(parsed);
  if (!body) {
    return jsonResponse(
      { ok: false, error: "invalid_request", details: "missing_or_unknown_preset" },
      400,
    );
  }

  // The default branch is resolved by re-fetching the repo's metadata via the
  // cached list (cheaper than a fresh `GET /repos/:o/:r`).
  let defaultBranch: string | null = null;
  const cached = REPOS_CACHE.get(ctx.login);
  if (cached && cached.expires_at > Date.now()) {
    const cachedBody = cached.body as { repos?: Array<{ owner: string; name: string; default_branch: string }> };
    const match = cachedBody.repos?.find(
      (r) => r.owner === owner && r.name === repo,
    );
    if (match) defaultBranch = match.default_branch;
  }
  if (!defaultBranch) {
    // Fall back to a direct repo lookup. listOwnedRepos's cache miss path:
    // when the user just elevated and immediately clicked Apply, the cache
    // may not have populated yet (e.g. they opened the page in one tab and
    // hit Apply in another). Resolve via the GitHub repo metadata endpoint.
    try {
      const resp = await fetch(
        `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
        {
          headers: {
            Authorization: `Bearer ${ctx.token}`,
            Accept: "application/vnd.github+json",
            "User-Agent": "ippoan-auth-worker",
            "X-GitHub-Api-Version": "2022-11-28",
          },
        },
      );
      if (!resp.ok) {
        return jsonResponse(
          { ok: false, error: "repo_lookup_failed", status: resp.status },
          502,
        );
      }
      const meta = (await resp.json()) as { default_branch?: string };
      if (!meta.default_branch) {
        return jsonResponse(
          { ok: false, error: "repo_lookup_failed", details: "default_branch missing" },
          502,
        );
      }
      defaultBranch = meta.default_branch;
    } catch (e) {
      return jsonResponse(
        {
          ok: false,
          error: "repo_lookup_failed",
          details: e instanceof Error ? e.message : String(e),
        },
        502,
      );
    }
  }

  const payload = buildPayload(body.preset, body.required_status_checks ?? undefined);
  const res = await setBranchProtection(ctx.token, owner, repo, defaultBranch, payload);
  console.log(JSON.stringify({
    event: "dashboard_apply_protection",
    login: ctx.login,
    owner,
    repo,
    branch: defaultBranch,
    preset: body.preset,
    github_status: res.status,
  }));
  if (!res.ok) {
    return jsonResponse(
      { ok: false, error: "github_api_error", status: res.status, body: res.body },
      502,
    );
  }
  REPOS_CACHE.delete(ctx.login);
  return jsonResponse({ ok: true, result: res.body, branch: defaultBranch }, 200);
}

export async function handleApiDashboardRemoveProtection(
  request: Request,
  env: Env,
  owner: string,
  repo: string,
): Promise<Response> {
  if (!(ALLOWED_DASHBOARD_OWNERS as readonly string[]).includes(owner)) {
    return jsonResponse({ ok: false, error: "forbidden_owner" }, 400);
  }
  const ctx = await gateAndLoadToken(request, env, { requireCsrf: true });
  if (ctx instanceof Response) return ctx;

  let defaultBranch: string | null = null;
  const cached = REPOS_CACHE.get(ctx.login);
  if (cached && cached.expires_at > Date.now()) {
    const cachedBody = cached.body as { repos?: Array<{ owner: string; name: string; default_branch: string }> };
    const match = cachedBody.repos?.find((r) => r.owner === owner && r.name === repo);
    if (match) defaultBranch = match.default_branch;
  }
  if (!defaultBranch) {
    try {
      const resp = await fetch(
        `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
        {
          headers: {
            Authorization: `Bearer ${ctx.token}`,
            Accept: "application/vnd.github+json",
            "User-Agent": "ippoan-auth-worker",
            "X-GitHub-Api-Version": "2022-11-28",
          },
        },
      );
      if (!resp.ok) {
        return jsonResponse(
          { ok: false, error: "repo_lookup_failed", status: resp.status },
          502,
        );
      }
      const meta = (await resp.json()) as { default_branch?: string };
      if (!meta.default_branch) {
        return jsonResponse(
          { ok: false, error: "repo_lookup_failed", details: "default_branch missing" },
          502,
        );
      }
      defaultBranch = meta.default_branch;
    } catch (e) {
      return jsonResponse(
        {
          ok: false,
          error: "repo_lookup_failed",
          details: e instanceof Error ? e.message : String(e),
        },
        502,
      );
    }
  }

  const res = await deleteBranchProtection(ctx.token, owner, repo, defaultBranch);
  console.log(JSON.stringify({
    event: "dashboard_remove_protection",
    login: ctx.login,
    owner,
    repo,
    branch: defaultBranch,
    github_status: res.status,
  }));
  if (!res.ok) {
    return jsonResponse(
      { ok: false, error: "github_api_error", status: res.status, body: res.body },
      502,
    );
  }
  REPOS_CACHE.delete(ctx.login);
  return jsonResponse({ ok: true, branch: defaultBranch }, 200);
}
