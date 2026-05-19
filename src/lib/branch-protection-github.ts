/**
 * Branch-protection GitHub-API helpers (issue #159 Phase 1).
 *
 * `/mcp/admin/exec` (binary path) と `/api/dashboard/repos/*` (browser path)
 * の両方から呼ぶため、共通の GitHub REST 呼び出しをここに集約する。
 *
 * いずれも:
 *   - `Authorization: Bearer <user OAuth token>` を使う (Administration:write
 *     を持つ GitHub App token ではなく、ユーザーの repo scope token)。
 *     これにより proxy が `delete_repo` を持たないことを構造的に担保する
 *     (`mcp-admin-exec.ts` の冒頭参照)。
 *   - `Accept`/`User-Agent`/`X-GitHub-Api-Version` を統一する。
 */

import type { Env } from "../index";
import { decryptWithKey } from "./mcp-crypto";
import type { BranchProtectionPayload } from "./branch-protection-presets";

const GITHUB_API = "https://api.github.com";
const GITHUB_UA = "ippoan-auth-worker";

function ghHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "User-Agent": GITHUB_UA,
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

/**
 * Load the encrypted GitHub OAuth token stored under `github_token:github:<login>`
 * (or `github_token:<sub>` for legacy keys) and decrypt it. Returns null if the
 * token is missing or fails to decrypt — caller renders a "re-pair" hint.
 */
export async function loadGithubToken(
  env: Env,
  sub: string,
): Promise<string | null> {
  if (!env.MCP_OAUTH_KV || !env.SSO_ENCRYPTION_KEY) return null;
  const encrypted = await env.MCP_OAUTH_KV.get(`github_token:${sub}`);
  if (!encrypted) return null;
  try {
    return await decryptWithKey(encrypted, env.SSO_ENCRYPTION_KEY);
  } catch {
    return null;
  }
}

export interface ProtectionResult {
  ok: boolean;
  status: number;
  body: unknown;
}

function protectionPath(owner: string, repo: string, branch: string): string {
  return `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/branches/${encodeURIComponent(branch)}/protection`;
}

async function readBody(resp: Response): Promise<unknown> {
  const text = await resp.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export async function setBranchProtection(
  token: string,
  owner: string,
  repo: string,
  branch: string,
  payload: BranchProtectionPayload,
): Promise<ProtectionResult> {
  const resp = await fetch(`${GITHUB_API}${protectionPath(owner, repo, branch)}`, {
    method: "PUT",
    headers: { ...ghHeaders(token), "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return { ok: resp.ok, status: resp.status, body: await readBody(resp) };
}

export async function getBranchProtection(
  token: string,
  owner: string,
  repo: string,
  branch: string,
): Promise<ProtectionResult> {
  const resp = await fetch(`${GITHUB_API}${protectionPath(owner, repo, branch)}`, {
    method: "GET",
    headers: ghHeaders(token),
  });
  return { ok: resp.ok, status: resp.status, body: await readBody(resp) };
}

export async function deleteBranchProtection(
  token: string,
  owner: string,
  repo: string,
  branch: string,
): Promise<ProtectionResult> {
  const resp = await fetch(`${GITHUB_API}${protectionPath(owner, repo, branch)}`, {
    method: "DELETE",
    headers: ghHeaders(token),
  });
  return { ok: resp.ok, status: resp.status, body: await readBody(resp) };
}

export interface RepoSummary {
  owner: string;
  name: string;
  default_branch: string;
}

interface GithubRepoListItem {
  name?: string;
  full_name?: string;
  default_branch?: string;
  owner?: { login?: string };
  archived?: boolean;
  fork?: boolean;
}

/**
 * `GET /user/repos?per_page=100&affiliation=...` を 1 page だけ取る。
 *
 * issue #159 Phase 1 では `ippoan/*` のみ対象なので、page=1 (最大 100 件) で
 * 十分。将来 owner pool が増えたら pagination を入れる。
 *
 * archived / fork は除外する (保護対象ではない)。
 */
export async function listOwnedRepos(
  token: string,
  ownerAllowlist: readonly string[],
): Promise<RepoSummary[]> {
  const resp = await fetch(
    `${GITHUB_API}/user/repos?per_page=100&affiliation=owner,organization_member`,
    { headers: ghHeaders(token) },
  );
  if (!resp.ok) {
    throw new Error(`github_user_repos_failed: ${resp.status}`);
  }
  const items = (await resp.json()) as GithubRepoListItem[];
  const out: RepoSummary[] = [];
  for (const item of items) {
    const owner = item.owner?.login;
    const name = item.name;
    const defaultBranch = item.default_branch;
    if (!owner || !name || !defaultBranch) continue;
    if (item.archived || item.fork) continue;
    if (!ownerAllowlist.includes(owner)) continue;
    out.push({ owner, name, default_branch: defaultBranch });
  }
  // Stable sort by owner/name for deterministic UI.
  out.sort((a, b) => {
    if (a.owner !== b.owner) return a.owner < b.owner ? -1 : 1;
    return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
  });
  return out;
}

/**
 * Summary the dashboard renders per repo. `protection` is the raw GitHub
 * protection record (or null if unprotected / 404).
 */
export interface RepoProtectionRow {
  owner: string;
  name: string;
  default_branch: string;
  protected: boolean;
  allow_force_pushes: boolean;
  allow_deletions: boolean;
  required_checks: string[];
  /** `protection` 取得時の HTTP status (404 → unprotected, 200 → protected,
   *  その他 → 表示用に保持して UI 側で warn する)。 */
  protection_status: number;
}

/**
 * Fetch `getBranchProtection` for every repo in parallel and shape it into
 * dashboard rows. 404 → unprotected (UI で ❌ 強調表示)。
 */
export async function fetchProtectionRows(
  token: string,
  repos: RepoSummary[],
): Promise<RepoProtectionRow[]> {
  return Promise.all(
    repos.map(async (r): Promise<RepoProtectionRow> => {
      const res = await getBranchProtection(token, r.owner, r.name, r.default_branch);
      const base: RepoProtectionRow = {
        owner: r.owner,
        name: r.name,
        default_branch: r.default_branch,
        protected: false,
        allow_force_pushes: false,
        allow_deletions: false,
        required_checks: [],
        protection_status: res.status,
      };
      if (res.status === 404) return base;
      if (!res.ok || typeof res.body !== "object" || res.body === null) {
        return base;
      }
      const body = res.body as Record<string, unknown>;
      const required = body["required_status_checks"];
      let checks: string[] = [];
      if (required && typeof required === "object") {
        const contexts = (required as { contexts?: unknown }).contexts;
        if (Array.isArray(contexts)) {
          checks = contexts.filter((c): c is string => typeof c === "string");
        }
      }
      const forcePushes = body["allow_force_pushes"];
      const deletions = body["allow_deletions"];
      return {
        ...base,
        protected: true,
        allow_force_pushes:
          typeof forcePushes === "object" && forcePushes !== null
            ? Boolean((forcePushes as { enabled?: unknown }).enabled)
            : false,
        allow_deletions:
          typeof deletions === "object" && deletions !== null
            ? Boolean((deletions as { enabled?: unknown }).enabled)
            : false,
        required_checks: checks,
      };
    }),
  );
}
