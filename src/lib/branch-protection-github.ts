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

/**
 * Effective ruleset rules for a branch (Phase 2 / issue #159 follow-up).
 *
 * GitHub `/repos/:o/:r/rules/branches/:b` returns the *aggregated* list of
 * rules from every active ruleset whose include/exclude targets cover this
 * branch. We collapse the array into a small struct the dashboard can
 * display alongside classic protection.
 *
 * The `branch.protected` boolean returned by the Branches API only reflects
 * **classic** branch protection — a repo protected exclusively through a
 * Ruleset will have `branch.protected = false` despite enforcement being
 * active. Surfacing both sources avoids the false-negative described in
 * issue #159's "out of scope: classic vs rulesets" note.
 */
export interface RulesetProtection {
  /** True if at least one ruleset rule applies to the branch. */
  active: boolean;
  /** required_status_checks contexts pulled from ruleset parameters. */
  required_checks: string[];
  /** True if a `non_fast_forward` rule applies (force push is blocked). */
  blocks_force_push: boolean;
  /** True if a `deletion` rule applies (branch deletion is blocked). */
  blocks_deletion: boolean;
  /** Raw list of rule `type` strings for visibility in the UI. */
  rule_types: string[];
}

interface GithubBranchRule {
  type?: string;
  parameters?: {
    required_status_checks?: Array<{ context?: string }>;
  };
}

export async function getBranchRulesetRules(
  token: string,
  owner: string,
  repo: string,
  branch: string,
): Promise<RulesetProtection> {
  const url = `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/rules/branches/${encodeURIComponent(branch)}`;
  const resp = await fetch(url, { headers: ghHeaders(token) });
  const empty: RulesetProtection = {
    active: false,
    required_checks: [],
    blocks_force_push: false,
    blocks_deletion: false,
    rule_types: [],
  };
  if (!resp.ok) return empty;
  const body = (await resp.json()) as unknown;
  if (!Array.isArray(body) || body.length === 0) return empty;
  const types = new Set<string>();
  const checks = new Set<string>();
  let blocksForce = false;
  let blocksDelete = false;
  for (const rule of body as GithubBranchRule[]) {
    if (typeof rule?.type !== "string") continue;
    types.add(rule.type);
    if (rule.type === "non_fast_forward") blocksForce = true;
    if (rule.type === "deletion") blocksDelete = true;
    if (rule.type === "required_status_checks" && rule.parameters) {
      const arr = rule.parameters.required_status_checks;
      if (Array.isArray(arr)) {
        for (const c of arr) {
          if (typeof c?.context === "string" && c.context) checks.add(c.context);
        }
      }
    }
  }
  return {
    active: types.size > 0,
    required_checks: [...checks].sort(),
    blocks_force_push: blocksForce,
    blocks_deletion: blocksDelete,
    rule_types: [...types].sort(),
  };
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
 * Summary the dashboard renders per repo. Merges classic branch protection
 * with effective ruleset rules so a repo protected exclusively via Rulesets
 * (where `.protected` is `false`) is still shown as protected.
 *
 * - `protected` is true if **either** classic protection OR an active
 *   ruleset rule applies.
 * - `protection_source` tells the UI which side(s) are contributing —
 *   `none` highlights repos that need attention (issue #159 motivation).
 * - `allow_force_pushes` / `allow_deletions` are true only when **no**
 *   source blocks the action (classic side = `enabled=true` OR no classic
 *   protection, and no `non_fast_forward` / `deletion` ruleset rule).
 * - `required_checks` is the **union** of classic + ruleset contexts.
 */
export interface RepoProtectionRow {
  owner: string;
  name: string;
  default_branch: string;
  protected: boolean;
  protection_source: "classic" | "ruleset" | "both" | "none";
  allow_force_pushes: boolean;
  allow_deletions: boolean;
  required_checks: string[];
  /** Rule `type` strings from active rulesets (e.g. `non_fast_forward`,
   *  `required_status_checks`). Empty when no ruleset applies. */
  ruleset_rule_types: string[];
  /** Classic protection HTTP status (404 → no classic rule, 200 →
   *  classic active, その他 → 表示用に保持して UI 側で warn する)。 */
  protection_status: number;
}

/**
 * Fetch classic protection + effective ruleset rules for every repo in
 * parallel and shape it into dashboard rows. Repos with neither source
 * surface as `protected: false` + `protection_source: "none"` (the ❌
 * highlight case issue #159 wants visible).
 */
export async function fetchProtectionRows(
  token: string,
  repos: RepoSummary[],
): Promise<RepoProtectionRow[]> {
  return Promise.all(
    repos.map(async (r): Promise<RepoProtectionRow> => {
      const [classicRes, ruleset] = await Promise.all([
        getBranchProtection(token, r.owner, r.name, r.default_branch),
        getBranchRulesetRules(token, r.owner, r.name, r.default_branch),
      ]);

      // Parse classic protection into the same shape as the ruleset side.
      let classicActive = false;
      let classicForcePushAllowed = false;
      let classicDeletionAllowed = false;
      let classicChecks: string[] = [];
      if (
        classicRes.ok &&
        typeof classicRes.body === "object" &&
        classicRes.body !== null
      ) {
        classicActive = true;
        const body = classicRes.body as Record<string, unknown>;
        const required = body["required_status_checks"];
        if (required && typeof required === "object") {
          const contexts = (required as { contexts?: unknown }).contexts;
          if (Array.isArray(contexts)) {
            classicChecks = contexts.filter((c): c is string => typeof c === "string");
          }
        }
        const forcePushes = body["allow_force_pushes"];
        const deletions = body["allow_deletions"];
        classicForcePushAllowed =
          typeof forcePushes === "object" && forcePushes !== null
            ? Boolean((forcePushes as { enabled?: unknown }).enabled)
            : false;
        classicDeletionAllowed =
          typeof deletions === "object" && deletions !== null
            ? Boolean((deletions as { enabled?: unknown }).enabled)
            : false;
      }

      const protectedByEither = classicActive || ruleset.active;
      const source: RepoProtectionRow["protection_source"] = classicActive && ruleset.active
        ? "both"
        : classicActive
          ? "classic"
          : ruleset.active
            ? "ruleset"
            : "none";

      // Action is allowed only when **no** source blocks it. Classic side
      // contributes "allowed" only when active + .enabled=true; ruleset
      // side contributes "blocked" when the rule is present.
      const forcePushAllowed = classicActive
        ? classicForcePushAllowed && !ruleset.blocks_force_push
        : !ruleset.blocks_force_push;
      const deletionAllowed = classicActive
        ? classicDeletionAllowed && !ruleset.blocks_deletion
        : !ruleset.blocks_deletion;

      // Union of required_checks contexts, de-duplicated, sorted for
      // stable UI ordering.
      const checks = new Set<string>([...classicChecks, ...ruleset.required_checks]);

      return {
        owner: r.owner,
        name: r.name,
        default_branch: r.default_branch,
        protected: protectedByEither,
        protection_source: source,
        allow_force_pushes: protectedByEither ? forcePushAllowed : false,
        allow_deletions: protectedByEither ? deletionAllowed : false,
        required_checks: [...checks].sort(),
        ruleset_rule_types: ruleset.rule_types,
        protection_status: classicRes.status,
      };
    }),
  );
}
