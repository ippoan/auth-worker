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
import type {
  BranchProtectionPayload,
  ProjectType,
} from "./branch-protection-presets";

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

/**
 * Probe a branch for ruleset protection. Two endpoints in series:
 *
 *   1. `/repos/:o/:r/rules/branches/:b` — the "effective rules" endpoint.
 *      Returns flattened rules from every **active** ruleset whose target
 *      pattern matches the branch. Rulesets in `evaluate` / `disabled`
 *      enforcement modes are NOT returned (per GitHub docs).
 *   2. `/repos/:o/:r/rulesets` — the list of rulesets attached at the repo
 *      level. Used to surface evaluate-mode rulesets and to give an honest
 *      "we saw a ruleset but it isn't enforcing on this branch" state when
 *      (1) is empty. Org-level rulesets do NOT appear here; they would
 *      need `/orgs/:o/rulesets` which requires `admin:org` scope.
 *
 * Each call's HTTP status + result count is logged so a misconfiguration
 * (403 on either endpoint, evaluate-mode ruleset, target-branch mismatch)
 * can be diagnosed from Cloudflare logs without changing code.
 */
interface GithubRepoRuleset {
  id?: number;
  enforcement?: string;
  conditions?: {
    ref_name?: {
      include?: string[];
      exclude?: string[];
    };
  };
}

function refMatchesBranch(
  conditions: GithubRepoRuleset["conditions"],
  branch: string,
  defaultBranch: string,
): boolean {
  const refName = conditions?.ref_name;
  if (!refName) return true; // missing conditions ≈ "applies to all"
  const include = refName.include ?? [];
  const exclude = refName.exclude ?? [];
  const branchRef = `refs/heads/${branch}`;
  const defaultRef = `refs/heads/${defaultBranch}`;
  const matchesPattern = (p: string): boolean => {
    if (p === "~ALL") return true;
    if (p === "~DEFAULT_BRANCH") return branch === defaultBranch;
    return p === branch || p === branchRef || p === defaultRef;
  };
  if (exclude.some(matchesPattern)) return false;
  if (include.length === 0) return true;
  return include.some(matchesPattern);
}

export async function getBranchRulesetRules(
  token: string,
  owner: string,
  repo: string,
  branch: string,
): Promise<RulesetProtection> {
  const empty: RulesetProtection = {
    active: false,
    required_checks: [],
    blocks_force_push: false,
    blocks_deletion: false,
    rule_types: [],
  };

  // Endpoint 1: effective rules for the branch (active rulesets only).
  const rulesUrl = `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/rules/branches/${encodeURIComponent(branch)}`;
  const rulesResp = await fetch(rulesUrl, { headers: ghHeaders(token) });
  const types = new Set<string>();
  const checks = new Set<string>();
  let blocksForce = false;
  let blocksDelete = false;
  let ruleCount = 0;
  if (rulesResp.ok) {
    const body = (await rulesResp.json()) as unknown;
    if (Array.isArray(body)) {
      ruleCount = body.length;
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
    }
  }

  // Endpoint 2: list of repo-level rulesets (used as a fallback for the
  // "evaluate mode" / "rule exists but doesn't match this branch" case).
  // Only count the ones whose conditions would match this branch — a repo
  // can have stale rulesets targeting other branches.
  let rulesetsFound = 0;
  let evaluateModeFound = false;
  try {
    const listResp = await fetch(
      `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/rulesets`,
      { headers: ghHeaders(token) },
    );
    if (listResp.ok) {
      const body = (await listResp.json()) as unknown;
      if (Array.isArray(body)) {
        rulesetsFound = body.length;
        for (const rs of body as GithubRepoRuleset[]) {
          if (refMatchesBranch(rs.conditions, branch, branch)) {
            if (rs.enforcement === "evaluate") evaluateModeFound = true;
          }
        }
      }
    } else {
      console.warn(JSON.stringify({
        event: "ruleset_list_probe_failed",
        owner, repo, branch,
        status: listResp.status,
      }));
    }
  } catch (e) {
    console.warn(JSON.stringify({
      event: "ruleset_list_probe_error",
      owner, repo, branch,
      error: e instanceof Error ? e.message : String(e),
    }));
  }

  console.log(JSON.stringify({
    event: "ruleset_probe",
    owner, repo, branch,
    rules_status: rulesResp.status,
    rules_count: ruleCount,
    rule_types: [...types],
    repo_rulesets_count: rulesetsFound,
    evaluate_mode_found: evaluateModeFound,
  }));

  // "active" if real enforcing rules were returned. Evaluate-mode rulesets
  // are surfaced via `rule_types` containing the synthetic marker
  // `evaluate-mode` so the UI can render an amber hint without claiming
  // the branch is actually protected.
  const realActive = types.size > 0;
  if (!realActive && evaluateModeFound) {
    return {
      ...empty,
      rule_types: ["evaluate-mode"],
    };
  }
  return {
    active: realActive,
    required_checks: [...checks].sort(),
    blocks_force_push: blocksForce,
    blocks_deletion: blocksDelete,
    rule_types: [...types].sort(),
  };
}

/**
 * Repo-level merge settings the dashboard surfaces alongside branch
 * protection. These come from `GET /repos/:o/:r` (not the minimal
 * `/user/repos` response, which omits them) so we pay one extra round-trip
 * per repo. The CI's branch-protection check (`ci-workflows/.github/
 * workflows/frontend-ci.yml`) already enforces both of these to be `true`,
 * so a repo with either flag off blocks `gh pr merge --auto`.
 */
export interface RepoSettings {
  allow_auto_merge: boolean;
  delete_branch_on_merge: boolean;
}

export async function getRepoSettings(
  token: string,
  owner: string,
  repo: string,
): Promise<RepoSettings | null> {
  const resp = await fetch(
    `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
    { headers: ghHeaders(token) },
  );
  if (!resp.ok) return null;
  const body = (await resp.json()) as Record<string, unknown>;
  return {
    allow_auto_merge: Boolean(body["allow_auto_merge"]),
    delete_branch_on_merge: Boolean(body["delete_branch_on_merge"]),
  };
}

/**
 * `PATCH /repos/:o/:r` with both merge-flow flags set to `true`. Returns
 * the resulting settings on success, or null on failure (caller surfaces
 * a JSON error). Other repo fields are untouched.
 */
export async function patchRepoSettings(
  token: string,
  owner: string,
  repo: string,
  settings: Partial<RepoSettings>,
): Promise<ProtectionResult> {
  const resp = await fetch(
    `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
    {
      method: "PATCH",
      headers: { ...ghHeaders(token), "Content-Type": "application/json" },
      body: JSON.stringify(settings),
    },
  );
  return { ok: resp.ok, status: resp.status, body: await readBody(resp) };
}

/**
 * Detect whether a repo is a Cloudflare Worker (`frontend-ci.yml` consumer),
 * a Rust crate (`rust-ci.yml` consumer), a Go service (`go-ci.yml` consumer
 * or any repo with a top-level `go.mod`), a Node.js library (`lib-ci.yml`
 * consumer), an Android app (`android-ci.yml` consumer or any repo with
 * `app/src/main/AndroidManifest.xml`), or none of these.
 *
 * Source of truth, in order:
 *   1. `.github/workflows/ci.yml` — most consumers use exactly that path and
 *      its body references the shared workflow:
 *         uses: ippoan/ci-workflows/.github/workflows/frontend-ci.yml@main
 *         uses: ippoan/ci-workflows/.github/workflows/rust-ci.yml@main
 *         uses: ippoan/ci-workflows/.github/workflows/go-ci.yml@main
 *         uses: ippoan/ci-workflows/.github/workflows/lib-ci.yml@main
 *         uses: ippoan/ci-workflows/.github/workflows/android-ci.yml@main
 *      A simple substring match is robust here — `.yml@` is unique enough
 *      and immune to indentation / quoting differences.
 *   2. `Cargo.toml` at the repo root — definitive for Rust crates that
 *      either pre-date the reusable workflow or use a custom CI shell.
 *   3. `go.mod` at the repo root — definitive for Go modules whose CI is
 *      still a hand-rolled workflow file (e.g. the initial
 *      `secrets-inventory-gcp` deploy.yml that pre-dates `go-ci.yml`).
 *   4. `app/src/main/AndroidManifest.xml` — definitive for Android (Gradle)
 *      apps. The Manifest path is fixed by AGP convention and is far more
 *      specific than `build.gradle.kts` (which a generic Kotlin/JVM project
 *      could also have). Probed last so a Rust/Go hybrid that vendored an
 *      Android shim still wins on its primary marker.
 *
 * Returns `"unknown"` when no marker matches. The dashboard then surfaces
 * every preset with a hint instead of locking the operator out — the worst
 * case is they pick the wrong one and the apply call fails on the GitHub
 * side with a structured error they can act on.
 *
 * Bounded HTTP cost per repo: at most four GETs (ci.yml + Cargo.toml +
 * go.mod + AndroidManifest.xml). All 404-fast when missing. Each call
 * short-circuits on any 5xx so transient GitHub errors don't blow up the
 * dashboard page.
 *
 * The `lib` detection only consults `ci.yml` because there is no language-
 * level file that uniquely identifies a Node.js library repo (a generic
 * `package.json` could be a worker, a frontend, or a lib). The dashboard
 * therefore treats lib repos as `"unknown"` until their CI is migrated to
 * the lib-ci.yml reusable.
 */
export async function detectProjectType(
  token: string,
  owner: string,
  repo: string,
): Promise<ProjectType> {
  const ci = await fetchTextFile(
    token,
    owner,
    repo,
    ".github/workflows/ci.yml",
  );
  if (ci) {
    if (ci.includes("ci-workflows/.github/workflows/frontend-ci.yml")) {
      return "worker";
    }
    if (ci.includes("ci-workflows/.github/workflows/rust-ci.yml")) {
      return "rust";
    }
    if (ci.includes("ci-workflows/.github/workflows/go-ci.yml")) {
      return "go";
    }
    if (ci.includes("ci-workflows/.github/workflows/lib-ci.yml")) {
      return "lib";
    }
    if (ci.includes("ci-workflows/.github/workflows/android-ci.yml")) {
      return "android";
    }
  }
  // Cargo.toml at the repo root is conclusive for Rust crates even when the
  // workflow file is missing / custom.
  const cargo = await fetchTextFile(token, owner, repo, "Cargo.toml");
  if (cargo) return "rust";
  // go.mod at the repo root is conclusive for Go modules. We probe it last
  // so a hybrid repo (e.g. a Rust crate with a vendored Go helper) still
  // resolves to "rust" via Cargo.toml above.
  const goMod = await fetchTextFile(token, owner, repo, "go.mod");
  if (goMod) return "go";
  // AndroidManifest.xml at the AGP-standard module path is conclusive for
  // Android apps (Gradle / Kotlin). Probed after Cargo/go so a hybrid repo
  // keeps its primary classification.
  const manifest = await fetchTextFile(
    token,
    owner,
    repo,
    "app/src/main/AndroidManifest.xml",
  );
  if (manifest) return "android";
  return "unknown";
}

/**
 * `GET /repos/:o/:r/contents/:path` returning raw text body. 404 → null
 * (file absent), 5xx → null (treated as "unknown" by the caller —
 * dashboard failure-mode is better than blocking the whole page on one
 * flaky API call). Decodes base64 in-process because the Workers runtime
 * has no way to set the `Accept: application/vnd.github.raw` header
 * reliably through cached fetches in every environment.
 */
async function fetchTextFile(
  token: string,
  owner: string,
  repo: string,
  path: string,
): Promise<string | null> {
  const url =
    `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}` +
    `/contents/${path.split("/").map(encodeURIComponent).join("/")}`;
  let resp: Response;
  try {
    resp = await fetch(url, { headers: ghHeaders(token) });
  } catch {
    return null;
  }
  if (resp.status === 404) return null;
  if (!resp.ok) return null;
  const body = (await resp.json()) as {
    content?: string;
    encoding?: string;
  };
  if (!body.content || body.encoding !== "base64") return null;
  try {
    return atob(body.content.replace(/\n/g, ""));
  } catch {
    return null;
  }
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
  /** Repo-level merge settings (auto-merge + delete on merge). `null`
   *  when the `GET /repos/:o/:r` probe failed — the UI shows a neutral
   *  state then. */
  repo_settings: RepoSettings | null;
  /** Detected project type (`worker` / `rust` / `unknown`). The dashboard
   *  uses this to show only the matching preset's Apply button. */
  project_type: ProjectType;
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
      const [classicRes, ruleset, settings, projectType] = await Promise.all([
        getBranchProtection(token, r.owner, r.name, r.default_branch),
        getBranchRulesetRules(token, r.owner, r.name, r.default_branch),
        getRepoSettings(token, r.owner, r.name),
        detectProjectType(token, r.owner, r.name),
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
        repo_settings: settings,
        project_type: projectType,
      };
    }),
  );
}
