/**
 * Org-based access control.
 *
 * Inputs:
 *   - `origins:wt` (KV) — ephemeral worktree tunnels, always bypass ACL
 *   - `app-orgs` (KV JSON) — origin URL → github-org classification
 *   - `TENANT_ACL` (Worker secret JSON) — per-org allowlisted tenant_ids
 *   - `USER_ACL` (Worker secret JSON) — per-org allowlisted user emails
 *   - `APP_TENANT_ACL` (Worker secret JSON) — per-redirect-origin allowlisted
 *     tenant_ids; partitions tenants across apps within the same org
 *     (checked AFTER checkOrgAccess in handlers)
 *
 * Used by /top (tile filtering) and the OAuth callback handlers (redirect
 * authorization).
 *
 * TENANT_ACL and USER_ACL are OR-composed: a request passes when *either*
 * the tenant_id or the email is on its org's allowlist. Either secret may
 * be missing; at least one must match for non-bypassed origins.
 *
 * `isOrgWideUser` additionally exposes the USER_ACL half of that OR on its
 * own, so callers can tell *why* a request passed. It only observes; it
 * never changes whether a request passes.
 */

import type { Env } from "../index";
import { classifyOrigin, isWorktreeOrigin } from "./config";

/**
 * Returns true iff (`tenantId`, `email`) is allowed to access `origin`.
 *
 * - wt-registered tunnels: always allowed (dev bypass)
 * - ippoan / unclassified origins: always allowed
 * - ohishi-exp origins: allowed when tenantId ∈ TENANT_ACL["ohishi-exp"]
 *   OR email ∈ USER_ACL["ohishi-exp"] (either list may be empty/missing)
 *
 * Missing / malformed secrets are treated as empty allowlists (fail-closed
 * when both are empty).
 */
export async function checkOrgAccess(
  env: Env,
  origin: string,
  tenantId: string,
  email?: string,
): Promise<boolean> {
  if (await isWorktreeOrigin(env, origin)) return true;

  const org = await classifyOrigin(env, origin);
  if (org !== "ohishi-exp") return true;

  return matchesOrgAllowlist(env, org, tenantId, email);
}

/**
 * Per-app tenant ACL: partitions tenants across apps within the same org,
 * with an optional global email bypass (typically used for developer access
 * on staging).
 *
 * Returns true iff (`tenantId`, `email`) is allowed to access the app at
 * `redirectOrigin`. Called *after* `checkOrgAccess` — org-level ACL is the
 * primary defense, this layer additionally restricts which tenants can use
 * which app.
 *
 * JSON shape (Worker secret `APP_TENANT_ACL`):
 * ```
 * {
 *   "bypass_emails": ["m.tama.ramu@gmail.com"],
 *   "apps": {
 *     "https://ichibanboshi.ippoan.org":         ["<prod-tenant-uuid>"],
 *     "https://ichibanboshi-staging.ippoan.org": ["<prod-tenant-uuid>"]
 *   }
 * }
 * ```
 *
 * Resolution order:
 * 1. `APP_TENANT_ACL` missing → pass (no restriction configured)
 * 2. `email` ∈ `bypass_emails` (case-insensitive) → pass
 *    (global developer bypass; typically set on staging only)
 * 3. `apps[redirectOrigin]` absent / not array → pass
 *    (opt-in: only origins with explicit entries are restricted)
 * 4. `apps[redirectOrigin]` contains `"*"` → pass (any tenant)
 * 5. `apps[redirectOrigin]` contains `tenantId` → pass
 * 6. Otherwise → deny
 * 7. Malformed JSON → pass (fail-open; we don't want a new check to break
 *    existing logins on parse error — the org ACL is still enforced)
 *
 * Keys in `apps` must be the exact origin string returned by
 * `new URL(uri).origin` (no trailing slash).
 */
export function checkAppTenant(
  env: Env,
  redirectOrigin: string,
  tenantId: string,
  email?: string,
): boolean {
  if (!env.APP_TENANT_ACL) return true;
  try {
    const config = JSON.parse(env.APP_TENANT_ACL) as {
      bypass_emails?: string[];
      apps?: Record<string, string[]>;
    };

    // 1. Global email bypass (staging dev access).
    if (email && Array.isArray(config.bypass_emails)) {
      const lower = email.toLowerCase();
      if (config.bypass_emails.some((e) => typeof e === "string" && e.toLowerCase() === lower)) {
        return true;
      }
    }

    // 2. Per-app tenant check.
    if (!config.apps || typeof config.apps !== "object") return true;
    const allowed = config.apps[redirectOrigin];
    if (!Array.isArray(allowed)) return true; // unregistered origin = pass
    if (allowed.includes("*")) return true;
    return allowed.includes(tenantId);
  } catch {
    return true; // malformed → fail-open
  }
}

/**
 * Synchronous ACL lookup — assumes the caller already knows the origin's
 * org. Used by /top where classify results are already in hand.
 */
export function isTenantInOrgAllowlist(
  env: Env,
  org: string,
  tenantId: string,
  email?: string,
): boolean {
  return matchesOrgAllowlist(env, org, tenantId, email);
}

/**
 * True iff `email` is on `USER_ACL[org]` — i.e. this person is allowlisted
 * **by identity, independent of which tenant their JWT carries**.
 *
 * That is exactly "may look beyond their own tenant inside this org":
 * `checkOrgAccess` passes them for any `tenant_id`, so they are not bound by
 * the tenant boundary. This is **authorization data** (`USER_ACL` is the
 * single source of truth for who may cross tenants) — do not confuse it with
 * `DEVELOPER_EMAILS` in `admin-html.ts` / `device-setup.ts`, which is a
 * display-only UI gate and is never consulted for access decisions.
 *
 * Deliberately **not** built on `matchesOrgAllowlist`: that helper checks
 * TENANT_ACL first and returns early, so somebody listed on *both* lists
 * would never be observed as a USER_ACL match. Here only USER_ACL is read.
 *
 * Purely observational — nothing in this function feeds an allow/deny
 * decision, so adding it cannot change who gets in.
 *
 * Fail-closed via `listFor`: secret missing / unparseable / org value not an
 * array / org key absent → empty list → `false`. Empty `email` → `false`.
 * Comparison is case-insensitive, matching `matchesOrgAllowlist`.
 *
 * Non-string elements inside the array are dropped one by one. `listFor` only
 * checks `Array.isArray`, not the element types, so a typo like
 * `{"ohishi-exp": [1]}` would otherwise throw here. That matters more than it
 * does in `matchesOrgAllowlist`: that helper returns early on a TENANT_ACL hit
 * and never reads USER_ACL for those users, whereas this function *always*
 * reads it — so a malformed USER_ACL would start breaking logins that
 * previously succeeded via TENANT_ACL. `listFor` itself is deliberately left
 * alone (it is shared with the two existing ACL checks).
 */
export function isOrgWideUser(env: Env, org: string, email?: string): boolean {
  if (!email) return false;
  const users = listFor(env.USER_ACL, org)
    .filter((e): e is string => typeof e === "string")
    .map((e) => e.toLowerCase());
  return users.includes(email.toLowerCase());
}

function matchesOrgAllowlist(
  env: Env,
  org: string,
  tenantId: string,
  email?: string,
): boolean {
  if (tenantId) {
    const tenants = listFor(env.TENANT_ACL, org);
    if (tenants.includes(tenantId)) return true;
  }
  if (email) {
    const users = listFor(env.USER_ACL, org).map((e) => e.toLowerCase());
    if (users.includes(email.toLowerCase())) return true;
  }
  return false;
}

function listFor(secret: string | undefined, org: string): string[] {
  if (!secret) return [];
  try {
    const parsed = JSON.parse(secret) as Record<string, string[]>;
    const list = parsed[org];
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}
