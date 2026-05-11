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
 * Per-app tenant ACL: partitions tenants across apps within the same org.
 *
 * Returns true iff `tenantId` is allowed to access the app at
 * `redirectOrigin`. Called *after* `checkOrgAccess` — org-level ACL is the
 * primary defense, this layer additionally restricts which tenants can use
 * which app (e.g. only the ichibanboshi tenant can hit ichibanboshi, even
 * though dtako-admin tenants also pass the ohishi-exp org check).
 *
 * Semantics:
 * - `APP_TENANT_ACL` missing → pass (no restriction configured)
 * - origin not in map → pass (opt-in: only origins with explicit entries
 *   are restricted; new apps don't need to register here)
 * - allowed list contains `"*"` → any tenant passes (useful for staging)
 * - allowed list contains `tenantId` → pass
 * - otherwise → deny
 * - malformed JSON or non-array value → pass (fail-open; we don't want a
 *   new check to break existing logins on parse error — the org ACL is
 *   still enforced)
 *
 * Keys must be the exact origin string returned by `new URL(uri).origin`
 * (no trailing slash).
 */
export function checkAppTenant(
  env: Env,
  redirectOrigin: string,
  tenantId: string,
): boolean {
  if (!env.APP_TENANT_ACL) return true;
  try {
    const map = JSON.parse(env.APP_TENANT_ACL) as Record<string, string[]>;
    const allowed = map[redirectOrigin];
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
