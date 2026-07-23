/**
 * KV-backed allowlist with in-memory cache.
 *
 * KV keys:
 *   origins:prod    - production frontends
 *   origins:staging - staging frontends
 *   origins:dev     - dev-proxy frontends (*-dev.ippoan.org)
 *   origins:wt      - ephemeral worktree URLs (e.g. *.trycloudflare.com).
 *                     Read **without** in-memory cache so entries added via
 *                     `wrangler kv key put` take effect immediately — only
 *                     KV edge propagation (seconds) remains.
 *   app-orgs        - JSON map of app-token → github-org, e.g.
 *                     `{"dtako-admin":"ohishi-exp","ohishi2":"ohishi-exp"}`.
 *                     Used to restrict specific orgs to allowlisted tenants.
 *   google-mcp-user-allowlist - JSON array of Google account emails allowed
 *                     to use `/mcp/authorize`'s Google IdP branch (issue: MCP
 *                     OAuth に Google IdP を追加), e.g. `["m.tama.ramu@gmail.com"]`.
 *                     Secrets Store は使わない — 中身は「誰が管理者アカウントか」
 *                     という設定であって秘密の値ではなく (`DEVELOPER_EMAILS` が
 *                     `device-setup.ts`/`admin-html.ts` で平文ハードコードされて
 *                     いるのと同じ位置づけ)、既存の origins:* / app-orgs と同じ
 *                     KV allowlist 規約に揃える方が GCP Secret Manager 側の
 *                     provisioning が要らず単純。
 *
 * At runtime the worker reads `origins:<WORKER_ENV>` ∪ `origins:dev` ∪ `origins:wt`
 * and unions them.
 */

import type { Env } from "../index";

const CACHE_TTL_MS = 60_000;

type CacheEntry = { value: string; expiresAt: number };
const cache = new Map<string, CacheEntry>();

async function readKey(env: Env, key: string): Promise<string> {
  const now = Date.now();
  const cached = cache.get(key);
  if (cached && cached.expiresAt > now) return cached.value;

  let value = "";
  try {
    value = (await env.AUTH_CONFIG?.get(key)) ?? "";
  } catch {
    value = "";
  }
  cache.set(key, { value, expiresAt: now + CACHE_TTL_MS });
  return value;
}

/**
 * Read a KV key without in-memory caching. Used for rapidly-changing allow
 * lists (ephemeral worktree quick-tunnel URLs) where a 60s cache would
 * force the caller to wait after each `wrangler kv key put`.
 */
async function readKeyNoCache(env: Env, key: string): Promise<string> {
  try {
    return (await env.AUTH_CONFIG?.get(key)) ?? "";
  } catch {
    return "";
  }
}

/**
 * Returns the combined allowlist for the current worker environment
 * (`origins:<WORKER_ENV>` ∪ `origins:dev` ∪ `origins:wt`).
 *
 * Used by OAuth redirect validators. wt entries are honored so /wt-quick
 * worktree tunnels can complete OAuth login.
 */
export async function getAllowedOrigins(env: Env): Promise<string> {
  const workerEnv = env.WORKER_ENV || "prod";
  const [envOrigins, devOrigins, wtOrigins] = await Promise.all([
    readKey(env, `origins:${workerEnv}`),
    readKey(env, "origins:dev"),
    readKeyNoCache(env, "origins:wt"),
  ]);

  return [envOrigins, devOrigins, wtOrigins]
    .filter((s) => s.length > 0)
    .join(",");
}

/**
 * Returns the origins shown on the /top page. Excludes `origins:wt` so
 * ephemeral worktree tunnels are not advertised as apps.
 */
export async function getDisplayOrigins(env: Env): Promise<string> {
  const workerEnv = env.WORKER_ENV || "prod";
  const [envOrigins, devOrigins] = await Promise.all([
    readKey(env, `origins:${workerEnv}`),
    readKey(env, "origins:dev"),
  ]);

  return [envOrigins, devOrigins].filter((s) => s.length > 0).join(",");
}

/**
 * Classify an origin URL by its GitHub org. Returns "ohishi-exp" when the
 * origin URL contains a token registered under ohishi-exp in the `app-orgs`
 * KV JSON map, otherwise "ippoan" (default — permissive).
 */
export async function classifyOrigin(
  env: Env,
  origin: string,
): Promise<"ohishi-exp" | "ippoan"> {
  const raw = await readKey(env, "app-orgs");
  if (!raw) return "ippoan";
  let map: Record<string, string>;
  try {
    map = JSON.parse(raw);
  } catch {
    return "ippoan";
  }
  for (const [token, org] of Object.entries(map)) {
    if (org === "ohishi-exp" && origin.includes(token)) {
      return "ohishi-exp";
    }
  }
  return "ippoan";
}

/**
 * True iff the given origin URL is listed in `origins:wt` (ephemeral
 * worktree tunnels). Reads fresh from KV so newly-registered tunnels are
 * recognized immediately.
 */
export async function isWorktreeOrigin(
  env: Env,
  origin: string,
): Promise<boolean> {
  const raw = await readKeyNoCache(env, "origins:wt");
  if (!raw) return false;
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .includes(origin);
}

/**
 * Google IdP MCP allowlist (`google-mcp-user-allowlist` KV key). Returns the
 * raw JSON string as stored (or `""` if unset) — caller (`mcp-auth-callback-
 * google.ts`'s `parseAllowlist`) is fail-closed on falsy/malformed input.
 */
export async function getGoogleMcpUserAllowlist(env: Env): Promise<string> {
  return readKey(env, "google-mcp-user-allowlist");
}

/** Test-only cache clear helper. */
export function _clearAllowedOriginsCache(): void {
  cache.clear();
}
