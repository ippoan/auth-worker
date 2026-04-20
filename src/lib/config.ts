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

/** Test-only cache clear helper. */
export function _clearAllowedOriginsCache(): void {
  cache.clear();
}
