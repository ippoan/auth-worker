import type { Env } from "../index";

/** 適用済み plan 1 件分。ippoan/ippoan-dev-plans の plan snapshot 由来。 */
export interface ActivePlan {
  /** Plan ID (例: `20260502_001_new_csv_parser`) */
  id: string;
  /** stage (例: `ga` / `early` / `applied`) */
  stage: string;
  /** early 等で対象が絞られている場合の scope (例: `ohishi-exp`) */
  scope?: string;
}

/** AUTH_CONFIG KV 上の plan snapshot キー。
 *  値は `ActivePlan[]` または `{ "active_plans": ActivePlan[] }` の JSON。
 *  snapshot の投入経路 (dev-plans CI 等) は未確定のため、未設定 / 壊れた JSON
 *  でも endpoint は空配列で応答する (Refs #253)。 */
export const DEV_PLANS_SNAPSHOT_KEY = "dev_plans_snapshot";

function parseActivePlans(raw: string): ActivePlan[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  const list = Array.isArray(parsed)
    ? parsed
    : (parsed as { active_plans?: unknown })?.active_plans;
  if (!Array.isArray(list)) return [];
  const plans: ActivePlan[] = [];
  for (const entry of list) {
    if (!entry || typeof entry !== "object") continue;
    const { id, stage, scope } = entry as Record<string, unknown>;
    if (typeof id !== "string" || typeof stage !== "string") continue;
    const plan: ActivePlan = { id, stage };
    if (typeof scope === "string" && scope) plan.scope = scope;
    plans.push(plan);
  }
  return plans;
}

/** GET /api/version — auth-worker 自身の version と適用済み plan の一覧を返す。
 *  /api/health (ALC backend proxy) と異なり upstream に依存しない。
 *  VersionBadge / StagingFooter (auth-client) が tooltip 表示に使う。 */
export async function handleVersion(env: Env): Promise<Response> {
  let activePlans: ActivePlan[] = [];
  try {
    const raw = await env.AUTH_CONFIG.get(DEV_PLANS_SNAPSHOT_KEY);
    if (raw) activePlans = parseActivePlans(raw);
  } catch {
    // KV 障害時も version 表示は生かす (fail-open で空配列)
  }

  const body = {
    auth_worker_version: env.VERSION || "dev",
    active_plans: activePlans,
  };

  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
