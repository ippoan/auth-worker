/**
 * Top page handler
 * Serves WOFF auth landing page with app navigation menu
 */
import type { Env } from "../index";
import { renderTopPage, type AppEntry } from "../lib/top-html";
import { getAuthCookie } from "../lib/cookies";
import { classifyOrigin, getDisplayOrigins } from "../lib/config";
import { isTenantInOrgAllowlist } from "../lib/acl";

/** Known app patterns — matches both production and staging URLs */
const APP_PATTERNS: Array<{
  match: (origin: string) => boolean;
  name: string;
  icon: string;
  description: string;
}> = [
  { match: (o) => o.includes("nuxt-pwa-carins") || o.includes("carins"), name: "車検証管理", icon: "車", description: "車検証・ファイル管理" },
  { match: (o) => o.includes("ohishi2") || o.includes("dtako-admin") || o.includes("dtako"), name: "DTako 管理", icon: "DVR", description: "ドライブレコーダーログ" },
  { match: (o) => o.includes("nuxt-items") || o.includes("items"), name: "物品管理", icon: "箱", description: "組織・個人の物品管理" },
  { match: (o) => o.includes("alc-app") || (o.includes("alc") && !o.includes("alc-api")), name: "アルコールチェック", icon: "🍺", description: "アルコール検知・管理" },
  { match: (o) => o.includes("nuxt-ichibanboshi") || o.includes("ichibanboshi"), name: "一番星", icon: "⭐", description: "一番星管理" },
  { match: (o) => o.includes("nuxt-notify") || o.includes("notify"), name: "通知管理", icon: "📨", description: "メッセージ配信" },
  { match: (o) => o.includes("nuxt-trouble") || o.includes("trouble"), name: "トラブル管理", icon: "🚨", description: "トラブル・事故管理" },
];

/** Map origin URL to app metadata */
function originToApp(origin: string): AppEntry {
  for (const pattern of APP_PATTERNS) {
    if (pattern.match(origin)) {
      return { name: pattern.name, url: origin, icon: pattern.icon, description: pattern.description };
    }
  }
  return { name: origin, url: origin, icon: "App", description: "" };
}

function tenantIdFromCookie(request: Request): string {
  const token = getAuthCookie(request);
  if (!token) return "";
  const payloadB64 = token.split(".")[1];
  if (!payloadB64) return "";
  try {
    const payload = JSON.parse(atob(payloadB64));
    return payload.tenant_id || payload.org || "";
  } catch {
    return "";
  }
}

export async function handleTopPage(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);

  // Server-side auth check: redirect to /login if no auth cookie
  // Skip for WOFF flow (?woff=1) and OAuth callback return (?lw_callback=1)
  // lw_callback: cookie was just set by callback, client JS will process #token fragment
  if (!url.searchParams.has("woff") && !url.searchParams.has("lw_callback") && !getAuthCookie(request)) {
    const loginUrl = `${url.origin}/login?redirect_uri=${encodeURIComponent(url.origin + "/top")}`;
    return Response.redirect(loginUrl, 302);
  }

  console.log(JSON.stringify({ event: "top_page" }));

  const requestOrigin = url.origin;
  const tenantId = tenantIdFromCookie(request);

  const apps = (await getDisplayOrigins(env))
    .split(",")
    .map((s: string) => s.trim())
    .filter(
      (s: string) =>
        s && s !== env.AUTH_WORKER_ORIGIN && !s.includes("auth-worker") && !s.includes("auth."),
    )
    .map(originToApp);

  // Deduplicate by app name (ippoan.org URLs come first, so they take priority)
  const seen = new Set<string>();
  const uniqueApps = apps.filter((app) => {
    if (seen.has(app.name)) return false;
    seen.add(app.name);
    return true;
  });

  // Drop ohishi-exp tiles unless the cookie JWT's tenant_id is in TENANT_ACL.
  const visibleApps: AppEntry[] = [];
  for (const app of uniqueApps) {
    const org = await classifyOrigin(env, app.url);
    if (org === "ohishi-exp" && !isTenantInOrgAllowlist(env, "ohishi-exp", tenantId)) {
      continue;
    }
    visibleApps.push(app);
  }

  const html = renderTopPage(visibleApps, requestOrigin, {
    workerEnv: env.WORKER_ENV,
    alcApiOrigin: env.ALC_API_ORIGIN,
    tenantId,
  });
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
