/**
 * Top page handler
 * Serves WOFF auth landing page with app navigation menu
 */
import type { Env } from "../index";
import { renderTopPage, type AppEntry } from "../lib/top-html";

/** Known app patterns — matches both production and staging URLs */
const APP_PATTERNS: Array<{
  match: (origin: string) => boolean;
  name: string;
  icon: string;
  description: string;
}> = [
  { match: (o) => o.includes("nuxt-pwa-carins") || o.includes("carins"), name: "車検証管理", icon: "車", description: "車検証・ファイル管理" },
  { match: (o) => o.includes("ohishi2") || o.includes("dtako-admin"), name: "DTako 管理", icon: "DVR", description: "ドライブレコーダーログ" },
  { match: (o) => o.includes("nuxt-items") || o.includes("items."), name: "物品管理", icon: "箱", description: "組織・個人の物品管理" },
  { match: (o) => o.includes("alc-app"), name: "アルコールチェック", icon: "🍺", description: "アルコール検知・管理" },
  { match: (o) => o.includes("nuxt-ichibanboshi") || o.includes("ichibanboshi"), name: "一番星", icon: "⭐", description: "一番星管理" },
  { match: (o) => o.includes("nuxt-notify") || o.includes("notify"), name: "通知管理", icon: "📨", description: "メッセージ配信" },
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

export async function handleTopPage(
  _request: Request,
  env: Env,
): Promise<Response> {
  console.log(JSON.stringify({ event: "top_page" }));

  const apps = (env.ALLOWED_REDIRECT_ORIGINS || "")
    .split(",")
    .map((s: string) => s.trim())
    .filter(
      (s: string) =>
        s && s !== env.AUTH_WORKER_ORIGIN && !s.includes("auth."),
    )
    .map(originToApp);

  const html = renderTopPage(apps, env.AUTH_WORKER_ORIGIN);
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
