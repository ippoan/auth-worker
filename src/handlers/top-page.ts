/**
 * Top page handler
 * Serves WOFF auth landing page with app navigation menu
 */
import type { Env } from "../index";
import { renderTopPage, type AppEntry } from "../lib/top-html";

/** Map origin URL to app metadata */
function originToApp(origin: string): AppEntry {
  if (origin.includes("nuxt-pwa-carins")) {
    return {
      name: "車検証管理",
      url: origin,
      icon: "車",
      description: "車検証・ファイル管理",
    };
  }
  if (origin.includes("ohishi2")) {
    return {
      name: "DTako ログ",
      url: origin,
      icon: "DVR",
      description: "ドライブレコーダーログ",
    };
  }
  if (origin.includes("nuxt-items")) {
    return {
      name: "物品管理",
      url: origin,
      icon: "箱",
      description: "組織・個人の物品管理",
    };
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
