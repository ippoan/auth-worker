/**
 * Top page handler
 * Serves WOFF auth landing page with app navigation menu
 */
import type { Env } from "../index";
import { renderTopPage, type AppEntry } from "../lib/top-html";
import { clearAuthCookie, getAuthCookie } from "../lib/cookies";
import { classifyOrigin, getDisplayOrigins } from "../lib/config";
import { isTenantInOrgAllowlist } from "../lib/acl";
import { verifyJwt, decodeJwtPayload, type JwtPayload } from "../lib/jwt";
import { resolveSecret } from "../lib/secret";
import { verifiedIdentityHeaders } from "../lib/identity-headers";
import { escapeHtml } from "../lib/html";

/** Known app patterns — matches both production and staging URLs */
const APP_PATTERNS: Array<{
  match: (origin: string) => boolean;
  name: string;
  icon: string;
  description: string;
}> = [
  { match: (o) => o.includes("nuxt-pwa-carins") || o.includes("carins"), name: "車検証管理", icon: "車", description: "車検証・ファイル管理" },
  // nuxt-dtako-logs (GPS トラック位置) は dtako.ippoan.org (運行管理) と別アプリ。
  // 旧 ohishi2.mtamaramu.com / 新 dtako-logs.ippoan.org のどちらの origin でも
  // 「車両位置」に分類する。"dtako-logs" は下の "dtako" パターンより前で
  // マッチさせる必要がある (= "DTako 管理" に吸われない)。配列順 = dedup priority。
  { match: (o) => o.includes("ohishi2") || o.includes("dtako-logs"), name: "車両位置", icon: "🚛", description: "GPS トラック位置" },
  { match: (o) => o.includes("dtako-admin") || o.includes("dtako"), name: "DTako 管理", icon: "DVR", description: "ドライブレコーダーログ" },
  { match: (o) => o.includes("nuxt-items") || o.includes("items"), name: "物品管理", icon: "箱", description: "組織・個人の物品管理" },
  { match: (o) => o.includes("alc-app") || (o.includes("alc") && !o.includes("alc-api")), name: "アルコールチェック", icon: "🍺", description: "アルコール検知・管理" },
  // ichibanboshi-seikyu (燃料サーチャージ請求) は一番星本体 (売上分析) と別アプリ。
  // 「一番星」より前に置いて先にマッチさせる (= "ichibanboshi" 部分一致で
  // 「一番星」に吸収され、name dedup で消えるのを防ぐ)。
  { match: (o) => o.includes("ichibanboshi-seikyu"), name: "一番星 請求", icon: "🧾", description: "燃料サーチャージ請求" },
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

function claimsFromPayload(payload: JwtPayload | null): {
  tenantId: string;
  email: string;
} {
  if (!payload) return { tenantId: "", email: "" };
  return {
    tenantId:
      (payload.tenant_id as string | undefined) ||
      (payload.org as string | undefined) ||
      "",
    email: (payload.email as string | undefined) || "",
  };
}

/**
 * rust /api/my-orgs で所属組織数を引く (api-my-orgs.ts と同じ前段 proxy 形)。
 * 判定不能 (identity claim 不足 / fetch 失敗 / 非 200 / 応答形不正) は null を
 * 返し、caller は fail-open で /top 表示を続行する — rust 障害やレスポンス変化で
 * ポータル全体を巻き添えにしない。
 */
async function myOrgsCount(env: Env, token: string): Promise<number | null> {
  try {
    const identity = await verifiedIdentityHeaders(env, token);
    if (!identity) return null;
    const resp = await fetch(`${env.ALC_API_ORIGIN}/api/my-orgs`, {
      method: "POST",
      headers: identity,
    });
    if (!resp.ok) return null;
    const data = (await resp.json()) as { organizations?: unknown };
    return Array.isArray(data.organizations) ? data.organizations.length : null;
  } catch {
    return null;
  }
}

/**
 * 再ログインしても所属組織が 0 件のままの場合の明示エラー (login → /top →
 * login の無限ループをここで断ち切る)。
 */
function noOrgErrorPage(origin: string): string {
  const o = escapeHtml(origin);
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>組織が見つかりません</title>
<style>body{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.3rem}.muted{color:#666;font-size:.9rem}a{color:#1a56db}</style></head>
<body><h1>組織が見つかりません</h1>
<p>このアカウントはどの組織にも所属していません (組織が削除されたか、まだ招待されていません)。
管理者に招待を依頼してください。</p>
<ul><li><a href="${o}/logout">ログアウトする</a></li></ul>
<p class="muted">${o}</p></body></html>`;
}

export async function handleTopPage(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  // cloudflared quick tunnel 経由では request.url が http scheme になるので
  // X-Forwarded-Proto ヘッダーを優先して public origin を再構築する。
  const forwardedProto = request.headers.get("x-forwarded-proto");
  if (forwardedProto && forwardedProto !== url.protocol.replace(":", "")) {
    url.protocol = `${forwardedProto}:`;
  }

  // Server-side auth check: verify the cookie JWT (signature + exp).
  // Skip verification for WOFF flow (?woff=1) — the page must render so the
  // WOFF SDK can run and obtain a token client-side. ?lw_callback=1 also
  // bypasses because the OAuth callback may redirect here in the same response
  // that issued Set-Cookie, before the UA persists it for the next request.
  const cookieToken = getAuthCookie(request);
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  // Refs #218: token に env claim があれば WORKER_ENV と一致を強制
  const payload = cookieToken && jwtSecret
    ? await verifyJwt(cookieToken, jwtSecret, env.WORKER_ENV)
    : null;
  const hasWoff = url.searchParams.has("woff");
  const hasLwCallback = url.searchParams.has("lw_callback");
  // 診断ログ (login ループ調査): token 本体は出さず、cookie 有無 / 検証成否 /
  // 失敗理由 (exp/env/alg) と query gate の状態だけを構造化ログに出す。
  let jwtDiag: Record<string, unknown> = {};
  if (cookieToken && !payload) {
    const raw = decodeJwtPayload(cookieToken);
    const parts = cookieToken.split(".");
    let alg: unknown;
    if (parts.length === 3) {
      try {
        alg = (JSON.parse(atob(parts[0]!.replace(/-/g, "+").replace(/_/g, "/"))) as { alg?: string }).alg;
      } catch {
        alg = "decode_err";
      }
    }
    jwtDiag = {
      jwtParts: parts.length,
      alg,
      hasJwtSecret: !!jwtSecret,
      claimExp: raw?.exp ?? null,
      nowSec: Math.floor(Date.now() / 1000),
      expired: typeof raw?.exp === "number" ? raw.exp <= Math.floor(Date.now() / 1000) : null,
      claimEnv: (raw?.env as string | undefined) ?? null,
      workerEnv: env.WORKER_ENV ?? null,
    };
  }
  console.log(
    JSON.stringify({
      event: "top_gate",
      hasCookie: !!cookieToken,
      cookieLen: cookieToken?.length ?? 0,
      payloadValid: !!payload,
      hasWoff,
      hasLwCallback,
      willRedirectToLogin: !hasWoff && !hasLwCallback && !payload,
      ...jwtDiag,
    }),
  );
  if (!hasWoff && !hasLwCallback && !payload) {
    const loginUrl = `${url.origin}/login?redirect_uri=${encodeURIComponent(url.origin + "/top")}`;
    return Response.redirect(loginUrl, 302);
  }

  // dangling tenant 検知: セッション JWT が有効でも、その tenant の tenants 行が
  // rust 側に無いと my-orgs が空になり、下流アプリは未認可扱い (再ログイン要求)、
  // hub ingest は FK 違反 500 になる (2026-07-13 本番で顕在化)。/top の時点で
  // 検知し、cookie を破棄して再ログインさせる。ログイン直後 (?lw_callback=1) でも
  // 空のままなら、login → /top → login の無限ループを避けて明示エラーで停止する。
  // WOFF フロー (?woff=1) はページ描画が前提なので gate しない。
  if (payload && cookieToken && !hasWoff) {
    const orgCount = await myOrgsCount(env, cookieToken);
    if (orgCount === 0) {
      const { tenantId } = claimsFromPayload(payload);
      console.log(
        JSON.stringify({ event: "top_no_org", tenantId, willForceRelogin: !hasLwCallback }),
      );
      if (!hasLwCallback) {
        const loginUrl = `${url.origin}/login?redirect_uri=${encodeURIComponent(url.origin + "/top")}`;
        return new Response(null, {
          status: 302,
          headers: {
            Location: loginUrl,
            "Set-Cookie": clearAuthCookie(url.hostname),
          },
        });
      }
      return new Response(noOrgErrorPage(url.origin), {
        status: 403,
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      });
    }
  }

  console.log(JSON.stringify({ event: "top_page" }));

  const requestOrigin = url.origin;
  const { tenantId, email } = claimsFromPayload(payload);

  const apps = (await getDisplayOrigins(env))
    .split(",")
    .map((s: string) => s.trim())
    .filter(
      (s: string) =>
        s && s !== env.AUTH_WORKER_ORIGIN && !s.includes("auth-worker") && !s.includes("auth."),
    )
    .map(originToApp);

  // Deduplicate by app name. 同名衝突時は `.ippoan.org` の canonical URL を優先
  // (例: 車両位置 = 旧 ohishi2.mtamaramu.com と 新 dtako-logs.ippoan.org が両方
  // allowlist に居る移行期間中、リンク先を ippoan ドメインに寄せる)。
  // Map は挿入順を保持するので、初出位置 = タイル表示順は変わらない。
  const byName = new Map<string, AppEntry>();
  for (const app of apps) {
    const existing = byName.get(app.name);
    if (!existing) {
      byName.set(app.name, app);
      continue;
    }
    if (!existing.url.includes(".ippoan.org") && app.url.includes(".ippoan.org")) {
      byName.set(app.name, app); // canonical (ippoan) を優先、表示位置は維持
    }
  }
  const uniqueApps = [...byName.values()];

  // Drop ohishi-exp tiles unless the cookie JWT's tenant_id is in TENANT_ACL.
  const visibleApps: AppEntry[] = [];
  for (const app of uniqueApps) {
    const org = await classifyOrigin(env, app.url);
    if (org === "ohishi-exp" && !isTenantInOrgAllowlist(env, "ohishi-exp", tenantId, email)) {
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
