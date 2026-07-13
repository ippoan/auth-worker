/**
 * Top page handler
 * Serves WOFF auth landing page with app navigation menu
 */
import type { Env } from "../index";
import { renderTopPage, type AppEntry } from "../lib/top-html";
import { getAuthCookie } from "../lib/cookies";
import { classifyOrigin, getDisplayOrigins } from "../lib/config";
import { isTenantInOrgAllowlist } from "../lib/acl";
import { verifyJwt, decodeJwtPayload, type JwtPayload } from "../lib/jwt";
import { resolveSecret } from "../lib/secret";
import { verifiedIdentityHeaders } from "../lib/identity-headers";

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

  // dangling tenant 検知: セッション JWT は有効でも、その tenant の tenants 行が
  // rust 側に無いと my-orgs が空になり、下流アプリは未認可扱い (再ログイン要求)
  // になる (2026-07-13 本番で顕在化)。0 件なら **/login ではなく /logout** へ飛ばす:
  //   - /login 直行は「同じ account → 同じ tenant_id → 同じ空 my-orgs」で
  //     自動 login ループになる (この gate が最初に踏んだバグ)。
  //   - /logout は cookie/session を破棄して /login で**止まる** (自動再認証
  //     しない) ので、ユーザーは別アカウントに切り替えられ、ループしない。
  // 判定不能 (rust 障害・claim 不足・応答形不正) は fail-open、?woff は gate 対象外。
  if (payload && cookieToken && !hasWoff) {
    const orgCount = await myOrgsCount(env, cookieToken);
    if (orgCount === 0) {
      const { tenantId } = claimsFromPayload(payload);
      console.log(JSON.stringify({ event: "top_no_org", tenantId }));
      return Response.redirect(`${url.origin}/logout`, 302);
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
