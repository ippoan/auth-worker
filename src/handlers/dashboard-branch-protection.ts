/**
 * `GET /dashboard/branch-protection` (issue #159 Phase 1).
 *
 * Auth flow:
 *   1. `mcp_pair_session` cookie verify → github_login。無効 / 不在 → /mcp/elevate に redirect
 *      (return_to=本ページ URL)。
 *   2. `elevate:<login>` KV flag 確認 (15 min admin window)。無 → /mcp/elevate に redirect。
 *
 * `/mcp/elevate_callback` は session cookie + elevate flag の両方を立てるので、
 * 「一度 elevate を踏めばダッシュボード操作が始められる」状態になる。
 *
 * CSRF: API endpoint (`/api/dashboard/repos*`) は `X-CSRF` header を要求する。
 * その値はこのページの inline script に焼き込み、HMAC(`SESSION_COOKIE_SECRET`,
 * `csrf|<login>|<iat>`) で生成する (同一 origin なので XSS が無ければ
 * 第三者 origin から fetch できないが、もう一段防御として導入)。
 */

import type { Env } from "../index";
import { jsonResponse } from "../lib/errors";
import { renderBranchProtectionPage } from "../lib/dashboard-branch-protection-html";
import {
  readPairSessionCookie,
  verifyPairSession,
} from "../lib/mcp-session";

const DASHBOARD_PATH = "/dashboard/branch-protection";

interface ElevateFlag {
  elevated_at: number;
  expires_at: number;
}

function htmlResponse(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function elevateRedirectUrl(env: Env): string {
  const returnTo = encodeURIComponent(`${env.AUTH_WORKER_ORIGIN}${DASHBOARD_PATH}`);
  return `${env.AUTH_WORKER_ORIGIN}/mcp/elevate?return_to=${returnTo}`;
}

async function isElevated(env: Env, login: string): Promise<boolean> {
  if (!env.MCP_OAUTH_KV) return false;
  const raw = await env.MCP_OAUTH_KV.get(`elevate:${login}`);
  if (!raw) return false;
  try {
    const flag = JSON.parse(raw) as ElevateFlag;
    return (
      typeof flag.expires_at === "number" &&
      flag.expires_at > Math.floor(Date.now() / 1000)
    );
  } catch {
    return false;
  }
}

async function computeCsrfToken(login: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const data = new TextEncoder().encode(`csrf|${login}`);
  const sig = await crypto.subtle.sign("HMAC", key, data);
  const bytes = new Uint8Array(sig);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] as number);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Helper shared between page handler and API handlers: returns
 * `{ login }` if both auth gates pass, otherwise an error Response.
 *
 * For HTML routes the error is a 302 redirect; for API routes the caller
 * typically discards the redirect and returns a JSON 401/403 instead.
 */
export interface DashboardAuthOk {
  ok: true;
  login: string;
}
export interface DashboardAuthFail {
  ok: false;
  status: 401 | 403 | 503;
  reason: "missing_session" | "expired_session" | "not_elevated" | "not_configured";
}

export async function authenticateDashboard(
  request: Request,
  env: Env,
): Promise<DashboardAuthOk | DashboardAuthFail> {
  if (
    !env.MCP_OAUTH_KV ||
    !env.SESSION_COOKIE_SECRET ||
    !env.AUTH_WORKER_ORIGIN
  ) {
    return { ok: false, status: 503, reason: "not_configured" };
  }
  const cookieRaw = readPairSessionCookie(request.headers.get("Cookie"));
  if (!cookieRaw) {
    return { ok: false, status: 401, reason: "missing_session" };
  }
  const session = await verifyPairSession(cookieRaw, env.SESSION_COOKIE_SECRET);
  if (!session) {
    return { ok: false, status: 401, reason: "expired_session" };
  }
  if (!(await isElevated(env, session.github_login))) {
    return { ok: false, status: 403, reason: "not_elevated" };
  }
  return { ok: true, login: session.github_login };
}

export async function handleDashboardBranchProtection(
  request: Request,
  env: Env,
): Promise<Response> {
  const auth = await authenticateDashboard(request, env);
  if (!auth.ok) {
    if (auth.status === 503) {
      return jsonResponse(
        { error: "server_error", error_description: "dashboard not configured" },
        503,
      );
    }
    return new Response(null, {
      status: 302,
      headers: {
        Location: elevateRedirectUrl(env),
        "Cache-Control": "no-store",
      },
    });
  }
  const csrf = await computeCsrfToken(auth.login, env.SESSION_COOKIE_SECRET!);
  const html = renderBranchProtectionPage({
    github_login: auth.login,
    elevate_url: elevateRedirectUrl(env),
    csrf_token: csrf,
  });
  return htmlResponse(html);
}

/**
 * Verify that the incoming API request carries an `X-CSRF` header whose value
 * matches `HMAC(SESSION_COOKIE_SECRET, "csrf|<login>")`. Returns true on
 * match. Same-origin XHR fetches inherit the cookie already; CSRF is a
 * second-line defense against a misconfigured frontend or extension proxying
 * cross-origin.
 */
export async function verifyCsrfHeader(
  request: Request,
  login: string,
  secret: string,
): Promise<boolean> {
  const header = request.headers.get("X-CSRF");
  if (!header) return false;
  const expected = await computeCsrfToken(login, secret);
  if (header.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < header.length; i++) {
    diff |= header.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

export { DASHBOARD_PATH, elevateRedirectUrl };
