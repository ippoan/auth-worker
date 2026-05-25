/**
 * `GET /mcp/pair_callback?code=...&state=...` (issue #144)
 *
 * `/mcp/pair/<code>` で cookie 不在を検出した時に開始した GitHub OAuth の callback。
 * Device flow callback (`/mcp/device_callback`) / Authorization Code callback
 * (`/mcp/auth_callback`) と分離する理由は、本 endpoint **だけが auth-worker 自身の
 * session cookie を set する** ため (他の 2 つは KV 書込のみ)。
 *
 * Flow:
 *   1. state 検証 → provider="github_mcp_pair" + pair_code を取得
 *   2. GitHub `/login/oauth/access_token` で code → github_token 交換
 *   3. GitHub `/user` で `login` 取得
 *   4. ACL check (`GITHUB_MCP_USER_ALLOWLIST`)
 *   5. session cookie を sign + Set-Cookie ヘッダ付きで `/mcp/pair/<pair_code>` に 302
 *
 * cookie 値: HMAC(`<payloadB64>`, `SESSION_COOKIE_SECRET`)。30 min TTL。
 *
 * github_token の KV 保管は本 flow では行わない (binding_jwt は別途
 * `/mcp/pair/<code>` 側で mint され、binary が後で `/mcp/introspect` を叩いた時の
 * github_token は既存 device / auth code flow で焼かれたものを再利用する。
 * pair flow で初めて auth-worker に来た user はそもそも binding_jwt を使った
 * MCP tool 呼び出し時に introspect が github_token を見つけられないので、
 * `whoami` 以上の tool は失敗する。これは仕様: pair は relay 接続専用で、
 * GitHub API token は device or auth-code flow で別途取らせる方針)。
 *
 * Phase 2 (out of scope for this PR) で pair flow にも github_token 保管を入れる
 * 可能性がある。本 PR では `whoami` (token 不要) + relay 接続 / disconnect の
 * 観測まで通れば accept とする。
 */

import type { Env } from "../index";
import { jsonResponse } from "../lib/errors";
import { buildSetCookie, signPairSession } from "../lib/mcp-session";
import { resolveSecret } from "../lib/resolve-secret";
import { verifyOAuthState } from "../lib/security";

function htmlResponse(html: string, status: number): Response {
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function errorPage(title: string, message: string, status: number): Response {
  const html = `<!doctype html><html><head><meta charset="utf-8">
<title>${title}</title>
<style>body{font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#1f2937;}h1{color:#b91c1c;}</style>
</head><body><h1>${title}</h1><p>${message}</p></body></html>`;
  return htmlResponse(html, status);
}

function parseAllowlist(raw: string | undefined): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.every((x) => typeof x === "string") ? (parsed as string[]) : [];
  } catch {
    return [];
  }
}

export async function handleMcpPairCallback(
  request: Request,
  env: Env,
): Promise<Response> {
  if (
    !env.MCP_OAUTH_KV ||
    !env.GITHUB_MCP_CLIENT_ID ||
    !env.GITHUB_MCP_CLIENT_SECRET ||
    !env.OAUTH_STATE_SECRET ||
    !env.SESSION_COOKIE_SECRET ||
    !env.AUTH_WORKER_ORIGIN
  ) {
    return jsonResponse(
      { error: "server_error", error_description: "MCP OAuth Provider not configured" },
      503,
    );
  }

  const url = new URL(request.url);
  const stateRaw = url.searchParams.get("state");
  const ghCode = url.searchParams.get("code");
  const ghError = url.searchParams.get("error");

  if (!stateRaw) {
    return errorPage("Invalid request", "Missing state parameter.", 400);
  }

  const decoded = await verifyOAuthState(stateRaw, env.OAUTH_STATE_SECRET);
  if (!decoded || decoded.provider !== "github_mcp_pair" || !decoded.pair_code) {
    return errorPage("Invalid state", "State could not be verified or did not contain a pair_code.", 400);
  }
  const pair_code = decoded.pair_code;

  if (ghError) {
    return errorPage(
      "Authorization denied",
      "GitHub authorization was cancelled or denied. Close this window and re-run the binary to retry.",
      400,
    );
  }
  if (!ghCode) {
    return errorPage("Invalid request", "Missing code parameter.", 400);
  }

  // ── GitHub token exchange ──
  const issuer = env.AUTH_WORKER_ORIGIN;
  const callbackUri = `${issuer}/mcp/pair_callback`;
  const ghClientId = await resolveSecret(env.GITHUB_MCP_CLIENT_ID);
  const ghClientSecret = await resolveSecret(env.GITHUB_MCP_CLIENT_SECRET);
  if (!ghClientId || !ghClientSecret) {
    return errorPage("Server error", "GitHub OAuth credentials not resolvable.", 503);
  }
  let ghToken: string;
  try {
    const ghResp = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "auth-worker-mcp-pair",
      },
      body: new URLSearchParams({
        client_id: ghClientId,
        client_secret: ghClientSecret,
        code: ghCode,
        redirect_uri: callbackUri,
      }),
    });
    if (!ghResp.ok) throw new Error(`token exchange status ${ghResp.status}`);
    const ghBody = (await ghResp.json()) as { access_token?: string; error?: string };
    if (!ghBody.access_token) {
      throw new Error(ghBody.error ?? "no access_token in response");
    }
    ghToken = ghBody.access_token;
  } catch {
    return errorPage("GitHub error", "Failed to exchange authorization code with GitHub.", 502);
  }

  // ── GitHub user fetch ──
  let login: string;
  try {
    const userResp = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${ghToken}`,
        "User-Agent": "auth-worker-mcp-pair",
        Accept: "application/vnd.github+json",
      },
    });
    if (!userResp.ok) throw new Error(`user status ${userResp.status}`);
    const user = (await userResp.json()) as { login?: string };
    if (!user.login) throw new Error("login missing");
    login = user.login;
  } catch {
    return errorPage("GitHub error", "Failed to fetch GitHub user information.", 502);
  }

  // ── ACL (fail-closed) ──
  const allowlistRaw = await resolveSecret(env.GITHUB_MCP_USER_ALLOWLIST);
  const allowlist = parseAllowlist(allowlistRaw ?? undefined);
  if (!allowlist.includes(login)) {
    return errorPage(
      "Access denied",
      "Your GitHub account is not authorized to use this MCP server.",
      403,
    );
  }

  // ── session cookie set + redirect back to /mcp/pair/<code> ──
  const cookieValue = await signPairSession(login, env.SESSION_COOKIE_SECRET);
  const setCookie = buildSetCookie(cookieValue);
  // 302 で同じ pair URL に戻す。ブラウザは cookie 付きで再 GET し、
  // 通常の approve path を通る。
  return new Response(null, {
    status: 302,
    headers: {
      Location: `${issuer}/mcp/pair/${pair_code}`,
      "Set-Cookie": setCookie,
      "Cache-Control": "no-store",
    },
  });
}
