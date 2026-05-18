/**
 * `/mcp/elevate` browser-facing admin elevation flow (Phase 1 admin auth).
 *
 * Background: 既存の MCP OAuth flow は `mcp.admin` scope を発行できるが、admin
 * 操作 (branch protection 更新等) を client binary に admin-scoped GitHub token
 * として渡すと「漏洩した PAT が直接 GitHub への admin write 権限を持つ」状態に
 * なる。これを避けるため、Phase 1 では:
 *
 *   1. binary は MCP JWT のみ持つ (GitHub token は read-only)。
 *   2. admin 操作は `/mcp/admin/exec` proxy 経由で実行する。
 *   3. proxy 利用には事前に **browser で `/mcp/elevate` を踏んで** 15min の
 *      elevation flag を KV に立てておく必要がある (= human-in-the-loop)。
 *
 * `/mcp/elevate` flow:
 *   - GET /mcp/elevate?return_to=<url> → random state nonce 採番 + KV 保存 →
 *     GitHub OAuth authorize に 302
 *   - GET /mcp/elevate_callback?code&state → state verify (one-shot) → GitHub
 *     code 交換 → /user で login 取得 → MCP_ADMIN_ALLOWLIST check →
 *     `elevate:<login>` を 15min TTL で KV set → return_to に 302 (or success
 *     HTML)
 *
 * Security:
 *   - state は 32-byte random nonce + KV 保管 (HMAC-signed self-contained
 *     state ではなく KV-backed nonce にしている理由: state revocation / replay
 *     の防御を KV TTL + delete-after-read で素直に実現できるため)。
 *   - `MCP_ADMIN_ALLOWLIST` missing → fail-closed (403). `not in array` も 403。
 *   - `return_to` は `https:` URL のみ受理 (空文字は許容)。
 */

import type { Env } from "../index";
import { errorResponse, jsonResponse } from "../lib/errors";

/** Browser からの elevate 開始時に KV に保存する state entry。 */
interface ElevateState {
  return_to: string;
  created_at: number;
}

/** KV TTL — state は GitHub round-trip の間だけ有効。10 min は十分余裕。 */
const ELEVATE_STATE_TTL_SEC = 600;

/** Elevation flag TTL — admin window。15 min は user 1 task 分を想定。 */
const ELEVATE_FLAG_TTL_SEC = 900;

function htmlResponse(html: string, status = 200): Response {
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

function parseAllowlist(raw: string | undefined): string[] | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return null;
    if (!parsed.every((x) => typeof x === "string")) return null;
    return parsed as string[];
  } catch {
    return null;
  }
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function isValidReturnTo(value: string | null): boolean {
  if (!value) return true;
  try {
    const u = new URL(value);
    return u.protocol === "https:";
  } catch {
    return false;
  }
}

/** `GET /mcp/elevate?return_to=<url>` */
export async function handleMcpElevateStart(
  request: Request,
  env: Env,
): Promise<Response> {
  if (
    !env.MCP_OAUTH_KV ||
    !env.GITHUB_MCP_CLIENT_ID ||
    !env.AUTH_WORKER_ORIGIN
  ) {
    return jsonResponse(
      { error: "server_error", error_description: "MCP elevate not configured" },
      503,
    );
  }
  const url = new URL(request.url);
  const returnTo = url.searchParams.get("return_to");
  if (!isValidReturnTo(returnTo)) {
    return errorResponse(400, "invalid_return_to");
  }

  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  const state = base64UrlEncodeBytes(nonceBytes);

  const entry: ElevateState = {
    return_to: returnTo ?? "",
    created_at: Date.now(),
  };
  await env.MCP_OAUTH_KV.put(
    `elevate_state:${state}`,
    JSON.stringify(entry),
    { expirationTtl: ELEVATE_STATE_TTL_SEC },
  );

  const redirectUri = `${env.AUTH_WORKER_ORIGIN}/mcp/elevate_callback`;
  const params = new URLSearchParams({
    client_id: env.GITHUB_MCP_CLIENT_ID,
    redirect_uri: redirectUri,
    state,
    scope: "read:user",
    prompt: "consent",
    allow_signup: "false",
  });
  const target = `https://github.com/login/oauth/authorize?${params.toString()}`;
  return new Response(null, {
    status: 302,
    headers: { Location: target, "Cache-Control": "no-store" },
  });
}

/** `GET /mcp/elevate_callback?code&state` */
export async function handleMcpElevateCallback(
  request: Request,
  env: Env,
): Promise<Response> {
  if (
    !env.MCP_OAUTH_KV ||
    !env.GITHUB_MCP_CLIENT_ID ||
    !env.GITHUB_MCP_CLIENT_SECRET ||
    !env.AUTH_WORKER_ORIGIN
  ) {
    return jsonResponse(
      { error: "server_error", error_description: "MCP elevate not configured" },
      503,
    );
  }
  const url = new URL(request.url);
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");
  const ghError = url.searchParams.get("error");

  if (!state) {
    return errorResponse(400, "missing_state");
  }
  // one-shot consumption: read then delete (replay 防御)。
  const raw = await env.MCP_OAUTH_KV.get(`elevate_state:${state}`);
  if (!raw) {
    return errorResponse(400, "invalid_or_expired_state");
  }
  await env.MCP_OAUTH_KV.delete(`elevate_state:${state}`);
  let parsedState: ElevateState;
  try {
    parsedState = JSON.parse(raw) as ElevateState;
  } catch {
    return errorResponse(400, "invalid_or_expired_state");
  }
  if (ghError) {
    return errorPage(
      "Authorization denied",
      "GitHub authorization was cancelled or denied.",
      400,
    );
  }
  if (!code) {
    return errorResponse(400, "missing_code");
  }

  // GitHub token 交換
  let ghToken: string;
  try {
    const tokenResp = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "ippoan-auth-worker",
      },
      body: new URLSearchParams({
        client_id: env.GITHUB_MCP_CLIENT_ID,
        client_secret: env.GITHUB_MCP_CLIENT_SECRET,
        code,
      }),
    });
    if (!tokenResp.ok) {
      return errorResponse(400, "github_token_exchange_failed");
    }
    const body = (await tokenResp.json()) as { access_token?: string; error?: string };
    if (!body.access_token) {
      return errorResponse(400, "github_token_exchange_failed");
    }
    ghToken = body.access_token;
  } catch {
    return errorResponse(400, "github_token_exchange_failed");
  }

  // user fetch
  let login: string;
  try {
    const userResp = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${ghToken}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "ippoan-auth-worker",
      },
    });
    if (!userResp.ok) {
      return errorResponse(400, "github_user_fetch_failed");
    }
    const user = (await userResp.json()) as { login?: string };
    if (!user.login) {
      return errorResponse(400, "github_user_fetch_failed");
    }
    login = user.login;
  } catch {
    return errorResponse(400, "github_user_fetch_failed");
  }

  // ACL — fail-closed when allowlist env unset or malformed.
  const allowlist = parseAllowlist(env.MCP_ADMIN_ALLOWLIST);
  if (allowlist === null) {
    return errorResponse(403, "admin_allowlist_unset");
  }
  if (!allowlist.includes(login)) {
    return errorResponse(403, "not_in_allowlist");
  }

  const now = Math.floor(Date.now() / 1000);
  await env.MCP_OAUTH_KV.put(
    `elevate:${login}`,
    JSON.stringify({ elevated_at: now, expires_at: now + ELEVATE_FLAG_TTL_SEC }),
    { expirationTtl: ELEVATE_FLAG_TTL_SEC },
  );

  if (parsedState.return_to) {
    return new Response(null, {
      status: 302,
      headers: { Location: parsedState.return_to, "Cache-Control": "no-store" },
    });
  }
  const html = `<!doctype html><html><head><meta charset="utf-8">
<title>Admin elevation granted</title>
<style>body{font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#1f2937;}h1{color:#047857;}</style>
</head><body><h1>Admin elevation granted</h1><p>Admin elevation granted for 15 minutes. You can close this tab.</p></body></html>`;
  return htmlResponse(html, 200);
}
