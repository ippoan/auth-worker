/**
 * `GET /mcp/device_callback?code=...&state=...`
 *
 * RFC 8628 device flow の GitHub OAuth callback。Phase 2 で `/device/proceed` が
 * approve → GitHub OAuth に飛ばす際、state HMAC に `{ device_code, provider: "github_mcp" }`
 * を埋め込んでいる。本 handler はそれを取り出し、以下を実行する:
 *
 *   1. state 検証 (verifyOAuthState で signature + provider + device_code 確認)
 *   2. GitHub `/login/oauth/access_token` で code → github_token 交換
 *   3. GitHub `/user` で `login` 取得
 *   4. `GITHUB_MCP_USER_ALLOWLIST` (JSON array) に含まれるか — missing/malformed → deny all (fail-closed)
 *   5. allow: KV `device_code:*` を status=approved + github_login + authorized_at に更新
 *            + `github_token:{sub}` を AES-256-GCM 暗号化して保管 (Phase 5 introspect 用、30d TTL)
 *      deny:  setDeviceCodeStatus(denied) — polling 側に access_denied を即返せるように
 *   6. ユーザーには「認証完了、ターミナルに戻ってください」HTML を表示
 *
 * Phase 3 の token endpoint (`/mcp/token`) はこの KV 状態を見て JWT を発行する。
 */

import type { Env } from "../index";
import { renderDeviceResultPage } from "../lib/mcp-device-html";
import { encryptWithKey } from "../lib/mcp-crypto";
import { resolveMcpJwtSecret } from "../lib/mcp-jwt";
import {
  setDeviceCodeStatus,
  setDeviceCodeStatusApproved,
} from "../lib/mcp-kv";
import { resolveSecret } from "../lib/secret";
import { verifyOAuthState } from "../lib/security";

/** github_token は refresh 寿命 (30 日) と同じ TTL で KV に保管。Phase 5 introspect が使う。 */
const GITHUB_TOKEN_TTL_SEC = 60 * 60 * 24 * 30;

function htmlResponse(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

/** ACL parse は fail-closed: JSON 不正 / 非 array / 文字列以外混在 → 空配列 (= deny all) */
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

export async function handleMcpDeviceCallback(
  request: Request,
  env: Env,
): Promise<Response> {
  const issuer = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";

  // ── env guard ────────────────────────────────────────────────────────────
  const jwtSecret = await resolveMcpJwtSecret(env.MCP_JWT_SECRET);
  const githubClientId = await resolveSecret(env.GITHUB_MCP_CLIENT_ID);
  const githubClientSecret = await resolveSecret(env.GITHUB_MCP_CLIENT_SECRET);
  if (
    !env.MCP_OAUTH_KV ||
    !githubClientId ||
    !githubClientSecret ||
    !jwtSecret ||
    !env.SSO_ENCRYPTION_KEY ||
    !env.OAUTH_STATE_SECRET
  ) {
    return htmlResponse(
      renderDeviceResultPage({
        title: "Service unavailable",
        message: "MCP OAuth Provider is not configured.",
        level: "error",
        issuer,
      }),
      503,
    );
  }

  const url = new URL(request.url);
  if (url.searchParams.get("error")) {
    return htmlResponse(
      renderDeviceResultPage({
        title: "Authorization denied",
        message: "GitHub authorization was cancelled or denied.",
        level: "error",
        issuer,
      }),
      400,
    );
  }

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) {
    return htmlResponse(
      renderDeviceResultPage({
        title: "Invalid request",
        message: "Missing code or state.",
        level: "error",
        issuer,
      }),
      400,
    );
  }

  // ── state 検証 (device_code を取り出す) ─────────────────────────────────
  const decoded = await verifyOAuthState(state, env.OAUTH_STATE_SECRET);
  if (!decoded || decoded.provider !== "github_mcp" || !decoded.device_code) {
    return htmlResponse(
      renderDeviceResultPage({
        title: "Invalid state",
        message: "State could not be verified or did not contain a device_code.",
        level: "error",
        issuer,
      }),
      400,
    );
  }
  const deviceCode = decoded.device_code;

  // ── GitHub token exchange ──────────────────────────────────────────────
  const callbackUri = `${issuer}/mcp/device_callback`;
  let ghToken: string;
  try {
    const ghResp = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "auth-worker-mcp-oauth",
      },
      body: new URLSearchParams({
        client_id: githubClientId,
        client_secret: githubClientSecret,
        code,
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
    await setDeviceCodeStatus(env, deviceCode, "denied");
    return htmlResponse(
      renderDeviceResultPage({
        title: "GitHub error",
        message: "Failed to exchange authorization code with GitHub.",
        level: "error",
        issuer,
      }),
      502,
    );
  }

  // ── GitHub user fetch ──────────────────────────────────────────────────
  let login: string;
  try {
    const userResp = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${ghToken}`,
        "User-Agent": "auth-worker-mcp-oauth",
        Accept: "application/vnd.github+json",
      },
    });
    if (!userResp.ok) throw new Error(`user status ${userResp.status}`);
    const user = (await userResp.json()) as { login?: string };
    if (!user.login) throw new Error("login missing");
    login = user.login;
  } catch {
    await setDeviceCodeStatus(env, deviceCode, "denied");
    return htmlResponse(
      renderDeviceResultPage({
        title: "GitHub error",
        message: "Failed to fetch GitHub user information.",
        level: "error",
        issuer,
      }),
      502,
    );
  }

  // ── ACL check (fail-closed) ────────────────────────────────────────────
  const allowlist = parseAllowlist(
    (await resolveSecret(env.GITHUB_MCP_USER_ALLOWLIST)) ?? undefined,
  );
  if (!allowlist.includes(login)) {
    await setDeviceCodeStatus(env, deviceCode, "denied");
    return htmlResponse(
      renderDeviceResultPage({
        title: "Access denied",
        message: "Your GitHub account is not authorized to use this MCP server.",
        level: "error",
        issuer,
      }),
      403,
    );
  }

  // ── success: KV 状態更新 + github_token 暗号化保管 ─────────────────────
  const sub = `github:${login}`;
  const encrypted = await encryptWithKey(ghToken, env.SSO_ENCRYPTION_KEY);
  await env.MCP_OAUTH_KV.put(`github_token:${sub}`, encrypted, {
    expirationTtl: GITHUB_TOKEN_TTL_SEC,
  });
  await setDeviceCodeStatusApproved(env, deviceCode, login);

  return htmlResponse(
    renderDeviceResultPage({
      title: "認証完了",
      message: "ターミナルに戻ってください。",
      level: "success",
      issuer,
    }),
  );
}
