/**
 * dev-login (issue #423/#424) — MCP 発行の localhost 検証用 dev JWT。
 *
 * `logi_auth_token` (既存の session JWT、`access-token.ts` の `createAccessToken`)
 * と同形の claims (`sub`/`email`/`name`/`tenant_id`/`role`/`org_slug?`) に
 * `token_kind: "dev"` を足しただけの JWT を発行する。Rust 側 (rust-alc-api) の
 * 検証コードは無変更のまま通す設計 (auth-client 側で dev cookie →
 * `logi_auth_token` へ書き換える、issue #425 — 本ファイルのスコープ外)。
 *
 * tenant_id/role/user_id の解決は、MCP Google IdP callback
 * (`mcp-auth-callback-google.ts`) が `google_sub:<email>` として cache した値を
 * 使って既存の `upsertGoogleUser` を呼ぶ。rust-alc-api 側は google_sub が
 * 一致する既存ユーザーには name/email を書き換えない (新規作成時のみ使う) ので、
 * 既にテナントに属している開発者アカウントに対しては副作用ゼロの read 相当。
 */
import type { Env } from "../index";
import { upsertGoogleUser } from "./alc-internal";
import { signJwt } from "./jwt";
import type { McpJwtPayload } from "./mcp-jwt";
import { resolveSecret } from "./secret";

/** 30分・refresh なし (issue #424 の決定事項)。 */
export const DEV_TOKEN_TTL_SEC = 1800;
/** one-shot code の TTL。Cloudflare KV `expirationTtl` の最小値 (60s) と一致。 */
export const DEV_CODE_TTL_SEC = 60;

export type MintDevTokenResult =
  | { kind: "ok"; token: string; expires_in: number }
  | { kind: "error"; error: string; status: number };

/** fail-closed allowlist parse (`GITHUB_MCP_USER_ALLOWLIST` と同方針、mcp-elevate.ts 参照)。 */
function parseAllowedSubjects(raw: string | undefined): string[] | null {
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

/**
 * MCP 認可済み `payload` (`/mcp/tools` の Bearer JWT payload) から dev JWT を
 * 発行する。
 *
 *  - `DEV_LOGIN_ALLOWED_SUBJECTS` 未設定/不正 → fail-closed (403)
 *  - `payload.sub` が allowlist に無い → 403
 *  - Google IdP flow 以外 (`payload.email` 無し) → 403 (dev-login は Google IdP 限定)
 *  - `google_sub:<email>` キャッシュ無し (MCP Google 再認可が必要) → 403
 *  - rust-alc-api にテナントが無い (`upsertGoogleUser` が null) → 403
 */
export async function mintDevToken(
  env: Env,
  payload: McpJwtPayload,
): Promise<MintDevTokenResult> {
  if (!env.MCP_OAUTH_KV) {
    return { kind: "error", error: "server_error", status: 503 };
  }
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) {
    return { kind: "error", error: "server_error", status: 503 };
  }
  const allowlist = parseAllowedSubjects(
    (await resolveSecret(env.DEV_LOGIN_ALLOWED_SUBJECTS)) ?? undefined,
  );
  if (allowlist === null) {
    return { kind: "error", error: "dev_login_not_configured", status: 403 };
  }
  if (!allowlist.includes(payload.sub)) {
    return { kind: "error", error: "not_in_allowlist", status: 403 };
  }
  if (!payload.email) {
    return { kind: "error", error: "google_login_required", status: 403 };
  }

  const googleSub = await env.MCP_OAUTH_KV.get(`google_sub:${payload.email}`);
  if (!googleSub) {
    return { kind: "error", error: "google_sub_not_cached", status: 403 };
  }

  let user;
  try {
    user = await upsertGoogleUser(env, {
      google_sub: googleSub,
      email: payload.email,
      name: payload.email,
    });
  } catch {
    return { kind: "error", error: "server_error", status: 500 };
  }
  if (!user) {
    return { kind: "error", error: "no_tenant_for_email", status: 403 };
  }

  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    sub: user.id,
    email: user.email,
    name: user.name,
    tenant_id: user.tenant_id,
    role: user.role,
    token_kind: "dev",
    iat: now,
    exp: now + DEV_TOKEN_TTL_SEC,
  };
  if (user.slug) claims.org_slug = user.slug;
  const token = await signJwt(claims, jwtSecret);
  return { kind: "ok", token, expires_in: DEV_TOKEN_TTL_SEC };
}

/** 256bit ランダム hex (64文字)。`mcp-codes.ts::generateDeviceCode` と同方式。 */
function generateDevCode(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * 発行済みの dev JWT を one-time code に束ねて KV へ保存する
 * (`http://localhost:<port>/__dev/callback?code=...` の code 部分)。
 *
 * 交換時に再ミントはしない (= `mintDevToken` を呼ばない) — この時点で既に
 * 発行済みの token をそのまま code に紐付けるだけなので、code 交換
 * (`consumeDevLoginCode`) は KV lookup のみで完結する。
 */
export async function issueDevLoginCode(env: Env, token: string): Promise<string> {
  if (!env.MCP_OAUTH_KV) throw new Error("MCP_OAUTH_KV not bound");
  const code = generateDevCode();
  await env.MCP_OAUTH_KV.put(`dev_code:${code}`, JSON.stringify({ token }), {
    expirationTtl: DEV_CODE_TTL_SEC,
  });
  return code;
}

/**
 * one-time code を消費して dev JWT を返す (get→delete、`mcp-authcode.ts::consumeAuthCode`
 * と同じ single-use idiom)。不在 / parse 失敗 → null。
 */
export async function consumeDevLoginCode(env: Env, code: string): Promise<string | null> {
  if (!env.MCP_OAUTH_KV) return null;
  const json = await env.MCP_OAUTH_KV.get(`dev_code:${code}`);
  if (!json) return null;
  await env.MCP_OAUTH_KV.delete(`dev_code:${code}`);
  try {
    const parsed = JSON.parse(json) as { token?: string };
    return typeof parsed.token === "string" ? parsed.token : null;
  } catch {
    return null;
  }
}
