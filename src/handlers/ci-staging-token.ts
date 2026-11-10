/**
 * `POST /api/ci/staging-token` — staging の CI 用の dev token の発行口
 * (Refs ippoan/ci-dashboard#520、ippoan/alc-app#668)。
 *
 * alc-app の staging e2e は画面と同じ経路 (`/api/proxy/*` → `/alc-proxy/*` → worker) で GET を叩くが、
 * `/alc-proxy` は JWT が無いと 401 で worker に届かない。CI から非対話で JWT を取るための口。
 *
 * - **staging でだけ有効。** `WORKER_ENV === "staging"` で、`[env.staging.vars]` の `CI_TOKEN_*` が全部揃って
 *   いるときだけ動く。どれか欠けたら 404 (fail-closed)。トップレベル (本番) の `[vars]` には置かない
 * - 認証は GitHub Actions の OIDC ID token (`Authorization: Bearer`)。`lib/github-oidc.ts` で JWKS 検証・
 *   `iss` / `aud` (`CI_TOKEN_AUDIENCE`) / 時刻 / `repository_owner` (`ippoan`) /
 *   `repository` (`CI_TOKEN_ALLOWED_REPOS`、カンマ区切りの完全一致) を見る。失敗は理由を出さずに 401
 *   (理由はログにだけ出す。token の値は出さない)
 * - 発行するのは MCP の dev-login と同じ dev token (`lib/dev-login.ts` の `signDevToken`、`token_kind: "dev"`)。
 *   `/alc-proxy` が非 safe method を 403 にする read-only の仕組みにそのまま乗る。利用者は設定値の固定の
 *   テスト用の会社・ユーザー。TTL は `CI_TOKEN_TTL_SEC` (dev-login の上限 `DEV_TOKEN_TTL_SEC` より短い)
 * - 応答は `{ token, expires_at }` (`expires_at` は UNIX 秒)。CI からのサーバ間呼び出しだけなので CORS は付けない
 */
import type { Env } from "../index";
import { DEV_TOKEN_TTL_SEC, signDevToken } from "../lib/dev-login";
import { jsonResponse } from "../lib/errors";
import { GithubOidcError, verifyGithubOidcToken } from "../lib/github-oidc";
import { resolveSecret } from "../lib/secret";

export const CI_STAGING_TOKEN_PATH = "/api/ci/staging-token";
/** 発行する token の寿命 (秒)。dev-login (`DEV_TOKEN_TTL_SEC` = 1800) より短くする。 */
export const CI_TOKEN_TTL_SEC = 900;
/** `repository_owner` に要求する値。allowlist の repo もこの owner の下に限る。 */
export const CI_TOKEN_REPOSITORY_OWNER = "ippoan";

interface CiTokenConfig {
  allowedRepos: string[];
  audience: string;
  tenantId: string;
  subject: string;
  email: string;
  role: string;
}

/** 設定を読む。staging でない・どれか欠けた・allowlist が空 → null (= 口が無い)。 */
function readConfig(env: Env): CiTokenConfig | null {
  if (env.WORKER_ENV !== "staging") return null;
  const allowedRepos = (env.CI_TOKEN_ALLOWED_REPOS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.startsWith(`${CI_TOKEN_REPOSITORY_OWNER}/`));
  const audience = env.CI_TOKEN_AUDIENCE?.trim() ?? "";
  const tenantId = env.CI_TOKEN_TENANT_ID?.trim() ?? "";
  const subject = env.CI_TOKEN_SUBJECT?.trim() ?? "";
  const email = env.CI_TOKEN_EMAIL?.trim() ?? "";
  const role = env.CI_TOKEN_ROLE?.trim() ?? "";
  if (allowedRepos.length === 0 || !audience || !tenantId || !subject || !email || !role) return null;
  return { allowedRepos, audience, tenantId, subject, email, role };
}

function bearer(request: Request): string {
  const h = request.headers.get("Authorization") ?? "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
}

function unauthorized(reason: string): Response {
  console.warn(JSON.stringify({ msg: "ci-staging-token-rejected", reason }));
  return jsonResponse({ error: "unauthorized" }, 401);
}

export async function handleCiStagingToken(request: Request, env: Env): Promise<Response> {
  const config = readConfig(env);
  if (!config) return jsonResponse({ error: "not_found" }, 404);
  if (request.method !== "POST") return jsonResponse({ error: "method_not_allowed" }, 405);

  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) return jsonResponse({ error: "server_error" }, 503);

  const oidcToken = bearer(request);
  if (!oidcToken) return unauthorized("missing_bearer");

  let claims;
  try {
    claims = await verifyGithubOidcToken(oidcToken, {
      audience: config.audience,
      allowedRepositories: config.allowedRepos,
      repositoryOwner: CI_TOKEN_REPOSITORY_OWNER,
    });
  } catch (e) {
    return unauthorized(e instanceof GithubOidcError ? e.reason : "verify_error");
  }

  const ttl = Math.min(CI_TOKEN_TTL_SEC, DEV_TOKEN_TTL_SEC);
  const { token, exp: expiresAt } = await signDevToken(
    jwtSecret,
    {
      id: config.subject,
      email: config.email,
      name: `CI ${claims.repository}`,
      tenant_id: config.tenantId,
      role: config.role,
    },
    ttl,
  );
  console.log(
    JSON.stringify({
      msg: "ci-staging-token-issued",
      repository: claims.repository,
      run_id: claims.run_id,
      ref: claims.ref,
      exp: expiresAt,
    }),
  );
  return new Response(JSON.stringify({ token, expires_at: expiresAt }), {
    status: 200,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}
