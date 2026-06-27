/**
 * admin API proxy の identity ヘッダ注入 + DEBUG ログ (Refs rust-alc-api#434)。
 *
 * #434 で rust-alc-api の admin/tenant route は `require_tenant_header` に一本化され、
 * **Bearer を検証せず、信頼できる proxy が注入した X-Tenant-ID / X-User-* ヘッダを信頼する**
 * 設計になった (rust は dumb backend)。auth-worker の admin proxy はこの trusted proxy
 * として、cookie/Bearer の JWT を `JWT_SECRET` で検証し、検証済み identity をヘッダとして
 * rust へ注入する必要がある。従来は `Authorization: Bearer` だけ転送していたため、rust が
 * `X-Tenant-ID` 欠落で 401 を返していた (admin 画面が全 API error)。
 *
 * 注入する 4 ヘッダは rust gateway `inject_auth_headers` と同じ:
 *   X-Tenant-ID / X-User-ID / X-User-Email / X-User-Role
 *
 * `env.DEBUG === "true"` のとき網羅ログ (verify 結果 / 注入 claims / rust 応答) を emit する。
 */
import type { Env } from "../index";
import { verifyJwt } from "./jwt";
import { resolveSecret } from "./secret";

/**
 * token を `JWT_SECRET` (+ WORKER_ENV) で検証し、rust admin route へ転送する
 * identity ヘッダ群を返す。検証失敗 (署名 / exp / env 不一致) は null → caller は 401。
 */
export async function buildAdminForwardHeaders(
  token: string,
  env: Env,
  event: string,
  extra?: Record<string, string>,
): Promise<Record<string, string> | null> {
  const secret = await resolveSecret(env.JWT_SECRET);
  const claims = secret ? await verifyJwt(token, secret, env.WORKER_ENV) : null;
  if (!claims) {
    if (env.DEBUG === "true") {
      console.log(
        JSON.stringify({
          debug: event,
          stage: "verify",
          ok: false,
          hasSecret: !!secret,
        }),
      );
    }
    return null;
  }
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    "X-Tenant-ID": String(claims.tenant_id ?? ""),
    "X-User-ID": String(claims.sub ?? ""),
    "X-User-Email": String(claims.email ?? ""),
    "X-User-Role": String(claims.role ?? ""),
    ...(extra ?? {}),
  };
  if (env.DEBUG === "true") {
    console.log(
      JSON.stringify({
        debug: event,
        stage: "verify",
        ok: true,
        tenant_id: claims.tenant_id,
        role: claims.role,
        env: claims.env,
        sub: claims.sub,
        injected: ["X-Tenant-ID", "X-User-ID", "X-User-Email", "X-User-Role"],
      }),
    );
  }
  return headers;
}

/** rust 応答 (status + body 先頭) を DEBUG ログに残す (失敗診断用)。 */
export function debugRustResponse(
  env: Env,
  event: string,
  status: number,
  body: string,
): void {
  if (env.DEBUG === "true") {
    console.log(
      JSON.stringify({
        debug: event,
        stage: "rust_response",
        status,
        body: body.slice(0, 300),
      }),
    );
  }
}
