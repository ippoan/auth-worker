/**
 * Workers RPC entrypoint — MCP に `/mcp/google-gcp` (issue #691) で Google ログインした
 * 人の **GCP アクセストークン**を、consumer (secrets-inventory) に渡す口。
 * **service binding 越しにだけ**呼べる (`InternalEntrypoint` の冒頭コメント参照)。
 *
 * 呼び手が渡すのは、MCP client から受け取った binding_jwt だけ。auth-worker が
 * 署名・期限・aud を検証し、Google flow の JWT (`sub` が `google:`) の email に対応する
 * refresh token で短命アクセストークンを取って返す。refresh token は返さない。
 *
 * ★ **binding_jwt だけで取れる公開 HTTP の口にはしない** — そうすると binding_jwt を持つ
 *   MCP client (claude.ai 等) が、ログインした人の GCP トークンを直接取れてしまう。
 *   RPC なら、`[[services]] entrypoint = "GoogleGcpTokenEntrypoint"` を宣言した
 *   同一アカウントの worker しか呼べない。
 * ★ **他の entrypoint と別 class** — binding ごとに呼べるメソッドが閉じる (blast radius)。
 *
 * 失敗は throw せず `{status, body, contentType}` で返す (`KyuyoAuthEntrypoint` と同じ流儀)。
 *   200 `{access_token, expires_in, email}` / 401 unauthorized・reauthorize_required /
 *   503 server_error
 * アクセストークンは log に出さない。
 */
import { WorkerEntrypoint } from "cloudflare:workers";
import type { Env } from "./index";
import { audPredicate } from "./handlers/mcp-introspect";
import { alcRpcError, type AlcRpcResult } from "./lib/alc-tenant-forward";
import { exchangeGcpAccessToken } from "./lib/google-gcp-token";
import { resolveMcpJwtSecret, verifyMcpJwt } from "./lib/mcp-jwt";

export class GoogleGcpTokenEntrypoint extends WorkerEntrypoint<Env> {
  async accessToken(bindingJwt: string): Promise<AlcRpcResult> {
    const jwtSecret = await resolveMcpJwtSecret(this.env.MCP_JWT_SECRET);
    if (!jwtSecret) return alcRpcError(503, "server_error");

    const payload = await verifyMcpJwt(
      typeof bindingJwt === "string" ? bindingJwt : "",
      jwtSecret,
      audPredicate(this.env),
    );
    // GitHub flow の JWT には GCP の資格情報が無い (email も無い)
    if (!payload || !payload.sub.startsWith("google:") || !payload.email) {
      return alcRpcError(401, "unauthorized");
    }

    const email = payload.email.toLowerCase();
    const result = await exchangeGcpAccessToken(this.env, email);
    if (!result.ok) {
      return alcRpcError(result.error === "reauthorize_required" ? 401 : 503, result.error);
    }
    console.log(JSON.stringify({ event: "google_gcp_token.issued", email }));
    return {
      status: 200,
      body: JSON.stringify({ access_token: result.accessToken, expires_in: result.expiresIn, email }),
      contentType: "application/json",
    };
  }
}
