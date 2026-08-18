/**
 * `GET /oidc/.well-known/jwks.json`
 *
 * Cloudflare Access 向け OIDC surface の公開鍵配布口 (RFC 7517 JWKS)。Access は
 * IdP 登録時の "Certs URL" にここを指し、受け取った `id_token` の署名を header の
 * `kid` で引いた鍵で検証する。
 *
 * **公開 endpoint (認証なし)。** JWKS は公開鍵しか含まないので秘匿する意味が無く、
 * むしろ Access 側から無認証で取得できる必要がある。私有鍵成分 `d` の除去は
 * `toPublicJwk` の 1 箇所に閉じてある (`lib/oidc-signing-key.ts`)。
 *
 * 鍵未設定 / 壊れている場合は **503** を返す (空の `keys: []` を 200 で返すと
 * Access 側は「鍵が無い IdP」ではなく「鍵が消えた」ように見えて原因が追いにくい)。
 */
import type { Env } from "../index";
import { corsJsonResponse } from "../lib/errors";
import { buildJwks, resolveOidcSigningKeys } from "../lib/oidc-signing-key";

export async function handleOidcJwks(_request: Request, env: Env): Promise<Response> {
  const keys = await resolveOidcSigningKeys(env.ACCESS_OIDC_SIGNING_KEY);
  if (!keys) {
    return corsJsonResponse(
      { error: "server_error", error_description: "signing key not configured" },
      503,
    );
  }
  const res = corsJsonResponse(await buildJwks(keys));
  // 鍵はローテーション時にしか変わらない。Access は起動時と定期に取りに来るので
  // edge cache を許可する。ローテーションは「新鍵を先頭に足す→旧鍵を消す」の
  // 2 段なので、この TTL の間 旧 JWKS が残っても検証は通る (両方載っているため)。
  res.headers.set("Cache-Control", "public, max-age=3600");
  return res;
}
