/**
 * rust-alc-api の `/api/internal/*` を叩くための短命 HS256 JWT を発行する。
 *
 * rust-alc-api 側 `crates/alc-core/src/auth_jwt.rs::verify_internal_token` と
 * `crates/alc-core/src/auth_middleware.rs::require_internal_jwt` で検証される。
 * 必須クレーム: `aud="alc-api-internal"` (これにより通常ユーザー JWT との混入を防止)、
 * `iss`, `iat`, `exp`。署名は `JWT_SECRET` (Workers Secret、rust-alc-api と共有) で行う。
 */

import { base64Encode } from "./lineworks-crypto";

const TEXT_ENCODER = new TextEncoder();
const INTERNAL_AUD = "alc-api-internal";
const ISSUER = "auth-worker";

interface InternalEnv {
  JWT_SECRET: string;
}

/**
 * 短命 (デフォルト 60s) の internal JWT を発行する。
 * 同じ `env` を複数回呼んでもキャッシュしないので、必要なら呼び出し側でキャッシュする。
 */
export async function signInternalJWT(
  env: InternalEnv,
  ttlSeconds = 60,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: ISSUER,
    aud: INTERNAL_AUD,
    iat: now,
    exp: now + ttlSeconds,
  };
  return signHs256(claims, env.JWT_SECRET);
}

async function signHs256(
  payload: Record<string, unknown>,
  secret: string,
): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const headerSegment = base64UrlEncodeJson(header);
  const payloadSegment = base64UrlEncodeJson(payload);
  const signingInput = `${headerSegment}.${payloadSegment}`;

  const key = await crypto.subtle.importKey(
    "raw",
    TEXT_ENCODER.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, TEXT_ENCODER.encode(signingInput));
  const sigSegment = base64UrlEncode(new Uint8Array(sig));
  return `${signingInput}.${sigSegment}`;
}

function base64UrlEncodeJson(obj: unknown): string {
  return base64UrlEncode(TEXT_ENCODER.encode(JSON.stringify(obj)));
}

function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
