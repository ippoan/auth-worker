/**
 * `GET /oidc/authorize`
 *
 * Cloudflare Access が user を送り込む認可 endpoint (RFC 6749 §4.1)。
 *
 * ## この surface の存在理由 = 追加ログインをゼロにすること
 *
 * 既に `logi_auth_token` を持っている user は、**IdP へ一切飛ばさずその場で code を
 * 発行して Access に返す**。これにより Access のリダイレクトは既存セッションで無言に
 * 通り、利用者から見ると「触ったことのない別の認証系」が一切出てこない。
 * cookie が無い / 期限切れの時だけ既存の `/login` に送り、戻り先として自分自身を渡す。
 *
 * 既存 `/mcp/authorize` は常に GitHub / Google の OAuth に飛ばす作りで、目的が違う
 * (あちらは外部 IdP の identity を取りに行く / こちらは自分が持っている identity を
 * 渡す)。よって流用せず別 handler にしてある。`/mcp/*` には触っていない。
 *
 * ## Query params
 *   response_type=code / client_id / redirect_uri / state / scope / nonce
 *   code_challenge + code_challenge_method=S256 (任意、Access の PKCE 設定が on の時)
 */
import type { Env } from "../index";
import { getAuthCookies } from "../lib/cookies";
import { errorResponse } from "../lib/errors";
import { decodeJwtPayload, verifyJwt } from "../lib/jwt";
import {
  OIDC_CODE_TTL_SEC,
  generateOidcOpaqueToken,
  putOidcCode,
  type OidcIdentityClaims,
} from "../lib/oidc-authcode";
import {
  findOidcClient,
  isRegisteredRedirectUri,
  resolveOidcClients,
} from "../lib/oidc-clients";
import { OIDC_SURFACE_PATH, oidcIssuer } from "../lib/oidc-surface";
import { resolveSecret } from "../lib/secret";

/**
 * redirect_uri に error を載せて返す (RFC 6749 §4.1.2.1)。`iss` も常に載せる
 * (RFC 9207 — client が mix-up attack を検出できるように、error response にも要る)。
 */
function redirectError(
  redirectUri: string,
  error: string,
  description: string,
  state: string | null,
  iss: string,
): Response {
  const u = new URL(redirectUri);
  u.searchParams.set("error", error);
  u.searchParams.set("error_description", description);
  if (state) u.searchParams.set("state", state);
  u.searchParams.set("iss", iss);
  return Response.redirect(u.toString(), 302);
}

/**
 * `logi_auth_token` を検証して identity claims を取り出す。
 *
 * 同名 cookie が複数届く (host-only と Domain 付きが併存する、Refs #387) 場合に
 * 先頭だけ見ると有効な方が陰に隠れるため、**全候補を順に検証**して最初に通ったものを使う。
 * `env` claim も突き合わせる (cross-env replay 防止、#218)。
 */
async function identityFromSession(
  request: Request,
  env: Env,
): Promise<OidcIdentityClaims | null> {
  const secret = await resolveSecret(env.JWT_SECRET);
  if (!secret) return null;
  for (const token of getAuthCookies(request)) {
    // claim の**取り出し**は decodeJwtPayload を使う。verifyJwt の内部 decoder は
    // atob 直呼びで UTF-8 を復元できず、`name` のような多バイト claim が文字化け
    // する (decodeJwtPayload だけが UTF-8 safe)。id_token の `name` はそのまま
    // Access の管理画面や監査ログに出るので、ここで化けさせない。jwt.ts 側は
    // 既存 consumer が多数ぶら下がる共有経路なので触らない。
    //
    // 形が壊れた cookie は署名検証より前にここで落とす (crypto を回す前に弾ける)。
    const payload = decodeJwtPayload(token);
    if (!payload) continue;
    // **署名 / exp / env claim の検証は verifyJwt が唯一の正**。上の decode は
    // 検証を一切兼ねないので、この行を通らない限り payload を信用しないこと。
    if (!(await verifyJwt(token, secret, env.WORKER_ENV))) continue;
    const sub = typeof payload.sub === "string" ? payload.sub : "";
    const email = typeof payload.email === "string" ? payload.email : "";
    // sub / email が無いトークンは Access に渡しても identity にならないので通さない。
    if (!sub || !email) continue;
    const claims: OidcIdentityClaims = { sub, email };
    if (typeof payload.name === "string") claims.name = payload.name;
    if (typeof payload.tenant_id === "string") claims.tenant_id = payload.tenant_id;
    if (typeof payload.role === "string") claims.role = payload.role;
    if (typeof payload.org_slug === "string") claims.org_slug = payload.org_slug;
    return claims;
  }
  return null;
}

export async function handleOidcAuthorize(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const q = url.searchParams;
  const iss = oidcIssuer(env);

  if (!env.MCP_OAUTH_KV) {
    return errorResponse(503, "oidc surface not configured");
  }
  const clients = await resolveOidcClients(env.ACCESS_OIDC_CLIENTS);
  if (!clients) {
    return errorResponse(503, "oidc clients not configured");
  }

  // ── client_id / redirect_uri は redirect **せずに** 400 で返す (RFC 6749 §4.1.2.1)。
  //    ここで redirect すると、未検証の redirect_uri へ飛ばす open redirect になる。
  const clientId = q.get("client_id") || "";
  const client = findOidcClient(clients, clientId);
  if (!client) {
    return errorResponse(400, "unknown client_id");
  }
  const redirectUri = q.get("redirect_uri") || "";
  if (!isRegisteredRedirectUri(client, redirectUri)) {
    return errorResponse(400, "redirect_uri is not registered for this client");
  }

  // ── ここから先は検証済みの redirect_uri へ error を返せる ──
  const state = q.get("state");
  if (q.get("response_type") !== "code") {
    return redirectError(
      redirectUri,
      "unsupported_response_type",
      "only response_type=code is supported",
      state,
      iss,
    );
  }
  const codeChallenge = q.get("code_challenge");
  if (codeChallenge && q.get("code_challenge_method") !== "S256") {
    return redirectError(
      redirectUri,
      "invalid_request",
      "only code_challenge_method=S256 is supported",
      state,
      iss,
    );
  }

  // ── 既存セッションがあるか。これが「追加ログインゼロ」の分岐点 ──
  const claims = await identityFromSession(request, env);
  if (!claims) {
    // 既存の browser login に送り、戻り先として **この authorize URL をそのまま** 渡す。
    // login 完了後にここへ戻ってくると cookie が付いているので、今度は無言で code が出る。
    const origin = env.AUTH_WORKER_ORIGIN || url.origin;
    const returnTo = `${origin}${OIDC_SURFACE_PATH}/authorize${url.search}`;
    return Response.redirect(
      `${origin}/login?redirect_uri=${encodeURIComponent(returnTo)}`,
      302,
    );
  }

  const code = generateOidcOpaqueToken();
  const scope = q.get("scope") || "openid";
  await putOidcCode(env.MCP_OAUTH_KV, code, {
    client_id: client.client_id,
    redirect_uri: redirectUri,
    ...(q.get("nonce") ? { nonce: q.get("nonce")! } : {}),
    ...(codeChallenge ? { code_challenge: codeChallenge } : {}),
    scope,
    claims,
  });

  console.log(
    JSON.stringify({
      event: "oidc_authorize_granted",
      client_id: client.client_id,
      // identity そのもの (email / sub) は出さない。追跡には tenant/role で足りる。
      tenant_id: claims.tenant_id ?? null,
      role: claims.role ?? null,
      code_ttl_sec: OIDC_CODE_TTL_SEC,
    }),
  );

  const out = new URL(redirectUri);
  out.searchParams.set("code", code);
  if (state) out.searchParams.set("state", state);
  out.searchParams.set("iss", iss);
  return Response.redirect(out.toString(), 302);
}
