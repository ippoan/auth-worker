/**
 * MCP relay WebSocket upgrade handler (issue #117 / Phase 6 + ADR-003 user-less variant
 * + issue #144 1-click pair token acceptance)。
 *
 * Two callsites in `src/index.ts:dispatchMcpRelay`:
 *
 * - `GET /u/<github_login>/connect` — back-compat for `github-mcp-server-rs`,
 *   `user` arg is the captured path segment.
 * - `GET /connect` — ADR-003 user-less endpoint for a binary that does not
 *   want to pin its github_login in URL config. `user` is `null`; DO id is
 *   derived from `verifyMcpJwt(jwt).github_login`.
 *
 * 認証モデル: binary は 2 通りの Bearer credential を提示できる:
 *
 *   1. MCP access JWT (aud=`github-mcp-server-rs`, Phase 3 device-flow / Phase 5
 *      auth-code で取得した token)。従来 path。
 *   2. **pair_code** (issue #144) — `POST /mcp/pair/new` で発行された短期 code。
 *      JWT 検証に失敗した時に fallback で KV `mcp/pair/<code>` を引き、
 *      `status === "approved"` であれば内部的に `binding_jwt` に置換して
 *      DO に forward する。`status === "pending"` なら 401 + `Pair-Status: pending`
 *      header を返す (binary 側 2s 間隔 retry の signal)。pair_code 使用後は
 *      1 回限りで KV から削除する (再利用防止)。
 */

import type { Env } from "../index";
import { getLiteralAudAllowlist } from "../lib/mcp-aud";
import { resolveMcpJwtSecret, verifyMcpJwt } from "../lib/mcp-jwt";
import { wwwAuthenticateValue } from "../lib/mcp-origins";
import {
  PAIR_REFRESH_TTL_SEC,
  deletePair,
  getPair,
} from "../lib/mcp-pair";

/** issue #144: pair_code の base64url 文字 + 長さ。誤って JWT を pair_code として
 *  扱わないために、形を狭く絞る (JWT は dot を含むのでまず除外できる)。 */
const PAIR_CODE_REGEX = /^[A-Za-z0-9_-]{30,60}$/;

function unauthorizedResponse(env: Env, body: string): Response {
  return new Response(body, {
    status: 401,
    headers: { "WWW-Authenticate": wwwAuthenticateValue(env) },
  });
}

function pendingPairResponse(): Response {
  // pair_code はまだ approve されていないので binary に「2s 後 retry」を伝える。
  // WWW-Authenticate は付けない: device-flow の 401 と区別させ、binary 側で
  // re-auth flow にフォールバックさせないため (pair-only signal)。
  return new Response("Pair pending", {
    status: 401,
    headers: { "Pair-Status": "pending" },
  });
}

interface ResolvedAuth {
  /** DO に forward する際の `Authorization: Bearer ...` の中身。 */
  forward_token: string;
  /** DO id 解決に使う github_login (user-less mode 用)。 */
  github_login: string;
  /** WS upgrade 成功後に消す pair_code (JWT path では undefined)。 */
  pair_code_to_invalidate?: string;
  /** issue #157: 101 response の `Pair-Refresh-Token` header に乗せる
   *  30 日 opaque token。pair_code 経路で approve 時に mint された場合のみ存在。
   *  JWT path や pre-#157 record (refresh_token 未 mint) では undefined。 */
  refresh_token?: string;
}

/**
 * Bearer token を JWT として verify する。失敗したら pair_code として KV を引く。
 * 戻り値:
 *  - `{ kind: "ok", auth }` 認証成功 (JWT or approved pair)
 *  - `{ kind: "pending" }` pair_code は存在するが status=pending
 *  - `{ kind: "unauthorized" }` どちらでもない (= 認証失敗)
 */
async function resolveAuth(
  token: string,
  env: Env,
  jwtSecret: string,
): Promise<
  | { kind: "ok"; auth: ResolvedAuth }
  | { kind: "pending" }
  | { kind: "unauthorized" }
> {
  // ── 1. JWT path ──
  // JWT は dot を 2 つ含む。pair_code (base64url、dot 無し) と完全に
  // disjoint なので、形だけ見て先に分岐する。
  if (token.includes(".")) {
    const payload = await verifyMcpJwt(
      token,
      jwtSecret,
      getLiteralAudAllowlist(env),
    );
    // relay は GitHub 由来の binary session 専用。Google IdP 追加 (issue) で
    // McpJwtPayload.github_login が optional 化されたため、Google flow の JWT
    // (github_login 無し) を明示的に弾く (mcp-relay-bridge.ts と同じ defense-in-depth)。
    if (payload && payload.github_login) {
      return {
        kind: "ok",
        auth: { forward_token: token, github_login: payload.github_login },
      };
    }
    return { kind: "unauthorized" };
  }

  // ── 2. pair_code path ──
  if (!PAIR_CODE_REGEX.test(token)) return { kind: "unauthorized" };
  const rec = await getPair(env, token);
  if (!rec) return { kind: "unauthorized" };
  if (rec.status === "pending") return { kind: "pending" };
  // status="approved": binding_jwt は必須 (approvePair が必ず set する)。
  if (!rec.binding_jwt) return { kind: "unauthorized" };
  return {
    kind: "ok",
    auth: {
      forward_token: rec.binding_jwt,
      github_login: rec.claim_login,
      pair_code_to_invalidate: token,
      refresh_token: rec.refresh_token,
    },
  };
}

export async function handleMcpRelayConnect(
  request: Request,
  env: Env,
  user: string | null,
): Promise<Response> {
  const jwtSecret = await resolveMcpJwtSecret(env.MCP_JWT_SECRET);
  if (!jwtSecret) {
    return new Response("MCP not configured", { status: 503 });
  }
  if (request.headers.get("Upgrade") !== "websocket") {
    return new Response("Expected websocket", { status: 426 });
  }
  if (!env.MCP_SESSION_DO) {
    return new Response("MCP relay not configured", { status: 503 });
  }
  if (user === "") {
    return new Response("Missing user", { status: 400 });
  }

  const authz = request.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(authz);
  if (!m || !m[1]) {
    return unauthorizedResponse(env, "Unauthorized");
  }
  const token = m[1];

  const resolved = await resolveAuth(token, env, jwtSecret);
  if (resolved.kind === "pending") return pendingPairResponse();
  if (resolved.kind === "unauthorized") {
    return unauthorizedResponse(env, "Invalid token");
  }
  const auth = resolved.auth;

  // user-scoped route だけ照合する (user-less mode = JWT/pair を origin of truth)。
  if (user !== null && auth.github_login !== user) {
    return new Response("User mismatch", { status: 403 });
  }

  // ── DO への転送。Authorization header は forward_token (binding_jwt の場合は
  //    内部 token) で書き換える。 ──
  const doKey = user ?? auth.github_login;
  const id = env.MCP_SESSION_DO.idFromName(doKey);
  const stub = env.MCP_SESSION_DO.get(id);
  const forwardHeaders = new Headers(request.headers);
  forwardHeaders.set("Authorization", `Bearer ${auth.forward_token}`);
  const doReq = new Request("https://do.invalid/__connect", {
    method: "GET",
    headers: forwardHeaders,
  });
  const res = await stub.fetch(doReq);

  // pair_code を 1 回限り消す: WS upgrade 成立 (101) でも fail (4xx/5xx) でも、
  // 一度 approve された pair_code は使い捨て (replay 防止)。失敗時の retry は
  // 新しい pair_code を取り直す前提。
  if (auth.pair_code_to_invalidate) {
    await deletePair(env, auth.pair_code_to_invalidate);
  }

  // issue #157 Phase A: WS upgrade 成立時に refresh_token を 101 response header
  // で binary に渡す。Phase B (consumer #57) で binary 側がここから読み取り、
  // 次回 container 起動時の `POST /mcp/pair/grant` 用に保存する。
  //
  // Cloudflare Response の `webSocket` プロパティは 101 を返す DO stub から
  // bubble up してくる非標準フィールド。新 Response を作る際は明示的に
  // 受け渡さないと WS upgrade が破綻するので注意 (test では polyfill で
  // status だけ持つので headers のみ確認する)。
  if (auth.refresh_token && res.status === 101) {
    const headers = new Headers(res.headers);
    headers.set("Pair-Refresh-Token", auth.refresh_token);
    headers.set("Pair-Refresh-Expires-In", String(PAIR_REFRESH_TTL_SEC));
    // `webSocket` は CF Workers 固有の非標準フィールド。常に渡しておく
    // (DO 側で undefined になることは 101 path では無いはずだが、undefined は
    // 標準 Response 構築で単に無視されるので無害)。条件分岐を入れない方が
    // coverage / 読みやすさで素直。
    const init = {
      status: res.status,
      statusText: res.statusText,
      headers,
      webSocket: (res as Response & { webSocket?: WebSocket }).webSocket,
    } as ResponseInit;
    return new Response(res.body, init);
  }

  return res;
}
