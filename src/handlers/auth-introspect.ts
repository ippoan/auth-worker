/**
 * `POST /auth/introspect`
 *
 * ブラウザ JWT (一般ユーザーの `logi_auth_token` cookie / Bearer) の検証を
 * auth-worker に集約する endpoint (issue #290)。frontend の server-proxy
 * consumer (nuxt-ichibanboshi-seikyu / trouble / items / dtako_logs / carins)
 * から呼ばれ、各 consumer が **`JWT_SECRET` (= 署名鍵) も `APP_TENANT_ACL` も
 * 持たずに** 「この token は valid か / このアプリ向けに許可されたテナントか」を
 * 判定できるようにする。
 *
 * 既存 `/mcp/introspect` (`mcp-introspect.ts`) は MCP 専用 (github_token を
 * 返す、aud は MCP relay 系) なのでそのままは使えない。ただし認証基盤
 * (`resolveAllSharedSecrets` = `INTERNAL_SHARED_SECRET*` multi-binding,
 * constant-time 比較, #189) は流用する。
 *
 * 認証:
 *   `Authorization: <INTERNAL_SHARED_SECRET>` (生の値, Bearer prefix なし)。
 *   `INTERNAL_SHARED_SECRET` で始まる全 binding と constant-time 比較し、
 *   1 つでも一致すれば通す (= consumer ごとに専用 secret を持たせられる)。
 *   `/mcp/introspect` の Bearer-JWT mode (mode 1) は **持たない** — こちらは
 *   server-to-server の shared secret 認証のみ。
 *
 * Request body (`application/json`):
 *   `{ "token": "<JWT>", "origin": "https://<app>.ippoan.org" }`
 *   - token  : 検証対象のブラウザ JWT (cookie 値 / Bearer)。
 *   - origin : 呼び出しアプリの origin。`APP_TENANT_ACL` の per-app テナント
 *              分割に使う。**必須** — 省略 / 不正だと ACL を強制できず
 *              cross-app cookie 流用 (#290 の穴 #3) を塞げないため
 *              `active:false` で fail-closed する。
 *
 * 処理:
 *   ① `JWT_SECRET` で署名検証 + exp + env claim 一致 (`verifyJwt`)。鍵は
 *      auth-worker だけが保持する。
 *   ② `checkOrgAccess` (org-level ACL) → `checkAppTenant` (per-app テナント)
 *      で origin × tenant_id を判定 (OAuth callback と同じ gate)。
 *
 * Response (RFC 7662 風):
 *   - 有効          : 200 `{ active: true, tenant_id, role, email, exp }`
 *   - 署名不正 / exp 切れ / env 不一致 / アプリ不許可テナント / origin 欠落:
 *                     200 `{ active: false }` (情報リーク回避)
 *   - 認証失敗      : 401 `{ error: "unauthorized" }`
 *   - 設定不備      : 503 `{ active: false, error: "server_error" }`
 *
 * Cache-Control: no-store。consumer 側で short-TTL cache する前提。
 */

import type { Env } from "../index";
import { checkAppTenant, checkOrgAccess } from "../lib/acl";
import { verifyJwt } from "../lib/jwt";
import { resolveSecret } from "../lib/secret";
import { resolveAllSharedSecrets } from "./mcp-introspect";

function jsonNoStore(data: unknown, status = 200): Response {
  const res = new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
  res.headers.set("Cache-Control", "no-store");
  return res;
}

/** 定数時間比較。短絡せず全文字を XOR して合算。 */
function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function handleAuthIntrospect(
  request: Request,
  env: Env,
): Promise<Response> {
  // ── env guard ────────────────────────────────────────────────────────────
  // 署名検証鍵 (JWT_SECRET) と shared secret (INTERNAL_SHARED_SECRET*) の両方が
  // 無いと endpoint は機能しない。Secrets Store binding は async resolve なので
  // ここで一度確定させる。
  const sharedSecrets = await resolveAllSharedSecrets(env);
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret || !sharedSecrets) {
    return jsonNoStore({ active: false, error: "server_error" }, 503);
  }

  // ── 認証: 生 shared secret (legacy + per-consumer multi-secret #189) ──────
  // 各候補を constant-time 比較。trailing wall-clock は鍵の本数 (1-N) を漏らす
  // が、どれが一致したかは漏らさない (運用本数が小さいので許容)。
  const authz = request.headers.get("Authorization") ?? "";
  if (!authz || !sharedSecrets.some((s) => constantTimeEquals(authz, s))) {
    return jsonNoStore({ error: "unauthorized" }, 401);
  }

  // ── 認証通過後の body 不正は RFC 7662 §2.2 に従い active:false (200) ───────
  let body: { token?: unknown; origin?: unknown };
  try {
    body = (await request.json()) as { token?: unknown; origin?: unknown };
  } catch {
    return jsonNoStore({ active: false });
  }
  const token = typeof body.token === "string" ? body.token : "";
  const originRaw = typeof body.origin === "string" ? body.origin : "";
  if (!token) {
    return jsonNoStore({ active: false });
  }

  // origin は ACL 分割に必須。省略 / 不正 → ACL を強制できないので fail-closed。
  let origin: string;
  try {
    origin = new URL(originRaw).origin;
  } catch {
    return jsonNoStore({ active: false });
  }

  // ① 署名 + exp + env claim 検証 (鍵は auth-worker だけが持つ)。
  const payload = await verifyJwt(token, jwtSecret, env.WORKER_ENV);
  if (!payload) {
    return jsonNoStore({ active: false });
  }

  const tenantId =
    (payload.tenant_id as string | undefined) ||
    (payload.org as string | undefined) ||
    "";
  const email = (payload.email as string | undefined) || "";
  const role = (payload.role as string | undefined) || "";

  // ② origin × tenant_id の ACL 判定 (OAuth callback と同じ二段 gate)。
  //    org-level が primary defense、app-level が同 org 内のテナント分割。
  if (!(await checkOrgAccess(env, origin, tenantId, email))) {
    return jsonNoStore({ active: false });
  }
  if (!checkAppTenant(env, origin, tenantId, email)) {
    return jsonNoStore({ active: false });
  }

  return jsonNoStore({
    active: true,
    tenant_id: tenantId,
    role,
    email,
    exp: payload.exp,
  });
}
