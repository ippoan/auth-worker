/**
 * headless device pairing エンドポイント (Phase 2.5 / ohishi-exp/smb-watch#1)。
 *
 *   POST /device/pair/start    — box (非 browser) が pairing を開始。device_code (秘密) +
 *                                user_code (短い) + verification URL を得て端末に表示する。
 *   GET  /device/pair/approve  — operator がスマホ等のブラウザで開く承認ページ。
 *                                logi_auth_token cookie の session で tenant を確定し、
 *                                未ログインなら /login に飛ばす。?user_code= を pre-fill。
 *   POST /device/pair/approve  — 承認フォーム送信。session の tenant で approvePairing。
 *   POST /device/pair/token    — box が device_code で poll。approved なら credential を
 *                                1 回だけ返す (Google 不要・無人)。
 *
 * device_code は秘密 (box 保持)、user_code は人間が承認 UI で扱う短い符号。状態は
 * lib/device-pair.ts が AUTH_CONFIG KV に短命 (既定 10 分) で保持する。
 */

import type { Env } from "../index";
import { resolveSecret } from "../lib/secret";
import { verifyJwt } from "../lib/jwt";
import { getAuthCookie } from "../lib/cookies";
import { escapeHtml } from "../lib/html";
import {
  startPairing,
  getPairingByUserCode,
  approvePairing,
  redeemPairing,
} from "../lib/device-pair";

function jsonNoStore(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function htmlNoStore(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function issuerOf(env: Env): string {
  return env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
}

interface OperatorSession {
  tenantId: string;
  email: string;
}

/** cookie (logi_auth_token) の session JWT から operator の tenant/email を返す。不正なら null。 */
async function cookieSession(request: Request, env: Env): Promise<OperatorSession | null> {
  const token = getAuthCookie(request);
  if (!token) return null;
  const secret = await resolveSecret(env.JWT_SECRET);
  if (!secret) return null;
  const payload = await verifyJwt(token, secret, env.WORKER_ENV);
  if (!payload) return null;
  const tenantId =
    (payload.tenant_id as string | undefined) || (payload.org as string | undefined) || "";
  if (!tenantId) return null;
  return { tenantId, email: (payload.email as string | undefined) || "" };
}

async function readJsonBody(request: Request): Promise<Record<string, unknown>> {
  try {
    const v = await request.json();
    return v && typeof v === "object" ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function checkOrigin(request: Request, expected: string): boolean {
  return request.headers.get("Origin") === expected;
}

const USER_CODE_RE = /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/;

function normalizeUserCode(raw: string): string {
  return raw.trim().toUpperCase();
}

/** POST /device/pair/start — box が pairing を開始する (認証不要)。 */
export async function handleDevicePairStart(request: Request, env: Env): Promise<Response> {
  const body = await readJsonBody(request);
  const label = typeof body.label === "string" ? body.label : "";

  const now = Math.floor(Date.now() / 1000);
  const p = await startPairing(env, label, now);

  const issuer = issuerOf(env);
  const verificationUri = `${issuer}/device/pair/approve`;
  return jsonNoStore(
    {
      device_code: p.device_code,
      user_code: p.user_code,
      verification_uri: verificationUri,
      verification_uri_complete: `${verificationUri}?user_code=${encodeURIComponent(p.user_code)}`,
      expires_in: p.expires_in,
      interval: p.interval,
    },
    201,
  );
}

function resultPage(issuer: string, title: string, message: string): string {
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.3rem}.muted{color:#666;font-size:.9rem}</style></head>
<body><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>
<p class="muted">${escapeHtml(issuer)}</p></body></html>`;
}

function approveForm(issuer: string, userCode: string, label: string, email: string): string {
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>デバイスを承認</title>
<style>body{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.3rem}code{background:#f2f2f2;padding:.15rem .4rem;border-radius:.25rem;font-size:1.1rem}
button{font-size:1rem;padding:.6rem 1.2rem;border-radius:.4rem;border:0;cursor:pointer}
.approve{background:#1a7f37;color:#fff}.deny{background:#eee;color:#333;margin-left:.5rem}
.muted{color:#666;font-size:.9rem}dl{line-height:1.8}</style></head>
<body><h1>デバイスを承認しますか？</h1>
<dl>
<dt class="muted">確認コード</dt><dd><code>${escapeHtml(userCode)}</code></dd>
<dt class="muted">デバイス名</dt><dd>${escapeHtml(label)}</dd>
<dt class="muted">承認者</dt><dd>${escapeHtml(email || "(unknown)")}</dd>
</dl>
<p class="muted">承認すると、このデバイスはあなたのテナントにアップロードできるようになります。
端末に表示されているコードと上のコードが一致することを確認してください。</p>
<form method="post" action="${escapeHtml(issuer)}/device/pair/approve">
<input type="hidden" name="user_code" value="${escapeHtml(userCode)}">
<button class="approve" type="submit" name="action" value="approve">承認する</button>
<button class="deny" type="submit" name="action" value="deny">拒否</button>
</form></body></html>`;
}

/** GET /device/pair/approve — operator 向け承認ページ。未ログインなら /login へ。 */
export async function handleDevicePairApprovePage(request: Request, env: Env): Promise<Response> {
  const issuer = issuerOf(env);
  const url = new URL(request.url);
  const rawCode = url.searchParams.get("user_code") ?? "";

  const session = await cookieSession(request, env);
  if (!session) {
    const back = `${issuer}/device/pair/approve${url.search}`;
    return Response.redirect(`${issuer}/login?redirect_uri=${encodeURIComponent(back)}`, 302);
  }

  const userCode = normalizeUserCode(rawCode);
  if (!USER_CODE_RE.test(userCode)) {
    return htmlNoStore(
      resultPage(issuer, "コードが不正です", "確認コードの形式が正しくありません。端末に表示されたコードを確認してください。"),
      400,
    );
  }

  const now = Math.floor(Date.now() / 1000);
  const state = await getPairingByUserCode(env, userCode, now);
  if (!state) {
    return htmlNoStore(
      resultPage(issuer, "コードが見つかりません", "確認コードが見つからないか、有効期限が切れています。端末でやり直してください。"),
      404,
    );
  }
  if (state.status !== "pending") {
    return htmlNoStore(
      resultPage(issuer, "処理済みです", "この確認コードはすでに処理されています。"),
      409,
    );
  }

  return htmlNoStore(approveForm(issuer, userCode, state.label, session.email));
}

/** POST /device/pair/approve — 承認フォーム送信を処理する。 */
export async function handleDevicePairApprove(request: Request, env: Env): Promise<Response> {
  const issuer = issuerOf(env);

  const session = await cookieSession(request, env);
  if (!session) {
    return htmlNoStore(resultPage(issuer, "未ログイン", "セッションが切れています。最初からやり直してください。"), 401);
  }
  if (!checkOrigin(request, issuer)) {
    return htmlNoStore(resultPage(issuer, "リクエスト拒否", "Origin が一致しません。"), 403);
  }

  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return htmlNoStore(resultPage(issuer, "不正なリクエスト", "フォーム形式の本文が必要です。"), 400);
  }

  const userCode = normalizeUserCode((form.get("user_code") as string | null) ?? "");
  if (!USER_CODE_RE.test(userCode)) {
    return htmlNoStore(resultPage(issuer, "コードが不正です", "確認コードの形式が正しくありません。"), 400);
  }

  const action = ((form.get("action") as string | null) ?? "").toLowerCase();
  if (action === "deny") {
    return htmlNoStore(resultPage(issuer, "拒否しました", "デバイスを承認しませんでした。このウィンドウを閉じてかまいません。"));
  }
  if (action !== "approve") {
    return htmlNoStore(resultPage(issuer, "不正な操作", "approve または deny を指定してください。"), 400);
  }

  const now = Math.floor(Date.now() / 1000);
  const result = await approvePairing(env, userCode, session.tenantId, now);
  switch (result) {
    case "approved":
      return htmlNoStore(
        resultPage(issuer, "承認しました", "デバイスを承認しました。端末側が自動で設定を受け取ります。このウィンドウを閉じてかまいません。"),
      );
    case "not_found":
      return htmlNoStore(resultPage(issuer, "コードが見つかりません", "確認コードが見つからないか、有効期限が切れています。"), 404);
    case "expired":
      return htmlNoStore(resultPage(issuer, "期限切れ", "確認コードの有効期限が切れています。端末でやり直してください。"), 410);
    case "already":
      return htmlNoStore(resultPage(issuer, "処理済みです", "この確認コードはすでに処理されています。"), 409);
  }
}

/** POST /device/pair/token — box が device_code で poll する (認証不要)。 */
export async function handleDevicePairToken(request: Request, env: Env): Promise<Response> {
  const body = await readJsonBody(request);
  const deviceCode = typeof body.device_code === "string" ? body.device_code : "";
  if (!deviceCode) return jsonNoStore({ error: "device_code required" }, 400);

  const now = Math.floor(Date.now() / 1000);
  const r = await redeemPairing(env, deviceCode, now);
  switch (r.status) {
    case "approved":
      return jsonNoStore({
        status: "approved",
        device_id: r.credential.device_id,
        device_secret: r.credential.device_secret,
        tenant_id: r.credential.record.tenant_id,
        label: r.credential.record.label,
        note: "store device_secret now; it is not retrievable later",
      });
    case "pending":
      return jsonNoStore({ status: "pending" });
    case "consumed":
      return jsonNoStore({ status: "consumed" }, 410);
    case "expired":
      return jsonNoStore({ status: "expired" }, 410);
  }
}
