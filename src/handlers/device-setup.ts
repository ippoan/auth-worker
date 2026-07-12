/**
 * /device/setup — CoreS3 (alc-app-s3) の USB provisioning ページ (Refs #365)。
 *
 * Wi-Fi の Improv 設定と同じ「セットアップは USB 前提」思想:
 * operator がログイン済みブラウザで本ページを開き、WebSerial (Chrome/Edge) で
 * CoreS3 に device credential を注入する。QR/承認ページのフローは使わない
 * (operator が既にログイン済みのため)。
 *
 *   GET  /device/setup       — login-gated HTML (WebSerial JS 入り)
 *   POST /device/setup/pair  — cookie session + Origin check で credential を mint
 *                              (role は device-hub 固定。replace_label で同一
 *                              (tenant, label) の旧 credential を revoke → 再発行)
 *
 * 注入手順 (ページ JS が自動実行):
 *   1. POST /device/setup/pair → { device_id, device_secret, tenant_id }
 *   2. シリアル: AUTH SET <id> <secret> <tenant>
 *   3. シリアル: AUTH URL <このページの origin>
 *      測定記録の送り先 (WS URL) はページの origin から自動判定 —
 *      staging で開いていれば staging recorder を注入、それ以外は送らず
 *      ファームウェア既定 (prod recorder) のまま。operator には訊かない
 *   4. シリアル: AUTH TOKEN → `EVT AUTH_TOKEN OK` で疎通確認完了
 */

import type { Env } from "../index";
import { resolveSecret } from "../lib/secret";
import { verifyJwt } from "../lib/jwt";
import { getAuthCookie } from "../lib/cookies";
import { escapeHtml } from "../lib/html";
import {
  createDeviceCredential,
  createDeviceCredentialReplacingLabel,
  DEVICE_ROLE_HUB,
} from "../lib/device";

function jsonNoStore(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
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

/** GET /device/setup — WebSerial provisioning ページ (要ログイン)。 */
export async function handleDeviceSetupPage(request: Request, env: Env): Promise<Response> {
  const issuer = issuerOf(env);
  const session = await cookieSession(request, env);
  if (!session) {
    // cookie が「有るのに検証に落ちる」場合 (期限切れ・env 不一致・組織未選択で
    // tenant_id 無し) に /login へ 302 すると、ログイン済みブラウザでは
    // login → (自動) callback → 本ページ → login … の無限リダイレクトになる。
    // cookie 有りの失敗はリダイレクトせず理由を表示して止める。
    if (getAuthCookie(request)) {
      return new Response(sessionErrorPage(issuer), {
        status: 403,
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      });
    }
    const back = `${issuer}/device/setup`;
    return Response.redirect(`${issuer}/login?redirect_uri=${encodeURIComponent(back)}`, 302);
  }
  return new Response(setupPage(issuer, session.email), {
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

/** cookie はあるがセッションとして使えない場合の案内 (リダイレクトループ防止)。 */
function sessionErrorPage(issuer: string): string {
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>セッションを確認できません</title>
<style>body{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.3rem}.muted{color:#666;font-size:.9rem}a{color:#1a56db}</style></head>
<body><h1>セッションを確認できません</h1>
<p>ログインセッションが期限切れか、組織が未選択の可能性があります。</p>
<ul>
<li><a href="${escapeHtml(issuer)}/top">/top で組織を確認・選択する</a></li>
<li><a href="${escapeHtml(issuer)}/logout">一度ログアウトしてやり直す</a></li>
</ul>
<p class="muted">${escapeHtml(issuer)}</p></body></html>`;
}

/**
 * POST /device/setup/pair — operator の cookie session で device credential を発行する。
 * `/device/pair` (Bearer 限定) と違い browser から叩くため Origin を検証する (CSRF 対策)。
 * role は CoreS3 用の device-hub に固定する (本ページの用途を越えた mint をさせない)。
 */
export async function handleDeviceSetupPair(request: Request, env: Env): Promise<Response> {
  const session = await cookieSession(request, env);
  if (!session) return jsonNoStore({ error: "unauthorized" }, 401);
  if (request.headers.get("Origin") !== issuerOf(env)) {
    return jsonNoStore({ error: "bad_origin" }, 403);
  }

  let body: Record<string, unknown> = {};
  try {
    const v = await request.json();
    if (v && typeof v === "object") body = v as Record<string, unknown>;
  } catch {
    // 空 body は既定値で続行
  }
  const label = typeof body.label === "string" && body.label ? body.label : "cores3";
  const replaceLabel = body.replace_label === true;

  const now = Math.floor(Date.now() / 1000);
  const cred = replaceLabel
    ? await createDeviceCredentialReplacingLabel(env, session.tenantId, label, now, DEVICE_ROLE_HUB)
    : await createDeviceCredential(env, session.tenantId, label, now, DEVICE_ROLE_HUB);

  return jsonNoStore(
    {
      device_id: cred.device_id,
      device_secret: cred.device_secret,
      tenant_id: cred.record.tenant_id,
      label: cred.record.label,
      role: cred.record.role,
      note: "store device_secret now; it is not retrievable later",
    },
    201,
  );
}

/** セットアップページ本体。WebSerial は Chrome/Edge のみ。 */
function setupPage(issuer: string, email: string): string {
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CoreS3 デバイス登録</title>
<style>
body{font-family:system-ui,sans-serif;max-width:36rem;margin:2.5rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.3rem}
button{font-size:1rem;padding:.6rem 1.2rem;border-radius:.4rem;border:0;cursor:pointer;background:#1a7f37;color:#fff}
button:disabled{background:#9ca3af;cursor:default}
input{font-size:1rem;padding:.4rem .6rem;border:1px solid #ccc;border-radius:.4rem;width:14rem}
label{display:block;margin:.8rem 0 .3rem;color:#444;font-size:.9rem}
pre{background:#f6f8fa;border:1px solid #e2e5e9;border-radius:.4rem;padding:.8rem;font-size:.82rem;
    height:16rem;overflow-y:auto;white-space:pre-wrap}
.muted{color:#666;font-size:.85rem}
.ok{color:#1a7f37;font-weight:600}.ng{color:#b91c1c;font-weight:600}
</style></head>
<body>
<h1>CoreS3 デバイス登録 (USB)</h1>
<p class="muted">CoreS3 を USB で接続し「セットアップ実行」を押してください。まず現在の登録状態を
表示し (登録済みなら上書き確認)、credential の発行 (テナント: このアカウント
${escapeHtml(email)})、シリアル注入、疎通確認まで自動で行います。Chrome / Edge のみ (WebSerial)。</p>
<label for="label">デバイスラベル (同名は旧 credential を自動失効)</label>
<input id="label" value="cores3" pattern="[A-Za-z0-9._-]+">
<p><button id="run">セットアップ実行</button></p>
<p id="result"></p>
<pre id="log"></pre>
<script>
"use strict";
const ISSUER = ${JSON.stringify(issuer)};
const logEl = document.getElementById("log");
const resultEl = document.getElementById("result");
const runBtn = document.getElementById("run");
function log(line) {
  logEl.textContent += line + "\\n";
  logEl.scrollTop = logEl.scrollHeight;
}
// CoreS3 は ESP-IDF ログが混在するため既知プレフィックス行のみ解釈する
const KNOWN = /^(OK|ERR|AUTH|EVT|WS|STATUS|PONG|CFG)\\b/;

async function run() {
  runBtn.disabled = true;
  resultEl.textContent = "";
  try {
    if (!("serial" in navigator)) throw new Error("このブラウザは WebSerial 非対応です (Chrome/Edge を使用)");
    const port = await navigator.serial.requestPort();
    await port.open({ baudRate: 115200 });
    const writer = port.writable.getWriter();
    const reader = port.readable.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    const lines = [];
    (async () => {
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          let i;
          while ((i = buf.search(/[\\r\\n]/)) >= 0) {
            const line = buf.slice(0, i).trim();
            buf = buf.slice(i + 1);
            if (line && KNOWN.test(line)) { lines.push(line); log("<< " + line); }
          }
        }
      } catch { /* port closed */ }
    })();
    const send = async (cmd, secretParts) => {
      log(">> " + (secretParts ? cmd.split(" ").slice(0, 2).join(" ") + " …(伏せ字)" : cmd));
      await writer.write(new TextEncoder().encode(cmd + "\\n"));
    };
    const waitLine = async (re, timeoutMs) => {
      const deadline = Date.now() + timeoutMs;
      let idx = 0;
      for (;;) {
        while (idx < lines.length) {
          const line = lines[idx++];
          if (re.test(line)) return line;
          if (/^ERR\\b/.test(line)) throw new Error(line);
        }
        if (Date.now() > deadline) throw new Error("応答タイムアウト: " + re);
        await new Promise((r) => setTimeout(r, 100));
      }
    };

    // 現在の登録状態を先に表示する (既存登録の黙殺・黙って上書きをしない)
    await send("AUTH STATUS");
    const current = await waitLine(/^AUTH (PAIRED|UNPAIRED)/, 5000);
    if (/^AUTH PAIRED/.test(current)) {
      const parts = current.split(" ");
      const msg = "このデバイスは登録済みです:\\n  デバイスID: " + (parts[3] || "?") +
        "\\n  テナント: " + (parts[2] || "?") +
        "\\n\\n上書き登録しますか? (旧 credential は失効します)";
      if (!confirm(msg)) throw new Error("キャンセルしました (既存の登録を維持)");
    } else {
      log("未登録のデバイスです — 新規登録します");
    }

    const label = document.getElementById("label").value || "cores3";
    log("credential を発行中 (label=" + label + ") ...");
    const res = await fetch(ISSUER + "/device/setup/pair", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ label, replace_label: true }),
    });
    if (!res.ok) throw new Error("credential 発行に失敗: HTTP " + res.status);
    const cred = await res.json();
    log("credential 発行 OK (device_id=" + cred.device_id + ")");

    await send("AUTH SET " + cred.device_id + " " + cred.device_secret + " " + cred.tenant_id, true);
    await waitLine(/^OK AUTH SET/, 5000);
    await send("AUTH URL " + ISSUER);
    await waitLine(/^OK AUTH URL/, 5000);
    // 測定記録の送り先はページの origin から自動判定する (operator に訊かない):
    // staging で開いていれば staging recorder、それ以外は送らずデバイス既定
    // (本番 recorder) のまま
    if (location.hostname.includes("staging")) {
      await send("WS URL wss://alc-recorder-staging.m-tama-ramu.workers.dev/ws");
      await waitLine(/^OK WS URL/, 5000);
    }
    await send("AUTH TOKEN");
    const evt = await waitLine(/^EVT AUTH_TOKEN (OK|NG)/, 30000);
    if (!/^EVT AUTH_TOKEN OK/.test(evt)) throw new Error(evt);
    await send("WS STATUS");
    await waitLine(/^WS /, 5000);

    resultEl.innerHTML = '<span class="ok">登録完了 — デバイスは auth-worker と疎通済みです</span>';
    writer.releaseLock();
    await reader.cancel().catch(() => {});
    await port.close().catch(() => {});
  } catch (e) {
    resultEl.innerHTML = '<span class="ng">失敗: ' +
      String(e && e.message ? e.message : e).replace(/[<>&]/g, "") + "</span>";
  } finally {
    runBtn.disabled = false;
  }
}
runBtn.addEventListener("click", run);
</script>
<p class="muted">${escapeHtml(issuer)}</p>
</body></html>`;
}
