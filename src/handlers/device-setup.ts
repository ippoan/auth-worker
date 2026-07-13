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
  getDeviceRecord,
  listDeviceRecordsByTenant,
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

/**
 * OTA URL 入力欄の既定値。alc-app-s3 の CI が GitHub Pages に公開する app 単体
 * イメージ (build.yml の "Save OTA app image")。operator は必要なら書き換える。
 */
function otaDefaultUrl(_issuer: string): string {
  return "https://ippoan.github.io/alc-app-s3/firmware/alc-hub-cores3-app.bin";
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

/**
 * GET /device/setup/list — operator の tenant に登録済みの有効な CoreS3 ハブ
 * (`device-hub` role) 一覧 (ページの「登録済みデバイス」表示用)。
 *
 * **role で `device-hub` に絞る**: 本ページは CoreS3 provisioning 専用で、OTA も
 * CoreS3 firmware を push する。dtako-scraper / uploader 等の別種デバイスを混ぜて
 * 表示すると、その行の「更新」で CoreS3 firmware を誤配布する事故になる。
 * secret は KV に hash しか無いため応答に含まれない (含められない)。
 */
export async function handleDeviceSetupList(request: Request, env: Env): Promise<Response> {
  const session = await cookieSession(request, env);
  if (!session) return jsonNoStore({ error: "unauthorized" }, 401);
  const devices = (await listDeviceRecordsByTenant(env, session.tenantId))
    .filter((r) => r.role === DEVICE_ROLE_HUB)
    .map((r) => ({
      device_id: r.device_id,
      label: r.label,
      role: r.role ?? "",
      created_at: r.created_at,
    }));
  return jsonNoStore({ devices });
}

/**
 * cf-alc-recorder の内部 HTTP API を service binding 経由で叩く。
 * recorder 側は `Authorization: <INTERNAL_SHARED_SECRET>` (生値) を要求する
 * (auth-worker と同じ Secrets Store entry を共有)。binding / secret 未設定は
 * null (caller が 503)。
 */
async function recorderFetch(
  env: Env,
  path: string,
  init: RequestInit,
): Promise<Response | null> {
  // await を跨ぐと env.ALC_RECORDER の narrowing が失われるためローカルに束ねる
  const recorder = env.ALC_RECORDER;
  if (!recorder) return null;
  const secret = await resolveSecret(env.INTERNAL_SHARED_SECRET);
  if (!secret) return null;
  const headers = new Headers(init.headers);
  headers.set("Authorization", secret);
  // service binding fetch は host を無視するが path は recorder の route と
  // 一致させる必要がある
  return recorder.fetch(`https://alc-recorder.internal${path}`, { ...init, headers });
}

/** device_id が本当にこの operator の tenant のものか (詐称防止に必須)。 */
async function deviceBelongsToTenant(
  env: Env,
  tenantId: string,
  deviceId: string,
): Promise<boolean> {
  const rec = await getDeviceRecord(env, deviceId);
  // OTA は CoreS3 firmware を push する → `device-hub` 以外には送らせない
  // (同 tenant でも dtako-scraper 等への誤配布を防ぐ、fail-closed)
  return !!rec && rec.tenant_id === tenantId && !rec.revoked && rec.role === DEVICE_ROLE_HUB;
}

/**
 * POST /device/setup/ota — 登録済みデバイスへ OTA 更新指示を push する。
 * body: `{ device_id, url }` (url は http(s) の firmware app イメージ)。
 * recorder の下り command API に `{action:"ota", url}` を投げ、返ってきた
 * command id を返す (web はこの id で進捗をポーリングする)。
 */
export async function handleDeviceSetupOta(request: Request, env: Env): Promise<Response> {
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
    // 空 body → 検証で弾く
  }
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  const url = typeof body.url === "string" ? body.url : "";
  if (!deviceId || !/^https?:\/\//.test(url)) {
    return jsonNoStore({ error: "device_id と http(s) url が必要です" }, 400);
  }
  // device がこの operator の tenant のものか確認 (他テナントのデバイスを
  // 更新させない — recorder は tenant 単位 DO だが、二重に fail-closed)
  if (!(await deviceBelongsToTenant(env, session.tenantId, deviceId))) {
    return jsonNoStore({ error: "not_your_device" }, 403);
  }

  const res = await recorderFetch(
    env,
    `/tenants/${encodeURIComponent(session.tenantId)}/devices/${encodeURIComponent(deviceId)}/command`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload: { action: "ota", url } }),
    },
  );
  if (!res) return jsonNoStore({ error: "recorder_unconfigured" }, 503);
  if (res.status === 404) {
    // デバイスが WS 未接続 (recorder に居ない)
    return jsonNoStore({ error: "device_not_connected" }, 409);
  }
  if (!res.ok) return jsonNoStore({ error: `recorder_${res.status}` }, 502);
  const data = (await res.json()) as { id?: string };
  return jsonNoStore({ id: data.id ?? "" });
}

/**
 * GET /device/setup/ota/:id — OTA 進捗の取得。デバイスが command_result として
 * push した最新の進捗 payload (`{phase, received, total}` / `{phase:"ok"}` /
 * `{phase:"error"}`) を返す。まだ何も無ければ 404 相当の `{phase:"pending"}`。
 */
export async function handleDeviceSetupOtaStatus(
  request: Request,
  env: Env,
  commandId: string,
): Promise<Response> {
  const session = await cookieSession(request, env);
  if (!session) return jsonNoStore({ error: "unauthorized" }, 401);

  const res = await recorderFetch(
    env,
    `/tenants/${encodeURIComponent(session.tenantId)}/commands/${encodeURIComponent(commandId)}/result`,
    { method: "GET" },
  );
  if (!res) return jsonNoStore({ error: "recorder_unconfigured" }, 503);
  if (res.status === 404) return jsonNoStore({ phase: "pending" });
  if (!res.ok) return jsonNoStore({ error: `recorder_${res.status}` }, 502);
  const stored = (await res.json()) as { payload?: unknown };
  const payload =
    stored.payload && typeof stored.payload === "object" ? stored.payload : { phase: "pending" };
  return jsonNoStore(payload);
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
h2{font-size:1.05rem;margin-top:2rem}
table{border-collapse:collapse;width:100%;font-size:.85rem}
th,td{border:1px solid #e2e5e9;padding:.35rem .6rem;text-align:left}
th{background:#f6f8fa;color:#444;font-weight:600}
button.small{font-size:.8rem;padding:.3rem .6rem;background:#1a56db}
.ota-cell{white-space:nowrap}
.bar{height:.5rem;background:#e2e5e9;border-radius:.25rem;overflow:hidden;margin-top:.3rem;width:12rem}
.bar>span{display:block;height:100%;background:#1a7f37;width:0}
.ota-msg{font-size:.8rem;color:#555;margin-top:.2rem}
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
<h2>登録済みデバイス</h2>
<label for="ota-url">OTA firmware URL (app イメージ)</label>
<input id="ota-url" value="${escapeHtml(otaDefaultUrl(issuer))}" style="width:100%;max-width:32rem">
<p class="muted">「更新」は WS 接続中のデバイスにのみ届きます (LAN/Wi-Fi)。進捗はデバイスが
返す状態をポーリング表示します。</p>
<p id="devices-status" class="muted">読み込み中...</p>
<table id="devices" style="display:none">
<thead><tr><th>ラベル</th><th>デバイスID</th><th>role</th><th>発行日時</th><th>OTA</th></tr></thead>
<tbody id="devices-body"></tbody>
</table>
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

// 登録済みデバイス一覧 (このテナントに発行済みで有効な credential)。
// ページ表示時 + セットアップ成功後に読み直す。
async function loadDevices() {
  const statusEl = document.getElementById("devices-status");
  const table = document.getElementById("devices");
  const body = document.getElementById("devices-body");
  try {
    const res = await fetch(ISSUER + "/device/setup/list", { credentials: "include" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    body.textContent = "";
    if (!data.devices || data.devices.length === 0) {
      table.style.display = "none";
      statusEl.textContent = "登録済みデバイスはありません";
      return;
    }
    for (const d of data.devices) {
      const tr = document.createElement("tr");
      for (const v of [
        d.label,
        d.device_id,
        d.role,
        new Date(d.created_at * 1000).toLocaleString("ja-JP"),
      ]) {
        const td = document.createElement("td");
        td.textContent = String(v);
        tr.appendChild(td);
      }
      // OTA セル: 更新ボタン + 進捗バー + メッセージ
      const otaTd = document.createElement("td");
      otaTd.className = "ota-cell";
      const btn = document.createElement("button");
      btn.className = "small";
      btn.textContent = "更新";
      const bar = document.createElement("div");
      bar.className = "bar";
      bar.style.display = "none";
      const barFill = document.createElement("span");
      bar.appendChild(barFill);
      const msg = document.createElement("div");
      msg.className = "ota-msg";
      btn.addEventListener("click", () => startOta(d.device_id, btn, bar, barFill, msg));
      otaTd.appendChild(btn);
      otaTd.appendChild(bar);
      otaTd.appendChild(msg);
      tr.appendChild(otaTd);
      body.appendChild(tr);
    }
    statusEl.textContent = "";
    table.style.display = "";
  } catch (e) {
    table.style.display = "none";
    statusEl.textContent = "一覧の取得に失敗しました";
  }
}

// OTA を開始し、command id で進捗をポーリングして表示する。
async function startOta(deviceId, btn, bar, barFill, msg) {
  const url = document.getElementById("ota-url").value.trim();
  if (!/^https?:\\/\\//.test(url)) { msg.textContent = "URL が不正です"; return; }
  btn.disabled = true;
  bar.style.display = "";
  barFill.style.width = "0";
  msg.textContent = "デバイスへ指示を送信中...";
  try {
    const res = await fetch(ISSUER + "/device/setup/ota", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ device_id: deviceId, url }),
    });
    if (res.status === 409) { msg.textContent = "デバイスが未接続です (WS 接続を確認)"; btn.disabled = false; return; }
    if (!res.ok) { msg.textContent = "送信失敗: HTTP " + res.status; btn.disabled = false; return; }
    const { id } = await res.json();
    if (!id) { msg.textContent = "command id を取得できませんでした"; btn.disabled = false; return; }
    msg.textContent = "更新を開始しました...";
    pollOta(id, btn, barFill, msg);
  } catch (e) {
    msg.textContent = "送信エラー";
    btn.disabled = false;
  }
}

// 進捗ポーリング (2s 間隔、最大 5 分)。phase = pending/download/ok/error。
async function pollOta(id, btn, barFill, msg) {
  const deadline = Date.now() + 5 * 60 * 1000;
  for (;;) {
    if (Date.now() > deadline) { msg.textContent = "タイムアウト (デバイスの状態を確認してください)"; btn.disabled = false; return; }
    await new Promise((r) => setTimeout(r, 2000));
    let p;
    try {
      const res = await fetch(ISSUER + "/device/setup/ota/" + encodeURIComponent(id), { credentials: "include" });
      if (!res.ok) continue;
      p = await res.json();
    } catch { continue; }
    if (p.phase === "download") {
      const pct = p.total > 0 ? Math.floor((p.received / p.total) * 100) : 0;
      barFill.style.width = pct + "%";
      msg.textContent = "ダウンロード中 " + pct + "% (" + p.received + "/" + p.total + ")";
    } else if (p.phase === "ok") {
      barFill.style.width = "100%";
      msg.textContent = "完了 — デバイスは再起動しています (" + (p.bytes || "?") + " bytes)";
      btn.disabled = false;
      return;
    } else if (p.phase === "error") {
      msg.textContent = "失敗: " + (p.message || "不明なエラー");
      btn.disabled = false;
      return;
    }
    // pending はそのまま次のポーリングへ
  }
}

async function run() {
  runBtn.disabled = true;
  resultEl.textContent = "";
  try {
    if (!("serial" in navigator)) throw new Error("このブラウザは WebSerial 非対応です (Chrome/Edge を使用)");
    const port = await navigator.serial.requestPort();
    await port.open({ baudRate: 115200 });
    // ポート open で ESP32-S3 が DTR/RTS トグルによりリセットする実装があるため、
    // 信号を落としてリセットを抑止する (対応しないボードでは無害)。
    // ただしこれに頼らず、下の PING/PONG で実際の起動完了を待つ
    try { await port.setSignals({ dataTerminalReady: false, requestToSend: false }); } catch {}
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

    // --- 準備ハンドシェイク (根本対策) ---
    // ポート open 時のリセットで最初のコマンドが起動中に飲まれる問題を、固定
    // 待ちやリトライ回数ではなく「PONG が返るまで PING を打ち続ける」ことで
    // 確実に解消する。デバイスが応答可能になった時点で必ず抜ける。
    // 起動 (Wi-Fi/BLE 初期化含む) を見込んで全体 20 秒、PING は 700ms 間隔。
    log("デバイスの起動を待機中 ...");
    const readyDeadline = Date.now() + 20000;
    let ready = false;
    while (Date.now() < readyDeadline) {
      const before = lines.length;
      await writer.write(new TextEncoder().encode("PING\\n"));
      // 700ms 以内に PONG が来たか (この PING への応答)
      const until = Date.now() + 700;
      while (Date.now() < until) {
        if (lines.slice(before).some((l) => /^PONG/.test(l))) { ready = true; break; }
        await new Promise((r) => setTimeout(r, 50));
      }
      if (ready) break;
    }
    if (!ready) throw new Error("デバイスが応答しません (USB 接続とファームウェアを確認してください)");
    log("デバイス応答 OK — 現在の登録状態を確認します");
    // 起動中に溜まったログ行は捨て、以降のコマンド応答だけを見る
    lines.length = 0;

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
    // AUTH TOKEN は HTTPS 疎通確認。デバイス側が Wi-Fi 再接続 (ポート open の
    // リセット後 ~30 秒) を内部で待ってから mint するため、余裕をもって待つ
    await send("AUTH TOKEN");
    const evt = await waitLine(/^EVT AUTH_TOKEN (OK|NG)/, 60000);
    if (!/^EVT AUTH_TOKEN OK/.test(evt)) throw new Error(evt);
    await send("WS STATUS");
    await waitLine(/^WS /, 5000);

    resultEl.innerHTML = '<span class="ok">登録完了 — デバイスは auth-worker と疎通済みです</span>';
    writer.releaseLock();
    await reader.cancel().catch(() => {});
    await port.close().catch(() => {});
    loadDevices();
  } catch (e) {
    resultEl.innerHTML = '<span class="ng">失敗: ' +
      String(e && e.message ? e.message : e).replace(/[<>&]/g, "") + "</span>";
  } finally {
    runBtn.disabled = false;
  }
}
runBtn.addEventListener("click", run);
loadDevices();
</script>
<p class="muted">${escapeHtml(issuer)}</p>
</body></html>`;
}
