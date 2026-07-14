/**
 * 印刷ブリッジ (AtomS3 + Atomic PoE Base、ippoan/alc-app-s3#38) のテスト支援。
 *
 *   GET /print/test.pdf     — テスト用 PDF (公開)。デバイスの HTTP クライアント
 *                             は認証ヘッダを付けないため認証無し。内容は
 *                             生成時刻入りの 1 ページ PDF (PDF ダイレクト
 *                             プリント対応プリンターの検証も兼ねる、#37)
 *   GET /device/print-test  — login-gated の WebSerial ページ。ブラウザから
 *                             印刷ブリッジに PRINTER ADDR / PRINT を注入し、
 *                             EVT PRINT_* の進捗・結果を表示する
 *
 * ページ構成・セッション検証・WebSerial の作法は device-setup.ts を踏襲。
 */

import type { Env } from "../index";
import { resolveSecret } from "../lib/secret";
import { verifyJwt } from "../lib/jwt";
import { getAuthCookie } from "../lib/cookies";
import { escapeHtml } from "../lib/html";

function issuerOf(env: Env): string {
  return env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
}

/**
 * 生成時刻・ホスト入りの最小 1 ページ PDF を組み立てる。
 * xref のバイトオフセットを正しく計算した正規の PDF (プリンターの PDF
 * ダイレクトプリントでそのまま印字できることを狙う)。ASCII のみで構成する
 * (バイト長 = 文字列長 の前提で offset を計算するため)。
 */
export function buildTestPdf(now: Date, host: string): Uint8Array {
  // PDF 文字列リテラルのエスケープ (ASCII 前提)
  const esc = (s: string) => s.replace(/[\\()]/g, (c) => `\\${c}`);
  const lines = [
    { size: 24, y: 780, text: "ALC PRINT TEST" },
    { size: 12, y: 745, text: `Generated: ${now.toISOString()}` },
    { size: 12, y: 725, text: `Source: ${host}` },
    { size: 12, y: 705, text: "alc-app-s3 #38 print bridge (AtomS3 + PoE)" },
    { size: 10, y: 60, text: "If you can read this, PDF direct printing works." },
  ];
  const content = lines
    .map((l) => `BT /F1 ${l.size} Tf 72 ${l.y} Td (${esc(l.text)}) Tj ET`)
    .join("\n");

  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] " +
      "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    `<< /Length ${content.length} >>\nstream\n${content}\nendstream`,
  ];

  let body = "%PDF-1.4\n";
  const offsets: number[] = [];
  objects.forEach((obj, i) => {
    offsets.push(body.length);
    body += `${i + 1} 0 obj\n${obj}\nendobj\n`;
  });
  const xrefAt = body.length;
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) {
    body += `${String(off).padStart(10, "0")} 00000 n \n`;
  }
  body +=
    `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\n` +
    `startxref\n${xrefAt}\n%%EOF\n`;
  return new TextEncoder().encode(body);
}

/** GET /print/test.pdf — テスト用 PDF (公開・認証無し)。 */
export function handlePrintTestPdf(request: Request): Response {
  const host = new URL(request.url).host;
  return new Response(buildTestPdf(new Date(), host), {
    headers: {
      "Content-Type": "application/pdf",
      // 毎回生成時刻が変わるためキャッシュさせない
      "Cache-Control": "no-store",
      "Content-Disposition": 'inline; filename="alc-print-test.pdf"',
    },
  });
}

interface OperatorSession {
  tenantId: string;
  email: string;
}

/** cookie (logi_auth_token) の session JWT から operator を返す。不正なら null。 */
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

/** GET /device/print-test — WebSerial プリントテストページ (要ログイン)。 */
export async function handlePrintTestPage(request: Request, env: Env): Promise<Response> {
  const issuer = issuerOf(env);
  const session = await cookieSession(request, env);
  if (!session) {
    // cookie 有りの検証失敗を /login に戻すと無限ループ (device-setup.ts と同じ)
    if (getAuthCookie(request)) {
      return new Response(sessionErrorPage(issuer), {
        status: 403,
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      });
    }
    const back = `${issuer}/device/print-test`;
    return Response.redirect(`${issuer}/login?redirect_uri=${encodeURIComponent(back)}`, 302);
  }
  return new Response(printTestPage(issuer, session.email), {
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

/** cookie はあるがセッションとして使えない場合の案内 (device-setup.ts と同文)。 */
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

function printTestPage(issuer: string, email: string): string {
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>印刷ブリッジ プリントテスト</title>
<style>
body{font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.4rem} h2{font-size:1.05rem;margin-top:1.6rem}
.card{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}
label{display:block;font-size:.85rem;color:#444;margin:.6rem 0 .2rem}
input{font:inherit;padding:.45rem .6rem;border:1px solid #bbb;border-radius:6px;width:16rem;max-width:100%}
button{font:inherit;padding:.5rem 1.1rem;border:0;border-radius:6px;background:#1a56db;color:#fff;cursor:pointer;margin-top:.6rem}
button:disabled{background:#9db3e8;cursor:default}
pre{background:#0b1020;color:#d5e0ff;padding: .8rem;border-radius:8px;min-height:9rem;max-height:20rem;overflow:auto;font-size:.78rem;white-space:pre-wrap}
.ok{color:#0a7a2f;font-weight:600}.ng{color:#c22;font-weight:600}.muted{color:#666;font-size:.85rem}
</style></head>
<body>
<h1>印刷ブリッジ プリントテスト</h1>
<p class="muted">ログイン中: ${escapeHtml(email)} — AtomS3 印刷ブリッジを USB で接続し、
テスト PDF (<a href="${escapeHtml(issuer)}/print/test.pdf" target="_blank">/print/test.pdf</a>)
をプリンターへ送ります。</p>

<div class="card">
  <label for="printer">プリンター宛先 (host:port — 9100 raw)</label>
  <input id="printer" placeholder="192.168.11.60:9100" spellcheck="false">
  <label for="url">印刷する PDF URL (既定はこのページのテスト PDF)</label>
  <input id="url" value="${escapeHtml(issuer)}/print/test.pdf" spellcheck="false" style="width:100%">
  <br>
  <button id="run">接続してテスト印刷</button>
  <p id="result"></p>
</div>

<h2>ログ</h2>
<pre id="log"></pre>
<p class="muted">対応コマンド: PING / STATUS / PRINTER ADDR / PRINT。
プリンター不通の場合は EVT PRINT NG (接続できません) が返ります (デバイスは稼働継続)。</p>

<script>
const ISSUER = ${JSON.stringify(issuer)};
const logEl = document.getElementById("log");
const resultEl = document.getElementById("result");
const runBtn = document.getElementById("run");
// デバイス応答の既知プレフィックスだけ拾う (ESP-IDF ログの混在対策)
const KNOWN = /^(OK|ERR|PONG|STATUS|PRINTER|EVT|HEAP)\\b/;
function log(s) { logEl.textContent += s + "\\n"; logEl.scrollTop = logEl.scrollHeight; }

async function run() {
  runBtn.disabled = true;
  resultEl.textContent = "";
  try {
    const printer = document.getElementById("printer").value.trim();
    if (!/^\\S+:\\d+$/.test(printer)) throw new Error("プリンター宛先を host:port 形式で入力してください");
    const url = document.getElementById("url").value.trim();
    if (!/^https?:\\/\\//.test(url)) throw new Error("PDF URL は http(s):// で始めてください");
    if (!("serial" in navigator)) throw new Error("このブラウザは WebSerial 非対応です (Chrome/Edge を使用)");

    const port = await navigator.serial.requestPort();
    await port.open({ baudRate: 115200 });
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
    const send = async (cmd) => {
      log(">> " + cmd);
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

    // PONG が返るまで PING (ポート open のリセットで最初のコマンドが飲まれる対策)
    log("デバイスの起動を待機中 ...");
    const readyDeadline = Date.now() + 20000;
    let ready = false;
    while (Date.now() < readyDeadline) {
      const before = lines.length;
      await writer.write(new TextEncoder().encode("PING\\n"));
      const until = Date.now() + 700;
      while (Date.now() < until) {
        if (lines.slice(before).some((l) => /^PONG/.test(l))) { ready = true; break; }
        await new Promise((r) => setTimeout(r, 50));
      }
      if (ready) break;
    }
    if (!ready) throw new Error("デバイスが応答しません (USB 接続とファームウェアを確認してください)");
    lines.length = 0;

    await send("STATUS");
    await waitLine(/^STATUS /, 5000);
    await send("PRINTER ADDR " + printer);
    await waitLine(/^OK PRINTER ADDR/, 5000);
    await send("PRINT " + url);
    await waitLine(/^OK PRINT/, 5000);
    log("印刷ジョブ開始 — 結果を待っています (最大 90 秒) ...");
    // 不通時は lwip の接続タイムアウト (~20 秒) 後に NG が届く
    const evt = await waitLine(/^EVT PRINT (OK|NG)/, 90000);
    if (/^EVT PRINT OK/.test(evt)) {
      resultEl.innerHTML = '<span class="ok">送信成功: ' + evt.replace(/[<>&]/g, "") + " bytes</span>";
    } else {
      resultEl.innerHTML = '<span class="ng">失敗: ' + evt.replace(/[<>&]/g, "") + "</span>";
    }
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
