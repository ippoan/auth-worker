/**
 * MCP OAuth Provider — Device authorization HTML pages.
 *
 * 3 つの page を export:
 *   - `renderDevicePage`         — `GET /device` の user_code 入力フォーム
 *   - `renderDeviceConsentPage`  — `POST /device/verify` 後の承認確認ページ
 *   - `renderDeviceResultPage`   — denied / expired / already-processed 等の終了画面
 *
 * 全 page にセキュリティバナー (issuer host 表示) を含めてフィッシング対策。
 * 値挿入は必ず `escapeHtml` 経由 (XSS 防止)。
 *
 * 既存 auth-worker に CSP header なし → Phase 7 で導入検討。
 */

import { escapeHtml } from "./html";

export interface DeviceConsentInfo {
  user_code: string;
  client_id: string;
  scope: string; // space-separated; empty when not provided
  issuer: string; // env.AUTH_WORKER_ORIGIN
}

function safeHost(issuer: string): string {
  try {
    return new URL(issuer).host;
  } catch {
    return issuer;
  }
}

function securityBanner(issuer: string): string {
  const host = escapeHtml(safeHost(issuer));
  return `
    <div class="banner banner--warn" role="alert">
      <strong>⚠ Verify the URL above is exactly <code>${host}</code></strong>
      before continuing. Phishing pages may look identical.
    </div>`;
}

const STYLE = `
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 540px;
           margin: 4em auto; padding: 0 1em; color: #1f2937; }
    h1 { font-size: 1.4em; margin-bottom: 0.5em; }
    .banner { padding: 0.9em 1em; border-radius: 6px; margin: 1em 0; font-size: 0.95em; }
    .banner--warn { background: #fef3c7; border: 1px solid #f59e0b; color: #78350f; }
    .banner--err  { background: #fee2e2; border: 1px solid #ef4444; color: #7f1d1d; }
    .banner--ok   { background: #d1fae5; border: 1px solid #10b981; color: #064e3b; }
    .banner--info { background: #dbeafe; border: 1px solid #3b82f6; color: #1e3a8a; }
    .field { margin: 1em 0; }
    label { display: block; font-weight: 600; margin-bottom: 0.3em; }
    input[type="text"] { font: inherit; padding: 0.6em 0.8em; border: 1px solid #d1d5db;
                         border-radius: 4px; width: 100%; box-sizing: border-box;
                         letter-spacing: 0.15em; font-size: 1.15em; }
    button { padding: 0.6em 1.2em; font: inherit; border-radius: 4px; border: 0;
             cursor: pointer; margin-right: 0.5em; }
    button.primary { background: #2563eb; color: #fff; }
    button.danger  { background: #dc2626; color: #fff; }
    button.ghost   { background: #e5e7eb; color: #1f2937; }
    .meta { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 4px;
            padding: 0.8em 1em; margin: 1em 0; font-size: 0.95em; }
    .meta dt { font-weight: 600; color: #6b7280; margin-top: 0.5em; }
    .meta dt:first-child { margin-top: 0; }
    .meta dd { margin: 0.2em 0 0.6em 0; font-family: ui-monospace, monospace; }
    code { font-family: ui-monospace, monospace; background: #f3f4f6; padding: 0.1em 0.3em;
           border-radius: 3px; }
  </style>`;

function shell(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${escapeHtml(title)}</title>${STYLE}
</head>
<body>${body}</body>
</html>`;
}

/** GET /device — user_code 入力フォーム。code が pre-fill されることもある。 */
export function renderDevicePage(opts: {
  prefilledCode?: string;
  errorMessage?: string;
  issuer: string;
}): string {
  const code = escapeHtml(opts.prefilledCode ?? "");
  const errBanner = opts.errorMessage
    ? `<div class="banner banner--err" role="alert">${escapeHtml(opts.errorMessage)}</div>`
    : "";
  const body = `
    <h1>Authorize device</h1>
    ${securityBanner(opts.issuer)}
    ${errBanner}
    <p>Enter the code shown on your device.</p>
    <form method="POST" action="/device/verify" autocomplete="off">
      <div class="field">
        <label for="user_code">User code</label>
        <input type="text" id="user_code" name="user_code" value="${code}"
               required pattern="[A-Za-z\\-\\s]{8,9}" maxlength="9"
               autocapitalize="characters" spellcheck="false" autofocus>
      </div>
      <button type="submit" class="primary">Continue</button>
    </form>`;
  return shell("Authorize device", body);
}

/** POST /device/verify — 承認確認画面 (scope / client_id を明示)。 */
export function renderDeviceConsentPage(info: DeviceConsentInfo): string {
  const userCode = escapeHtml(info.user_code);
  const clientId = escapeHtml(info.client_id);
  const scopeStr = info.scope || "(no scopes requested)";
  const scopeHtml = escapeHtml(scopeStr);
  const body = `
    <h1>Approve this device?</h1>
    ${securityBanner(info.issuer)}
    <p>A device is requesting authorization with the following details:</p>
    <dl class="meta">
      <dt>Application</dt><dd>${clientId}</dd>
      <dt>Requested scopes</dt><dd>${scopeHtml}</dd>
      <dt>User code</dt><dd>${userCode}</dd>
    </dl>
    <p>If you did not initiate this request, click <strong>Deny</strong>.</p>
    <form method="POST" action="/device/proceed" autocomplete="off">
      <input type="hidden" name="user_code" value="${userCode}">
      <button type="submit" name="action" value="approve" class="primary">Approve</button>
      <button type="submit" name="action" value="deny" class="danger">Deny</button>
    </form>`;
  return shell("Approve device", body);
}

/** denied / expired / unknown user_code 等の終了画面。 */
export function renderDeviceResultPage(opts: {
  title: string;
  message: string;
  level: "info" | "success" | "error";
  issuer: string;
}): string {
  const cls =
    opts.level === "success" ? "banner--ok" :
    opts.level === "error"   ? "banner--err" :
                                "banner--info";
  const body = `
    <h1>${escapeHtml(opts.title)}</h1>
    ${securityBanner(opts.issuer)}
    <div class="banner ${cls}" role="status">${escapeHtml(opts.message)}</div>
    <p>You may close this window.</p>`;
  return shell(opts.title, body);
}
