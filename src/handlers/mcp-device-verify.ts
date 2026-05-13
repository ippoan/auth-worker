/**
 * `POST /device/verify` — user_code 検証 → 承認確認ページ表示。
 *
 * Browser からの form POST を受け、入力された user_code を:
 *   1. Origin header で CSRF 防御 (RFC 6454 / OWASP standard)
 *   2. 正規化 + フォーマット validate (大文字化、hyphen 整形)
 *   3. KV `user_code:*` で逆引き → `device_code:*` を取得
 *   4. status が pending なら承認確認ページ (consent) を返す
 *   5. 既に approved / denied なら 409
 *
 * 不在 / 期限切れ / 不正フォーマットは device 入力ページに戻して再入力させる。
 */

import type { Env } from "../index";
import {
  renderDeviceConsentPage,
  renderDevicePage,
  renderDeviceResultPage,
} from "../lib/mcp-device-html";
import {
  getDeviceCode,
  getDeviceCodeByUserCode,
} from "../lib/mcp-kv";

function htmlResponse(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

/** RFC 6454 / OWASP CSRF defense: Origin must match this auth-worker origin. */
function checkOrigin(request: Request, expected: string): boolean {
  const origin = request.headers.get("Origin");
  if (!origin) return false; // fail-closed for browsers that omit Origin
  return origin === expected;
}

/** `BCDFGHJK`, `bcdf-ghjk`, `BCDF GHJK` → `BCDFGHJK` → `BCDF-GHJK` */
export function normalizeUserCode(raw: string): string {
  const stripped = raw.toUpperCase().replace(/[^A-Z]/g, "");
  if (stripped.length !== 8) return raw.trim().toUpperCase();
  return `${stripped.slice(0, 4)}-${stripped.slice(4)}`;
}

const USER_CODE_RE = /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/;

export async function handleMcpDeviceVerify(
  request: Request,
  env: Env,
): Promise<Response> {
  const issuer = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";

  if (!env.MCP_OAUTH_KV) {
    return htmlResponse(
      renderDeviceResultPage({
        title: "Service unavailable",
        message: "MCP OAuth Provider is not configured.",
        level: "error",
        issuer,
      }),
      503,
    );
  }
  if (!checkOrigin(request, issuer)) {
    return htmlResponse(
      renderDeviceResultPage({
        title: "Request rejected",
        message: "Request rejected (Origin mismatch).",
        level: "error",
        issuer,
      }),
      403,
    );
  }

  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return htmlResponse(
      renderDeviceResultPage({
        title: "Invalid request",
        message: "Expected form-encoded body.",
        level: "error",
        issuer,
      }),
      400,
    );
  }

  const rawCode = ((form.get("user_code") as string | null) ?? "").trim();
  const userCode = normalizeUserCode(rawCode);

  if (!USER_CODE_RE.test(userCode)) {
    return htmlResponse(
      renderDevicePage({
        prefilledCode: rawCode,
        errorMessage: "Invalid user_code format. Expected XXXX-XXXX (8 letters).",
        issuer,
      }),
      400,
    );
  }

  const deviceCode = await getDeviceCodeByUserCode(env, userCode);
  if (!deviceCode) {
    return htmlResponse(
      renderDevicePage({
        prefilledCode: rawCode,
        errorMessage: "Code not found or expired. Please re-run the command on your device.",
        issuer,
      }),
      404,
    );
  }
  const record = await getDeviceCode(env, deviceCode);
  if (!record) {
    return htmlResponse(
      renderDevicePage({
        prefilledCode: rawCode,
        errorMessage: "Code expired. Please re-run the command on your device.",
        issuer,
      }),
      410,
    );
  }
  if (record.status !== "pending") {
    return htmlResponse(
      renderDeviceResultPage({
        title: "Already processed",
        message: `This code has already been ${record.status}.`,
        level: "info",
        issuer,
      }),
      409,
    );
  }

  return htmlResponse(
    renderDeviceConsentPage({
      user_code: userCode,
      client_id: record.client_id,
      scope: record.scope,
      issuer,
    }),
  );
}
