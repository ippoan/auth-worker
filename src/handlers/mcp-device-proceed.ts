/**
 * `POST /device/proceed` — 承認確認ページからの approve / deny を処理する。
 *
 *   - `action=approve` → GitHub OAuth authorize URL へ 302
 *     (state に device_code を埋め込み、Phase 3 callback で取り出す)
 *   - `action=deny`    → KV `device_code:*` の status を "denied" に更新
 *     + 終了画面を表示
 *
 * verify と同じガード (KV bind / Origin / form parse / user_code 検証) を踏む。
 */

import type { Env } from "../index";
import {
  renderDevicePage,
  renderDeviceResultPage,
} from "../lib/mcp-device-html";
import {
  getDeviceCode,
  getDeviceCodeByUserCode,
  setDeviceCodeStatus,
} from "../lib/mcp-kv";
import { generateOAuthState } from "../lib/security";
import { normalizeUserCode } from "./mcp-device-verify";

function htmlResponse(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function checkOrigin(request: Request, expected: string): boolean {
  const origin = request.headers.get("Origin");
  if (!origin) return false;
  return origin === expected;
}

const USER_CODE_RE = /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/;

export async function handleMcpDeviceProceed(
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
        errorMessage: "Invalid user_code.",
        issuer,
      }),
      400,
    );
  }

  const action = ((form.get("action") as string | null) ?? "").toLowerCase();
  if (action !== "approve" && action !== "deny") {
    return htmlResponse(
      renderDeviceResultPage({
        title: "Invalid action",
        message: "Expected action=approve or action=deny.",
        level: "error",
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
        errorMessage: "Code not found or expired.",
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
        errorMessage: "Code expired.",
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

  if (action === "deny") {
    await setDeviceCodeStatus(env, deviceCode, "denied");
    return htmlResponse(
      renderDeviceResultPage({
        title: "Denied",
        message: "You denied this device. You may close this window.",
        level: "info",
        issuer,
      }),
    );
  }

  // action === "approve"
  if (!env.GITHUB_MCP_CLIENT_ID) {
    return htmlResponse(
      renderDeviceResultPage({
        title: "Configuration error",
        message: "GitHub OAuth App is not configured.",
        level: "error",
        issuer,
      }),
      503,
    );
  }

  // OAuth state に device_code を埋め込み、Phase 3 callback で取り出す。
  // generateOAuthState は OAUTH_STATE_SECRET で HMAC 署名するので改ざん不可。
  const callbackUri = `${issuer}/mcp/device_callback`;
  const state = await generateOAuthState(
    callbackUri,
    env.OAUTH_STATE_SECRET,
    { device_code: deviceCode, provider: "github_mcp" },
  );

  const ghAuthorize = new URL("https://github.com/login/oauth/authorize");
  ghAuthorize.searchParams.set("client_id", env.GITHUB_MCP_CLIENT_ID);
  ghAuthorize.searchParams.set("redirect_uri", callbackUri);
  ghAuthorize.searchParams.set("scope", "read:user");
  ghAuthorize.searchParams.set("state", state);
  ghAuthorize.searchParams.set("allow_signup", "false");

  return Response.redirect(ghAuthorize.toString(), 302);
}
