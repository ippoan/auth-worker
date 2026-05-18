/**
 * `POST /mcp/revoke` (issue #145) — RFC 7009 OAuth 2.0 Token Revocation。
 *
 * 受け付ける form fields:
 *   - `token`            (required) — access_token (JWT) または refresh_token
 *   - `token_type_hint`  (optional) — `"access_token"` | `"refresh_token"`
 *   - `client_id`        (optional) — 検証はしない (RFC 7009 §2.1 SHOULD)
 *
 * Behavior:
 *   - refresh_token: KV `refresh:{sha256(token)}` を delete
 *   - access_token (JWT): JWT は self-contained で revoke できないため、
 *     対応する `github_token:{sub}` KV を削除して「以後 introspect しても
 *     使えない」状態にする。これにより JWT exp 切れ前でも実質失効する。
 *
 * Response: RFC 7009 §2.2 に従い、token の有効性に関わらず常に 200 + 空 body。
 * server error は 503 / 500 で返す。
 *
 * Note: token_type_hint が間違っていても両方試す (RFC 7009 §2.1)。
 */

import type { Env } from "../index";
import { jsonResponse } from "../lib/errors";
import { verifyMcpJwt } from "../lib/mcp-jwt";

const MCP_AUD_LEGACY = "github-mcp-server-rs";

function isJwtShape(s: string): boolean {
  // base64url alphabet only, no whitespace, three dot-separated parts
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(s);
}

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function deleteRefresh(env: Env, token: string): Promise<boolean> {
  if (!env.MCP_OAUTH_KV) return false;
  const hash = await sha256Hex(token);
  const key = `refresh:${hash}`;
  const existed = (await env.MCP_OAUTH_KV.get(key)) !== null;
  await env.MCP_OAUTH_KV.delete(key);
  return existed;
}

async function deleteGithubTokenForJwt(env: Env, token: string): Promise<boolean> {
  if (!env.MCP_OAUTH_KV || !env.MCP_JWT_SECRET) return false;
  // verifyMcpJwt は aud strict だが revoke は best-effort なので legacy aud
  // でも relay-origin aud でも通す (どちらも有効に発行されている前提)。
  const accept = (aud: string): boolean => {
    if (aud === MCP_AUD_LEGACY) return true;
    try { return /^https:\/\/[^/]+$/.test(new URL(aud).origin); } catch { return false; }
  };
  const payload = await verifyMcpJwt(token, env.MCP_JWT_SECRET, accept);
  if (!payload) return false;
  const key = `github_token:${payload.sub}`;
  const existed = (await env.MCP_OAUTH_KV.get(key)) !== null;
  await env.MCP_OAUTH_KV.delete(key);
  return existed;
}

export async function handleMcpRevoke(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!env.MCP_OAUTH_KV || !env.MCP_JWT_SECRET) {
    return jsonResponse(
      { error: "server_error", error_description: "MCP OAuth Provider not configured" },
      503,
    );
  }

  // Accept both application/x-www-form-urlencoded (RFC 7009 default) and JSON.
  let token = "";
  let hint = "";
  const ct = request.headers.get("Content-Type") ?? "";
  try {
    if (ct.includes("application/json")) {
      const body = (await request.json()) as { token?: unknown; token_type_hint?: unknown };
      token = typeof body.token === "string" ? body.token : "";
      hint = typeof body.token_type_hint === "string" ? body.token_type_hint : "";
    } else {
      const form = await request.formData();
      const t = form.get("token");
      token = typeof t === "string" ? t : "";
      const h = form.get("token_type_hint");
      hint = typeof h === "string" ? h : "";
    }
  } catch {
    // RFC 7009 §2.2: invalid request → 400.
    return jsonResponse(
      { error: "invalid_request", error_description: "could not parse body" },
      400,
    );
  }
  if (!token) {
    return jsonResponse(
      { error: "invalid_request", error_description: "token is required" },
      400,
    );
  }

  // try the hinted shape first, then fall back to the other shape.
  const looksJwt = isJwtShape(token);
  const order: Array<"access_token" | "refresh_token"> =
    hint === "access_token"
      ? ["access_token", "refresh_token"]
      : hint === "refresh_token"
        ? ["refresh_token", "access_token"]
        : looksJwt
          ? ["access_token", "refresh_token"]
          : ["refresh_token", "access_token"];

  for (const kind of order) {
    if (kind === "access_token") {
      if (await deleteGithubTokenForJwt(env, token)) break;
    } else {
      if (await deleteRefresh(env, token)) break;
    }
  }
  // RFC 7009 §2.2: response is the empty body on success (whether or not
  // the token was valid). HTTP 200 with no Content-Length is conformant.
  return new Response(null, { status: 200 });
}
