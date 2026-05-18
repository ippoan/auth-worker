/**
 * `POST /mcp/jwt/pickup`
 *
 * Recovery endpoint for `github-mcp-server-rs` binaries whose local
 * `refresh_token` is dead (rotated by a parallel session / expired past 30d
 * TTL / cache file corrupted). The binary presents its **possibly expired**
 * JWT, we verify the signature only (not `exp`), look up
 * `mcp_jwt_pickup:<sub>` (populated by `/mcp/elevate_callback`), decrypt,
 * **delete** (one-shot) and return the fresh pair.
 *
 * Threat model:
 *  - Accepting an expired-but-genuine JWT here doesn't widen the trust
 *    surface beyond "this caller once held a valid token signed by
 *    `MCP_JWT_SECRET`". The KV entry is bound to `payload.sub` and is
 *    one-shot, so a leaked expired JWT can only redeem the pickup if it
 *    *also* happens to land within the 1h window where the user just
 *    elevated. That's a narrow window we accept in exchange for the UX win.
 *  - If you suspect a JWT secret leak, rotate `MCP_JWT_SECRET` — that
 *    invalidates every signature including the expired ones this endpoint
 *    would otherwise accept.
 *
 * Authentication:
 *   `Authorization: Bearer <MCP JWT, possibly expired>`
 *
 * Responses:
 *   200 → `{ access_token, refresh_token, scope, expires_in }`
 *   401 → `{ error: "unauthorized" }`  (missing/malformed header, bad sig)
 *   404 → `{ error: "no_pickup" }`     (no pending pickup for this `sub`)
 *   503 → `{ error: "server_error" }`  (env binding missing)
 *
 * Cache-Control: no-store on every response.
 */

import type { Env } from "../index";
import { decryptWithKey } from "../lib/mcp-crypto";
import { verifyMcpJwtSignatureOnly } from "../lib/mcp-jwt";

function jsonNoStore(data: unknown, status = 200): Response {
  const res = new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
  res.headers.set("Cache-Control", "no-store");
  return res;
}

interface PickupBlob {
  access_token: string;
  refresh_token: string;
  scope: string;
  expires_in: number;
}

export async function handleMcpJwtPickup(
  request: Request,
  env: Env,
): Promise<Response> {
  if (
    !env.MCP_OAUTH_KV ||
    !env.MCP_JWT_SECRET ||
    !env.SSO_ENCRYPTION_KEY
  ) {
    return jsonNoStore({ error: "server_error" }, 503);
  }

  const authz = request.headers.get("Authorization") ?? "";
  const bearer = /^Bearer\s+(.+)$/i.exec(authz);
  if (!bearer || !bearer[1]) {
    return jsonNoStore({ error: "unauthorized" }, 401);
  }

  // Signature-only verification — exp is allowed to be in the past so a
  // stale binary can recover. `sub` shape is validated inside the helper.
  const payload = await verifyMcpJwtSignatureOnly(bearer[1], env.MCP_JWT_SECRET);
  if (!payload) {
    return jsonNoStore({ error: "unauthorized" }, 401);
  }

  const key = `mcp_jwt_pickup:${payload.sub}`;
  const ciphertext = await env.MCP_OAUTH_KV.get(key);
  if (!ciphertext) {
    return jsonNoStore({ error: "no_pickup" }, 404);
  }

  // delete-first to make pickup one-shot (mirrors `consumeRefreshToken`)
  await env.MCP_OAUTH_KV.delete(key);

  let plaintext: string;
  try {
    plaintext = await decryptWithKey(ciphertext, env.SSO_ENCRYPTION_KEY);
  } catch {
    // Decrypt failed (key rotated, corrupted entry). Surface as no_pickup —
    // the binary will fall through to the device-URL error and the user
    // re-runs `/mcp/elevate` which writes a fresh entry.
    return jsonNoStore({ error: "no_pickup" }, 404);
  }

  let blob: PickupBlob;
  try {
    blob = JSON.parse(plaintext) as PickupBlob;
  } catch {
    return jsonNoStore({ error: "no_pickup" }, 404);
  }

  return jsonNoStore({
    access_token: blob.access_token,
    refresh_token: blob.refresh_token,
    scope: blob.scope,
    expires_in: blob.expires_in,
  });
}
