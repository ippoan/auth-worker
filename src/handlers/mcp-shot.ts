/**
 * `GET /mcp/shot/:id` — verify_screenshot (src/lib/verify-shot.ts) が KV に
 * 置いた PNG を配る短命 endpoint。
 *
 * 認証なし・予測不能 id (256bit hex)・TTL 5 分の組み合わせは cdp-relay の
 * shot_url / stash_url と同じ判断: PNG を MCP body (= LLM context) に載せずに
 * `curl -o shot.png <url>` で回収させるための配布口で、id を知り得るのは
 * 発行を受けた MCP セッションだけ。
 */
import type { Env } from "../index";
import { base64Decode } from "../lib/lineworks-crypto";
import { VERIFY_SHOT_KV_PREFIX } from "../lib/verify-shot";

const SHOT_ID_RE = /^[0-9a-f]{64}$/;

export async function handleMcpShot(
  _request: Request,
  env: Env,
  id: string,
): Promise<Response> {
  if (!env.MCP_OAUTH_KV) {
    return new Response(JSON.stringify({ error: "server_error" }), {
      status: 503,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  }
  if (!SHOT_ID_RE.test(id)) {
    return new Response(JSON.stringify({ error: "not_found" }), {
      status: 404,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  }
  const b64 = await env.MCP_OAUTH_KV.get(`${VERIFY_SHOT_KV_PREFIX}${id}`);
  if (!b64) {
    return new Response(JSON.stringify({ error: "not_found" }), {
      status: 404,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  }
  const png = base64Decode(b64);
  return new Response(png, {
    status: 200,
    headers: {
      "Content-Type": "image/png",
      "Cache-Control": "no-store",
      "Content-Disposition": `inline; filename="${id.slice(0, 12)}.png"`,
    },
  });
}
