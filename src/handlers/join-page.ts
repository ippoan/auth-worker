/**
 * Join page handler: GET /join/:slug (REST version)
 * Shows organization name + OAuth buttons for requesting access
 */

import type { Env } from "../index";
import { resolveSecret } from "../lib/secret";
import { alcOidcToken } from "../lib/alc-data-fetch";
import { renderJoinPage, renderJoinNotFoundPage } from "../lib/join-html";

export async function handleJoinPage(
  request: Request,
  env: Env,
  slug: string,
): Promise<Response> {
  try {
    // Look up tenant by slug via REST。#434 lockdown 後は Cloud Run IAM が OIDC を
    // 要求するため Google OIDC token (aud=ALC_API_ORIGIN) を付ける。by-slug は public
    // route なので identity 注入は不要、transport 用の OIDC だけ。mint 不可 (SA 未設定)
    // の場合は header 無しで継続 (lockdown 前は allUsers で素通り)。
    const oidc = await alcOidcToken(env);
    const resp = await fetch(
      `${env.ALC_API_ORIGIN}/api/tenants/by-slug/${encodeURIComponent(slug)}`,
      oidc ? { headers: { Authorization: `Bearer ${oidc}` } } : undefined,
    );

    if (resp.status === 404) {
      return new Response(renderJoinNotFoundPage(), {
        status: 404,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (!resp.ok) {
      const text = await resp.text();
      console.error("Error fetching organization:", text);
      return new Response("Internal Server Error", { status: 500 });
    }

    const orgInfo = (await resp.json()) as { found: boolean; name: string };

    if (!orgInfo.found) {
      return new Response(renderJoinNotFoundPage(), {
        status: 404,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    const html = renderJoinPage({
      orgName: orgInfo.name,
      orgSlug: slug,
      googleEnabled: !!(await resolveSecret(env.GOOGLE_CLIENT_ID)),
      authWorkerOrigin: env.AUTH_WORKER_ORIGIN,
    });

    return new Response(html, {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  } catch (err) {
    console.error("Error fetching organization:", err);
    return new Response("Internal Server Error", { status: 500 });
  }
}
