/**
 * 参加ページ: GET /join/:slug
 * slug の会社の名前と、参加を申請するためのログインのボタンを出す。会社は alc-auth-worker の
 * `GET /internal/tenant-by-slug/{slug}` で引く (Refs ippoan/rust-alc-api#680。以前は rust-alc-api の
 * `/api/tenants/by-slug/{slug}`)。認証は要らない。
 */

import type { Env } from "../index";
import { resolveSecret } from "../lib/secret";
import { callTenantAdmin } from "../lib/alc-tenant-admin";
import { renderJoinPage, renderJoinNotFoundPage } from "../lib/join-html";

export async function handleJoinPage(
  _request: Request,
  env: Env,
  slug: string,
): Promise<Response> {
  const r = await callTenantAdmin(env, `/internal/tenant-by-slug/${encodeURIComponent(slug)}`);

  if (r.status === 404) {
    return new Response(renderJoinNotFoundPage(), {
      status: 404,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  if (r.status !== 200) {
    console.error(JSON.stringify({ event: "join_page_lookup_failed", status: r.status }));
    return new Response("Internal Server Error", { status: 500 });
  }

  const orgInfo = r.body as { name: string };

  const html = renderJoinPage({
    orgName: orgInfo.name,
    orgSlug: slug,
    googleEnabled: !!(await resolveSecret(env.GOOGLE_CLIENT_ID)),
    authWorkerOrigin: env.AUTH_WORKER_ORIGIN,
  });

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
