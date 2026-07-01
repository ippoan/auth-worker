import type { Env } from "../index";
import { alcOidcToken } from "../lib/alc-data-fetch";

export async function handleHealthProxy(env: Env): Promise<Response> {
  // #434 lockdown: rust は allUsers 削除後 Google OIDC (aud=ALC_API_ORIGIN) を要求する。
  // mint 不可 (SA key 未設定 = lockdown 前) は Authorization 無しで fail-open。
  const oidc = await alcOidcToken(env);
  const res = await fetch(
    `${env.ALC_API_ORIGIN}/api/health`,
    oidc ? { headers: { Authorization: `Bearer ${oidc}` } } : undefined,
  );

  let backend: Record<string, unknown> = {};
  try {
    backend = await res.json() as Record<string, unknown>;
  } catch { /* non-JSON response */ }

  const body = {
    ...backend,
    auth_worker_version: env.VERSION || "dev",
  };

  return new Response(JSON.stringify(body), {
    status: res.status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
