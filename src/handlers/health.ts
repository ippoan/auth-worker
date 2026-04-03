import type { Env } from "../index";

export async function handleHealthProxy(env: Env): Promise<Response> {
  const res = await fetch(`${env.ALC_API_ORIGIN}/api/health`);

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
