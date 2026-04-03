import type { Env } from "../index";

export async function handleHealthProxy(env: Env): Promise<Response> {
  const res = await fetch(`${env.ALC_API_ORIGIN}/api/health`);
  return new Response(res.body, {
    status: res.status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
