/**
 * Cloudflare Access 向け OIDC surface の path / issuer 定義。
 *
 * issuer を `<origin>/oidc` と **path 付き**にするのは、既存の MCP surface
 * (issuer = `<origin>`) と衝突させないため。同じ origin で 2 つの AS を名乗る形に
 * なるので、issuer が別であることが両者を分ける唯一の識別子になる。
 */
import type { Env } from "../index";

export const OIDC_SURFACE_PATH = "/oidc";

/** 本 surface の issuer (`id_token.iss` と discovery の `issuer`)。 */
export function oidcIssuer(env: Env): string {
  const origin = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
  return `${origin}${OIDC_SURFACE_PATH}`;
}
