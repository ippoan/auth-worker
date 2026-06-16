import type { Env } from "../index";

/**
 * `GET /health/internal-secret-fingerprints` — auth-worker isolate が runtime に
 * 解決した全 `INTERNAL_SHARED_SECRET*` binding の非可逆 fingerprint を返す。
 *
 * 用途: cross-store drift (= CF Secrets Store と GCP Secret Manager で同名 secret
 * の値が乖離しているケース) の切り分け。consumer (email-receiver / rust-alc-api
 * 等) が同じ binding の sha256 prefix を log に出せば、auth-worker のこの endpoint
 * の prefix と突き合わせて runtime レベルで一致/不一致を判定できる。
 *
 * 値そのものは context にも response にも一切載せない:
 *   - hex 8 文字 = 32 bit、SHA-256 の prefix なので不可逆 (preimage 不可能)
 *   - length / head / tail は出さない (partial leak になるため)
 *
 * 認証なし (公開) で問題ないか:
 *   - prefix 8 文字単独では値復元できない
 *   - binding 名 (`INTERNAL_SHARED_SECRET` etc.) は wrangler.toml に書かれており既に公開
 *   - 攻撃者にとっての追加情報は実質ゼロ
 *
 * Refs ippoan/email-receiver#1 (epic の 401 切り分けで drift 検知に使用)。
 */
export async function handleHealthFingerprints(env: Env): Promise<Response> {
  const bindings: Record<string, string> = {};

  for (const key of Object.keys(env)) {
    if (!key.startsWith("INTERNAL_SHARED_SECRET")) continue;
    const value = await resolveSecretBinding(
      (env as unknown as Record<string, unknown>)[key],
    );
    if (value) {
      bindings[key] = await sha256Prefix(value);
    }
  }

  const body = {
    auth_worker_version: env.VERSION || "dev",
    bindings,
  };

  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

async function resolveSecretBinding(binding: unknown): Promise<string | null> {
  if (!binding) return null;
  if (typeof binding === "string") return binding;
  if (
    typeof binding === "object" && binding !== null &&
    typeof (binding as { get?: unknown }).get === "function"
  ) {
    try {
      return await (binding as { get: () => Promise<string> }).get();
    } catch {
      return null;
    }
  }
  return null;
}

async function sha256Prefix(input: string): Promise<string> {
  const buf = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hex.slice(0, 8);
}
