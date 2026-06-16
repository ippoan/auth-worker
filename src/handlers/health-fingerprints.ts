import type { Env } from "../index";

/**
 * `GET /health/secret-fingerprint?name=<binding>&expected=<8hex>` —
 * auth-worker isolate が runtime に解決した任意 env / Secrets Store binding の
 * 値の sha256 prefix が `expected` と一致するかを `{ "match": bool }` で返す。
 *
 * 用途: cross-store drift (= CF Secrets Store と GCP Secret Manager で同名
 * secret の値が乖離) の CI 自動検出。caller 側 (`ippoan/ci-workflows`
 * `drift-check.yml`) が GCP SM から値を読んで `sha256[0..8]` を計算し、本
 * endpoint を叩いて `match: true` を assert する。
 *
 * 値の hex を返さない (oracle 防止):
 *   - env 不在 / 値違い / typo を全て `match: false` に集約 → name 列挙不可
 *   - timing-safe compare (`crypto.subtle.timingSafeEqual`)
 *
 * 認証なし (= CCoW / CI runner から curl 一発で叩ける):
 *   - `expected` は 32 bit の sha256 prefix なので preimage 不可
 *   - binding 名は `wrangler.toml` で既に公開
 *   - 攻撃者にとっての追加情報は実質ゼロ
 *
 * Refs ippoan/auth-worker#274 / ippoan/email-receiver#1.
 */
export async function handleSecretFingerprint(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const name = url.searchParams.get("name");
  const expected = url.searchParams.get("expected");

  // input validation。形式違反は 400 で reject (= 200/match:false に丸めない)。
  // 不正 query は drift とは別の class of bug なので CI に切り分けさせたい。
  if (!name || !/^[A-Za-z][A-Za-z0-9_]{0,254}$/.test(name)) {
    return jsonResponse({ error: "invalid name" }, 400);
  }
  if (!expected || !/^[0-9a-f]{8}$/.test(expected)) {
    return jsonResponse({ error: "invalid expected" }, 400);
  }

  const value = await resolveSecretBinding(
    (env as unknown as Record<string, unknown>)[name],
  );
  const actual = value ? await sha256Prefix(value) : "";

  // env 不在 / 値違い / typo を全て match:false に集約 (= oracle 不可)。
  // 8 文字 hex の constant-time 比較。
  const match = actual !== "" && timingSafeEqualHex(actual, expected);
  return jsonResponse({ match }, 200);
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
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

/**
 * Timing-safe equality on two pre-validated 8-char hex strings.
 * Both args are required to be `/^[0-9a-f]{8}$/` so length is constant by
 * construction; we only need to defeat short-circuit byte comparison.
 */
function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
