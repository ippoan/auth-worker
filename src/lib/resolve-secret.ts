/**
 * Cloudflare Secrets Store binding と legacy Worker secret (string) の
 * 両方を受け取って string に正規化する共通ヘルパ。
 *
 * 2026-05-25 (Refs ippoan/auth-worker#205 / 同 hotfix) で `GOOGLE_CLIENT_ID`
 * 等多数の secret を Workers secret → CF Secrets Store binding に移行したが、
 * 移行直後は code 側がまだ binding を素の string として扱っていた。結果として
 * `URL.searchParams.set("client_id", env.GOOGLE_CLIENT_ID)` のような呼び出しが
 * `[object Fetcher]` を URL に乗せて Google OAuth が 401 invalid_client で死亡
 * (production)。
 *
 * 解決策: 使う側で **必ずこの helper 経由で string 化する**。
 *
 * - `string` (legacy `wrangler secret put` / vitest) → そのまま return
 * - `SecretsStoreSecret` (account-level binding、`.get()` 持ち) → resolve
 * - `undefined` / `.get()` 失敗 → `null` (上位 handler は 500 / 503 を返す)
 *
 * MCP 用の専用ヘルパ (`resolveMcpJwtSecret`) と挙動は等価。今後新規 secret を
 * 追加する場合もこの generic 版で済むが、既存の `resolveMcpJwtSecret` 呼び出しは
 * 安定性のため当面そのままにする (lib/mcp-jwt.ts 参照)。
 */
export type SecretBinding = string | SecretsStoreSecret | undefined;

export async function resolveSecret(
  binding: SecretBinding,
): Promise<string | null> {
  if (!binding) return null;
  if (typeof binding === "string") return binding;
  try {
    const value = await binding.get();
    return value ?? null;
  } catch {
    return null;
  }
}
