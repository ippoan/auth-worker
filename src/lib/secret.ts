/**
 * Generic CF Secrets Store binding resolver.
 *
 * `wrangler.toml` の `[[secrets_store_secrets]]` binding は production deploy では
 * `{ get(): Promise<string> }` (`SecretsStoreSecret`) として注入されるが、vitest /
 * `wrangler dev` は同名を **plain string** で渡す。両形態を共通化して `string | null`
 * に正規化することで、呼び出し側は `if (!value) return 503` の 1 分岐で扱える。
 *
 * `resolveMcpJwtSecret()` (`./mcp-jwt.ts`) と同じパターンを generic 化したもの。
 * MCP_JWT_SECRET 固有 helper は引き続き残し、内部で本 helper を呼ぶ薄ラッパーにする
 * (後方互換維持)。
 *
 * Refs #206: PR #205 で `.dev.vars` 由来 7 secret を Secrets Store binding に
 * 移行したが、consumer 側は `env.X` を string として直叩きしていたため
 * `[object Fetcher]` が Google OAuth / GitHub webhook 等に流れていた。
 */

export type SecretBinding = string | SecretsStoreSecret | undefined;

/**
 * 3 形態を共通化して `string | null` を返す。
 *
 *   - `undefined` / falsy → `null`
 *   - `string` (vitest / `wrangler dev`) → そのまま
 *   - `SecretsStoreSecret` (`.get()` 持ち) → 解決して return
 *   - `.get()` throw / 空文字 → `null`
 *
 * 呼び出し側は `null` を「未 bind or 取得失敗」として 503 / fail-closed 扱いに統一する。
 */
export async function resolveSecret(
  binding: SecretBinding,
): Promise<string | null> {
  if (!binding) return null;
  if (typeof binding === "string") return binding;
  try {
    const value = await binding.get();
    return value || null;
  } catch {
    return null;
  }
}
