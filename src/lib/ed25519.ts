/**
 * Ed25519 signature verification (issue #522, 警告デバイス device-login)。
 *
 * WebCrypto (`crypto.subtle.importKey('raw', ..., {name:'Ed25519'})` /
 * `crypto.subtle.verify('Ed25519', ...)`) が本番の workerd (`compatibility_date`
 * 変更なし) で正しく動くことを、`@cloudflare/vitest-pool-workers` を使わず
 * miniflare 直叩き (本番と同じ compatibility_date/flags) で実測済み — 標準 API
 * だけで足り、`@noble/ed25519` の追加は不要だった (auth-worker#522 [完了] 参照)。
 * この repo の通常テストは node pool で走るが、Node の `crypto.subtle` も同じ
 * WebCrypto Ed25519 API を実装しているため、ここの unit test はそのまま node で
 * 意味を持つ。
 */

/** raw 公開鍵 (32 B) で `sig` (64 B) が `message` の正当な Ed25519 署名か検証する。
 *  鍵長/署名長不正・import 失敗・不一致はすべて `false` (fail-closed、例外を投げない)。 */
export async function verifyEd25519(
  pubkeyRaw: Uint8Array,
  sig: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  if (pubkeyRaw.length !== 32 || sig.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      pubkeyRaw,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify("Ed25519", key, sig, message);
  } catch {
    return false;
  }
}
