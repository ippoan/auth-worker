/**
 * happy-dom 対策: Node.js native API を退避
 *
 * vitest.config.ts の setupFiles の先頭に配置:
 *   setupFiles: ['@ippoan/test-utils/src/save-native.ts', ...]
 *
 * happy-dom が globalThis.FormData/Blob/URL を上書きする前に退避し、
 * live テスト時に restoreNativeApis() で復元する。
 */
;(globalThis as any).__nativeFormData = globalThis.FormData
;(globalThis as any).__nativeBlob = globalThis.Blob
;(globalThis as any).__nativeURL = globalThis.URL

/**
 * live テスト時に happy-dom の API を Node.js native に戻す。
 * setupApi() の先頭で呼ぶ。
 */
export function restoreNativeApis(): void {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  globalThis.Blob = require('node:buffer').Blob
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  globalThis.URL = require('node:url').URL
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const undici = require('undici')
  globalThis.FormData = undici.FormData
  globalThis.fetch = undici.fetch
}
