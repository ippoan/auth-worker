/**
 * chunk (`/_nuxt/*.js`) の load 失敗を検知して自動復旧する Nuxt client plugin。
 *
 * `@ippoan/auth-client/module` (Nuxt module) が addPlugin で注入する。判断ロジックは
 * `../chunkReload` 側に置き、ここは DOM / Nuxt との wiring だけを持つ
 * (auth-client の vitest は pure Node なので DOM 依存はテスト対象外)。
 *
 * 背景と対策の理由は `../chunkReload` の doc comment を参照
 * (Refs ippoan/nuxt-trouble#236)。
 */
import { defineNuxtPlugin } from '#imports'
import {
  CHUNK_RELOAD_STORAGE_KEY,
  chunkErrorMessage,
  extractChunkUrl,
  isChunkLoadErrorMessage,
  recoverFromChunkError,
  type ChunkReloadDeps,
} from '../chunkReload'

/** 諦めた旨を出す要素の id (二重挿入の抑止に使う)。 */
const FALLBACK_ID = 'ippoan-chunk-reload-fallback'

const FALLBACK_STYLE =
  'position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;' +
  'padding:1.5rem;text-align:center;background:#ffffff;color:#111111;font-size:1rem;line-height:1.6'

/** 自動復旧を諦めた旨を画面に出す (真っ暗のまま放置しない)。 */
function renderFallback(message: string): void {
  if (document.getElementById(FALLBACK_ID)) return

  const el = document.createElement('div')
  el.id = FALLBACK_ID
  el.setAttribute('style', FALLBACK_STYLE)
  el.textContent = message
  document.body.appendChild(el)
}

export default defineNuxtPlugin((nuxtApp) => {
  // 同じ失敗で複数の hook / event が同時に飛ぶため、復旧は 1 本に絞る。
  let recovering = false

  const deps: ChunkReloadDeps = {
    now: () => Date.now(),
    getItem: (key) => window.sessionStorage.getItem(key),
    setItem: (key, value) => window.sessionStorage.setItem(key, value),
    refetch: async (url) => {
      await fetch(url, { cache: 'reload' })
    },
    reload: () => window.location.reload(),
    giveUp: (message) => {
      console.error('[auth-client] chunk-reload:', message, `(${CHUNK_RELOAD_STORAGE_KEY})`)
      renderFallback(message)
    },
  }

  /** chunk load 失敗が確定している入口 (原因判定を通さない)。 */
  function recover(error: unknown) {
    if (recovering) return
    recovering = true
    void recoverFromChunkError(extractChunkUrl(chunkErrorMessage(error)), deps).then(
      (result) => {
        // 諦めた後は時間窓が明ければ再度自動復旧できるよう guard を解く。
        if (result === 'gave-up') recovering = false
      },
    )
  }

  nuxtApp.hook('app:chunkError', ({ error }: { error: Error }) => recover(error))

  window.addEventListener('vite:preloadError', (event) => {
    recover((event as Event & { payload?: unknown }).payload)
  })

  // chunk と無関係な reject も飛んでくるので、ここだけは原因を判定してから拾う。
  window.addEventListener('unhandledrejection', (event) => {
    if (isChunkLoadErrorMessage(chunkErrorMessage(event.reason))) recover(event.reason)
  })
})
