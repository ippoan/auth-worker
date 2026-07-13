// デプロイ後にブラウザ / Service Worker が古い JS バンドルを配り続ける問題への
// version-tag ベースのキャッシュバスト共通ロジック (Refs ippoan/auth-worker#379)。
//
// consumer 側の薄い client plugin から呼ぶ:
//
//   import { ensureFreshBuild } from '@ippoan/auth-client'
//   declare const __APP_BUILD_VERSION__: string   // nuxt.config の vite.define で焼込み
//   export default defineNuxtPlugin(() => {
//     ensureFreshBuild({
//       buildVersion: __APP_BUILD_VERSION__,
//       serverVersion: String(useRuntimeConfig().public.appVersion ?? ''),
//     })
//   })
//
//   buildVersion  = このバンドルがビルドされた版 (Vite define で焼込み・不変)
//   serverVersion = 現在デプロイ中のサーバの版 (SSR 由来・毎リクエスト新鮮)
//
// 両者が食い違う = 古いバンドルを掴んでいる → SW / CacheStorage を破棄し 1 回だけ
// reload する。reload 後は build == server に収束するので再発火しない。加えて
// sessionStorage の per-server-version ガードで「1 セッション 1 回」に抑え、万一
// 収束しなくても無限 reload を物理的に不可能にする (login ループ再発防止と同発想)。
//
// build 版とサーバ版は consumer 側で「同じ式・同じフォーマット」で解決すること
// (例: 両方 NUXT_PUBLIC_APP_VERSION || GITHUB_SHA)。揃わないと build != server が
// 常時成立して毎セッション 1 回 reload が走るため。どちらかが 'dev' / 空 の時は
// no-op (ローカル開発・未注入ビルドで誤発火させない)。

/** ensureFreshBuild が触るブラウザ API の最小 surface (テスト注入用)。 */
export interface FreshBuildWindow {
  sessionStorage: Pick<Storage, 'getItem' | 'setItem'>
  location: { reload: () => void }
  navigator?: {
    serviceWorker?: {
      getRegistrations?: () => Promise<ReadonlyArray<{ unregister: () => Promise<boolean> }>>
    }
  }
  caches?: { keys: () => Promise<string[]>; delete: (key: string) => Promise<boolean> }
}

export interface EnsureFreshBuildOptions {
  /** このバンドルのビルド版 (Vite define で焼込んだ不変値)。 */
  buildVersion: string
  /** 現在デプロイ中のサーバ版 (runtimeConfig.public.appVersion 等)。 */
  serverVersion: string
  /** sessionStorage キーの namespace (複数アプリの衝突回避)。既定 'authclient'。 */
  namespace?: string
  /** テスト注入用。省略時は本物の `window` (無ければ no-op)。 */
  win?: FreshBuildWindow
}

/**
 * build 版と server 版が食い違う (= 古いバンドルを掴んでいる) 時だけ true を返す純関数。
 * どちらかが空 / 'dev' の時は false (誤発火防止)。
 */
export function isStaleBuild(buildVersion: string, serverVersion: string): boolean {
  const build = (buildVersion ?? '').trim()
  const server = (serverVersion ?? '').trim()
  if (!build || !server) return false
  if (build === 'dev' || server === 'dev') return false
  return build !== server
}

/**
 * 古いバンドルを掴んでいたら SW / CacheStorage を破棄して 1 回だけ reload する。
 * reload をトリガしたら true、しなければ false を返す。SSR / window 不在では no-op。
 */
export async function ensureFreshBuild(opts: EnsureFreshBuildOptions): Promise<boolean> {
  const win: FreshBuildWindow | undefined =
    opts.win ?? (typeof window !== 'undefined' ? (window as unknown as FreshBuildWindow) : undefined)
  if (!win) return false
  if (!isStaleBuild(opts.buildVersion, opts.serverVersion)) return false

  const server = opts.serverVersion.trim()
  const namespace = opts.namespace ?? 'authclient'
  const guardKey = `${namespace}:freshreload:${server}`
  try {
    // この server 版には既に 1 回 reload 済みなら二度としない (無限 reload 防止)
    if (win.sessionStorage.getItem(guardKey)) return false
    win.sessionStorage.setItem(guardKey, '1')
  } catch {
    // sessionStorage 不可 (private mode 等) は安全側で no-op (loop より stale を選ぶ)
    return false
  }

  // SW / CacheStorage を破棄してから hard reload。PWA precache を確実に無効化する。
  try {
    const regs = (await win.navigator?.serviceWorker?.getRegistrations?.()) ?? []
    await Promise.all(regs.map((r) => r.unregister()))
  } catch {
    // 破棄失敗でも reload は行う
  }
  try {
    const caches = win.caches
    const keys = caches ? await caches.keys() : []
    await Promise.all(keys.map((k) => caches!.delete(k)))
  } catch {
    // 破棄失敗でも reload は行う
  }
  win.location.reload()
  return true
}
