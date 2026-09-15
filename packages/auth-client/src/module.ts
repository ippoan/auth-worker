/**
 * `@ippoan/auth-client/module` — consumer の nuxt.config に 1 行足すだけで
 * 有効になる Nuxt module。
 *
 * ```ts
 * export default defineNuxtConfig({
 *   modules: ['@ippoan/auth-client/module'],
 * })
 * ```
 *
 * 責務は 2 つ:
 * - chunk load 失敗からの自動復旧 (Refs ippoan/nuxt-trouble#236)。
 *   これを consumer 側の手書き plugin にすると `experimental.emitRouteChunkError`
 *   の設定漏れで**対策が黙って無効化される**ため、module 側で一括して面倒を見る。
 * - (opt-in, issue #560) SSR で `logi_auth_token` cookie から認証状態を決めて
 *   `useState('auth')` に載せる server plugin の追加。
 */
import { addPlugin, createResolver, defineNuxtModule } from '@nuxt/kit'

export interface AuthClientModuleOptions {
  /** chunk load 失敗時の自動復旧を有効にする (既定 true)。 */
  chunkReload?: boolean
  /**
   * SSR 時に `logi_auth_token` cookie から認証状態を決めて `useState('auth')` に
   * 載せる server plugin を有効にする (既定 **false**)。consumer が
   * `ippoanAuthClient: { authState: true }` で opt-in する。
   *
   * 有効にすると:
   * - server が cookie から `expiresAt` / `orgId` / `username` 等を決めて SSR
   *   payload に載せるため、client の `loadFromStorage` が hydrate 済みの
   *   state を localStorage の古いコピーで上書きしなくなる (#559 の穴の恒久対策)。
   * - payload には生 JWT を載せない (`token: ''`)。Bearer 送信用の token は
   *   client 側で cookie から補う。
   * - fragment 配送 (`#token=`) / `?lw_callback=1` の判断は従来どおり client。
   *
   * 段階投入・rollback 可を優先するため既定 off。全 consumer で確認後に
   * 既定を反転する予定 (#560)。
   */
  authState?: boolean
}

export default defineNuxtModule<AuthClientModuleOptions>({
  meta: {
    name: '@ippoan/auth-client',
    configKey: 'ippoanAuthClient',
  },
  defaults: {
    chunkReload: true,
    authState: false,
  },
  setup(options, nuxt) {
    if (options.chunkReload || options.authState) {
      // auth-client は .ts をそのまま ship するので consumer 側で transpile が要る。
      // 既に consumer が宣言済みのケースが多いので重複は足さない。
      if (!nuxt.options.build.transpile.includes('@ippoan/auth-client')) {
        nuxt.options.build.transpile.push('@ippoan/auth-client')
      }
    }

    const { resolve } = createResolver(import.meta.url)

    if (options.chunkReload) {
      // Nuxt 既定の 'automatic' は素のリロードをするだけで HTTP キャッシュを
      // バイパスしないため、immutable キャッシュに焼き付いた 404 を消せない。
      // plugin 側に制御を渡す。
      nuxt.options.experimental.emitRouteChunkError = 'manual'
      addPlugin({ src: resolve('./runtime/chunkReload.client.ts'), mode: 'client' })
    }

    if (options.authState) {
      addPlugin({ src: resolve('./runtime/authState.server.ts'), mode: 'server' })
    }
  },
})
