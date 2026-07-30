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
 * 現在の責務は chunk load 失敗からの自動復旧 (Refs ippoan/nuxt-trouble#236)。
 * これを consumer 側の手書き plugin にすると `experimental.emitRouteChunkError`
 * の設定漏れで**対策が黙って無効化される**ため、module 側で一括して面倒を見る。
 */
import { addPlugin, createResolver, defineNuxtModule } from '@nuxt/kit'

export interface AuthClientModuleOptions {
  /** chunk load 失敗時の自動復旧を有効にする (既定 true)。 */
  chunkReload?: boolean
}

export default defineNuxtModule<AuthClientModuleOptions>({
  meta: {
    name: '@ippoan/auth-client',
    configKey: 'ippoanAuthClient',
  },
  defaults: {
    chunkReload: true,
  },
  setup(options, nuxt) {
    if (!options.chunkReload) return

    // Nuxt 既定の 'automatic' は素のリロードをするだけで HTTP キャッシュを
    // バイパスしないため、immutable キャッシュに焼き付いた 404 を消せない。
    // plugin 側に制御を渡す。
    nuxt.options.experimental.emitRouteChunkError = 'manual'

    // auth-client は .ts をそのまま ship するので consumer 側で transpile が要る。
    // 既に consumer が宣言済みのケースが多いので重複は足さない。
    if (!nuxt.options.build.transpile.includes('@ippoan/auth-client')) {
      nuxt.options.build.transpile.push('@ippoan/auth-client')
    }

    const { resolve } = createResolver(import.meta.url)
    addPlugin({ src: resolve('./runtime/chunkReload.client.ts'), mode: 'client' })
  },
})
