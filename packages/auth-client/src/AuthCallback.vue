<template>
  <div class="w-full max-w-sm mx-auto rounded-lg border border-gray-200 bg-white p-6 shadow">
    <div class="text-center space-y-4">
      <template v-if="error">
        <p class="text-red-600">{{ error }}</p>
        <slot name="error-action">
          <a
            :href="loginPath"
            class="inline-block px-3 py-1.5 text-sm border rounded text-gray-700 hover:bg-gray-50"
          >ログインに戻る</a>
        </slot>
      </template>
      <template v-else>
        <div
          class="mx-auto h-12 w-12 animate-spin rounded-full border-4 border-gray-300 border-t-transparent"
        />
        <p class="text-gray-500">認証中...</p>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
/**
 * auth-worker リダイレクト後の callback ページ本体。
 * URL fragment の token を consumeFragment() で保存し、成功なら redirectTo へ遷移する。
 * nuxt-dtako-admin ↔ nuxt-trouble の `pages/auth/callback.vue` コピーを 1 本化
 * (Refs ippoan/auth-worker#257)。消費側 page:
 *
 * ```vue
 * <script setup lang="ts">
 * definePageMeta({ layout: 'auth' })
 * <\/script>
 * <template><AuthCallback redirect-to="/operations" /></template>
 * ```
 */
import { ref, onMounted } from 'vue'
import { navigateTo } from '#imports'
import { useAuth } from './useAuth'

const props = withDefaults(
  defineProps<{
    /** 認証成功時の遷移先 */
    redirectTo?: string
    /** 失敗時「ログインに戻る」リンクの遷移先 */
    loginPath?: string
    /** 失敗時のメッセージ */
    errorMessage?: string
  }>(),
  {
    redirectTo: '/',
    loginPath: '/login',
    errorMessage: '認証に失敗しました。再度ログインしてください。',
  },
)

const { consumeFragment } = useAuth()
const error = ref<string | null>(null)

onMounted(() => {
  const success = consumeFragment()
  if (success) {
    void navigateTo(props.redirectTo)
  } else {
    error.value = props.errorMessage
  }
})
</script>
