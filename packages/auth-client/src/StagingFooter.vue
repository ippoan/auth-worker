<template>
  <div
    v-if="isStaging"
    class="fixed bottom-0 left-0 right-0 bg-yellow-500 text-yellow-900 text-xs px-3 py-1 flex items-center justify-between z-50"
  >
    <span class="font-bold">STAGING</span>
    <span>{{ backendInfo || apiLabel }}</span>
    <span />
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'

const props = defineProps<{
  apiBase: string
  /**
   * @deprecated 使わない。Export / Import のボタンは rust-alc-api の staging export / import と一緒に消した
   * (Refs ippoan/rust-alc-api#680)。呼び手の型を壊さないよう受けるだけ残す。
   */
  tenantId?: string
  /** @deprecated 同上 (staging export / import の X-Staging-Key。rust-alc-api#391) */
  stagingApiKey?: string
}>()

const isStaging = computed(() => props.apiBase.includes('staging'))
const apiLabel = computed(() => props.apiBase.replace('https://', '').split('.')[0] ?? '')
const backendInfo = ref('')

// /api/health から SHA + PR 名を取得
if (typeof window !== 'undefined') {
  ;(async () => {
    try {
      const res = await fetch(`${props.apiBase}/api/health`)
      const h = await res.json() as Record<string, string>
      const parts: string[] = []
      if (h.git_sha && h.git_sha !== 'dev') parts.push(h.git_sha)
      if (h.git_ref) parts.push(h.git_ref)
      if (parts.length) backendInfo.value = parts.join(' — ')
    } catch { /* ignore */ }
  })()
}
</script>
