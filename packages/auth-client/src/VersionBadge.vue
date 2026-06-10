<template>
  <div
    class="fixed bottom-0 right-0 text-xs px-2 py-0.5 rounded-tl opacity-60 hover:opacity-100 transition-opacity z-40"
    :class="[
      isStaging ? 'bg-yellow-500 text-yellow-900' : 'bg-gray-700 text-gray-300',
      activePlans.length ? 'cursor-pointer' : '',
    ]"
    :title="tooltip"
    @click="openPlans"
  >
    <span>{{ label }}</span>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'

interface ActivePlan {
  id: string
  stage: string
  scope?: string
}

const props = defineProps<{
  apiBase?: string
  healthUrl?: string
  frontendVersion?: string
  /**
   * auth-worker の /api/version URL (例: `https://auth.ippoan.org/api/version`)。
   * 指定すると適用済み plan の stage を tooltip に追加表示する。
   * 取得失敗時は version 表示のみで継続する (graceful degradation)。
   * Refs ippoan/auth-worker#253
   */
  versionUrl?: string
  /** plan 一覧クリック時の遷移先。デフォルトは ippoan-dev-plans の issue リスト。 */
  plansLink?: string
}>()

const isStaging = computed(() =>
  (props.apiBase || '').includes('staging') || (props.healthUrl || '').includes('staging')
)

const backendVersion = ref('')
const backendSha = ref('')
const backendRef = ref('')
const authWorkerVersion = ref('')
const activePlans = ref<ActivePlan[]>([])

/** tooltip に出す plan の最大件数 (超過分は「他N件」に畳む) */
const MAX_PLANS_SHOWN = 5

onMounted(async () => {
  const url = props.healthUrl || (props.apiBase ? `${props.apiBase}/api/health` : '')
  if (url) {
    try {
      const res = await fetch(url)
      const h = await res.json() as Record<string, string>
      backendVersion.value = h.version || ''
      backendSha.value = h.git_sha || ''
      backendRef.value = h.git_ref || ''
      authWorkerVersion.value = h.auth_worker_version || ''
    } catch { /* ignore */ }
  }

  if (props.versionUrl) {
    try {
      const res = await fetch(props.versionUrl)
      const v = await res.json() as { auth_worker_version?: string; active_plans?: ActivePlan[] }
      if (Array.isArray(v.active_plans)) activePlans.value = v.active_plans
      if (!authWorkerVersion.value && v.auth_worker_version) {
        authWorkerVersion.value = v.auth_worker_version
      }
    } catch { /* ignore — version 表示のみで継続 */ }
  }
})

const label = computed(() => {
  const fe = props.frontendVersion || 'dev'
  const be = backendVersion.value || backendSha.value || '...'
  const aw = authWorkerVersion.value
  return aw ? `FE:${fe} / BE:${be} / AW:${aw}` : `FE:${fe} / BE:${be}`
})

/** plan 1 件を `- <id> (<stage>[, <scope>])` 形式に整形 */
function formatPlan(p: ActivePlan): string {
  return p.scope ? `- ${p.id} (${p.stage}, ${p.scope})` : `- ${p.id} (${p.stage})`
}

const tooltip = computed(() => {
  const parts: string[] = [`Frontend: ${props.frontendVersion || 'dev'}`]
  if (backendVersion.value) parts.push(`Backend: ${backendVersion.value}`)
  if (backendSha.value) parts.push(`SHA: ${backendSha.value}`)
  if (backendRef.value) parts.push(`Ref: ${backendRef.value}`)
  if (authWorkerVersion.value) parts.push(`Auth Worker: ${authWorkerVersion.value}`)
  if (activePlans.value.length) {
    parts.push('')
    parts.push('Active plans:')
    for (const p of activePlans.value.slice(0, MAX_PLANS_SHOWN)) {
      parts.push(formatPlan(p))
    }
    const rest = activePlans.value.length - MAX_PLANS_SHOWN
    if (rest > 0) parts.push(`他${rest}件`)
  }
  return parts.join('\n')
})

function openPlans(): void {
  if (!activePlans.value.length) return
  const link = props.plansLink || 'https://github.com/ippoan/ippoan-dev-plans/issues'
  window.open(link, '_blank', 'noopener')
}
</script>
