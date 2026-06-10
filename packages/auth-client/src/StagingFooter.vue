<template>
  <div
    v-if="isStaging"
    class="fixed bottom-0 left-0 right-0 bg-yellow-500 text-yellow-900 text-xs px-3 py-1 flex items-center justify-between z-50"
  >
    <span class="font-bold">STAGING</span>
    <span>{{ backendInfo || apiLabel }}</span>

    <!-- Plan summary (staging は毎日新しい plan が動く可能性が高いので常設表示) -->
    <a
      v-if="activePlans.length"
      class="underline hover:no-underline"
      :href="plansLink || 'https://github.com/ippoan/ippoan-dev-plans/issues'"
      target="_blank"
      rel="noopener"
      :title="plansTooltip"
    >
      Plans: {{ plansSummary }}
    </a>

    <div class="flex items-center gap-2">
      <!-- Export -->
      <button
        v-if="tenantId"
        class="px-2 py-0.5 bg-yellow-600 text-white rounded hover:bg-yellow-700 transition-colors"
        :disabled="busy"
        @click="handleExport"
      >
        {{ busy && action === 'export' ? 'Exporting...' : 'Export' }}
      </button>

      <!-- Import -->
      <button
        class="px-2 py-0.5 bg-yellow-600 text-white rounded hover:bg-yellow-700 transition-colors"
        :disabled="busy"
        @click="triggerImport"
      >
        {{ busy && action === 'import' ? 'Importing...' : 'Import' }}
      </button>
      <input
        ref="fileInput"
        type="file"
        accept=".json"
        class="hidden"
        @change="handleImport"
      />

      <!-- Status message -->
      <span v-if="statusMsg" :class="statusOk ? 'text-green-900' : 'text-red-900'">
        {{ statusMsg }}
      </span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'

interface ActivePlan {
  id: string
  stage: string
  scope?: string
}

const props = defineProps<{
  apiBase: string
  tenantId?: string
  /**
   * staging export/import の X-Staging-Key (rust-alc-api#391 の opt-in 認証)。
   * 未指定なら従来どおりヘッダ無しで呼ぶ (backend 側も env 未設定なら無認証)。
   */
  stagingApiKey?: string
  /**
   * auth-worker の /api/version URL。指定すると適用済み plan のサマリを表示する。
   * 取得失敗時は従来表示のみで継続 (graceful degradation)。
   * Refs ippoan/auth-worker#253
   */
  versionUrl?: string
  /** plan サマリクリック時の遷移先。デフォルトは ippoan-dev-plans の issue リスト。 */
  plansLink?: string
}>()

/** X-Staging-Key を opt-in で付与する fetch ヘッダを組み立てる */
function stagingHeaders(extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = { ...(extra ?? {}) }
  if (props.stagingApiKey) headers['X-Staging-Key'] = props.stagingApiKey
  return headers
}

const isStaging = computed(() => props.apiBase.includes('staging'))
const apiLabel = computed(() => props.apiBase.replace('https://', '').split('.')[0] ?? '')
const backendInfo = ref('')

const activePlans = ref<ActivePlan[]>([])

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

  // auth-worker /api/version から適用済み plan を取得 (#253)
  if (props.versionUrl) {
    ;(async () => {
      try {
        const res = await fetch(props.versionUrl as string)
        const v = await res.json() as { active_plans?: ActivePlan[] }
        if (Array.isArray(v.active_plans)) activePlans.value = v.active_plans
      } catch { /* ignore — 従来表示のみで継続 */ }
    })()
  }
}

/** footer 内に出す短いサマリ (先頭 plan + 残数)。全件は title tooltip で見る */
const plansSummary = computed(() => {
  const first = activePlans.value[0]
  if (!first) return ''
  const head = `${first.id} (${first.stage})`
  const rest = activePlans.value.length - 1
  return rest > 0 ? `${head} +${rest}` : head
})

const plansTooltip = computed(() =>
  activePlans.value
    .map((p: ActivePlan) => (p.scope ? `${p.id} (${p.stage}, ${p.scope})` : `${p.id} (${p.stage})`))
    .join('\n')
)

const busy = ref(false)
const action = ref<'export' | 'import' | null>(null)
const statusMsg = ref('')
const statusOk = ref(true)
const fileInput = ref<HTMLInputElement | null>(null)

function clearStatus() {
  setTimeout(() => { statusMsg.value = '' }, 5000)
}

async function handleExport() {
  if (!props.tenantId) return
  busy.value = true
  action.value = 'export'
  statusMsg.value = ''
  try {
    const url = `${props.apiBase}/staging/export?tenant_id=${props.tenantId}`
    const res = await fetch(url, { headers: stagingHeaders() })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const data = await res.json()
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `staging-export-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(a.href)
    statusMsg.value = 'Exported!'
    statusOk.value = true
  } catch (e: any) {
    statusMsg.value = `Export failed: ${e.message}`
    statusOk.value = false
  } finally {
    busy.value = false
    action.value = null
    clearStatus()
  }
}

function triggerImport() {
  fileInput.value?.click()
}

async function handleImport(event: Event) {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0]
  if (!file) return

  busy.value = true
  action.value = 'import'
  statusMsg.value = ''
  try {
    const text = await file.text()
    const res = await fetch(`${props.apiBase}/staging/import`, {
      method: 'POST',
      headers: stagingHeaders({ 'Content-Type': 'application/json' }),
      body: text,
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const result = await res.json() as { counts?: Record<string, number> }
    const counts = result.counts || {}
    const total = Object.values(counts).reduce((a: number, b: any) => a + (b as number), 0)
    statusMsg.value = `Imported ${total} records`
    statusOk.value = true
  } catch (e: any) {
    statusMsg.value = `Import failed: ${e.message}`
    statusOk.value = false
  } finally {
    busy.value = false
    action.value = null
    target.value = ''
    clearStatus()
  }
}
</script>
