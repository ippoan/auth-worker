<template>
  <div
    v-if="isStaging"
    class="fixed bottom-0 left-0 right-0 bg-yellow-500 text-yellow-900 text-xs px-3 py-1 flex items-center justify-between z-50"
  >
    <span class="font-bold">STAGING</span>
    <span>{{ backendInfo || apiLabel }}</span>

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

const props = defineProps<{
  apiBase: string
  tenantId?: string
}>()

const isStaging = computed(() => props.apiBase.includes('staging'))
const apiLabel = computed(() => props.apiBase.replace('https://', '').split('.')[0] ?? '')
const backendInfo = ref('')

// /api/health から SHA + PR 名を取得
if (typeof window !== 'undefined') {
  fetch(`${props.apiBase}/api/health`).then(r => r.json()).then(h => {
    const parts = []
    if (h.git_sha && h.git_sha !== 'dev') parts.push(h.git_sha)
    if (h.git_ref) parts.push(h.git_ref)
    if (parts.length) backendInfo.value = parts.join(' — ')
  }).catch(() => {})
}

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
    const res = await fetch(url)
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
      headers: { 'Content-Type': 'application/json' },
      body: text,
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const result = await res.json()
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
