<template>
  <div
    class="fixed bottom-0 right-0 text-xs px-2 py-0.5 rounded-tl opacity-60 hover:opacity-100 transition-opacity z-40"
    :class="isStaging ? 'bg-yellow-500 text-yellow-900' : 'bg-gray-700 text-gray-300'"
    :title="tooltip"
  >
    <span>{{ label }}</span>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'

const props = defineProps<{
  apiBase?: string
  healthUrl?: string
  frontendVersion?: string
}>()

const isStaging = computed(() =>
  (props.apiBase || '').includes('staging') || (props.healthUrl || '').includes('staging')
)

const backendVersion = ref('')
const backendSha = ref('')
const backendRef = ref('')
const authWorkerVersion = ref('')

onMounted(async () => {
  const url = props.healthUrl || (props.apiBase ? `${props.apiBase}/api/health` : '')
  if (!url) return
  try {
    const res = await fetch(url)
    const h = await res.json()
    backendVersion.value = h.version || ''
    backendSha.value = h.git_sha || ''
    backendRef.value = h.git_ref || ''
    authWorkerVersion.value = h.auth_worker_version || ''
  } catch { /* ignore */ }
})

const label = computed(() => {
  const fe = props.frontendVersion || 'dev'
  const be = backendVersion.value || backendSha.value || '...'
  const aw = authWorkerVersion.value
  return aw ? `FE:${fe} / BE:${be} / AW:${aw}` : `FE:${fe} / BE:${be}`
})

const tooltip = computed(() => {
  const parts = [`Frontend: ${props.frontendVersion || 'dev'}`]
  if (backendVersion.value) parts.push(`Backend: ${backendVersion.value}`)
  if (backendSha.value) parts.push(`SHA: ${backendSha.value}`)
  if (backendRef.value) parts.push(`Ref: ${backendRef.value}`)
  if (authWorkerVersion.value) parts.push(`Auth Worker: ${authWorkerVersion.value}`)
  return parts.join('\n')
})
</script>
