<template>
  <div class="flex items-center gap-1">
    <!-- Org switcher (multiple orgs) -->
    <div
      v-if="showOrgSlug && isAuthenticated && isMultiOrg && ownerType !== 'personal'"
      class="relative org-switcher"
    >
      <button
        @click="toggleOrgMenu"
        class="text-xs px-1.5 py-0.5 rounded bg-purple-100 text-purple-700
               whitespace-nowrap hover:bg-purple-200 transition-colors cursor-pointer
               flex items-center gap-0.5"
      >
        {{ orgSlug }}
        <span class="text-[10px]">&#9660;</span>
      </button>
      <div
        v-if="orgMenuOpen"
        class="absolute right-0 top-full mt-1 bg-white border rounded shadow-lg
               z-50 min-w-[160px] py-1"
      >
        <button
          v-for="org in organizations"
          :key="org.id"
          @click="handleSwitchOrg(org.id)"
          class="w-full px-3 py-1.5 text-left text-sm hover:bg-gray-100
                 flex items-center justify-between"
          :class="{ 'font-bold bg-purple-50': org.id === orgId }"
        >
          {{ org.slug }}
          <span v-if="org.id === orgId" class="text-purple-600 text-xs">&#10003;</span>
        </button>
      </div>
    </div>

    <!-- Org slug display (single org) -->
    <span
      v-else-if="showOrgSlug && isAuthenticated && orgSlug && ownerType !== 'personal'"
      class="text-xs px-1.5 py-0.5 rounded bg-purple-100 text-purple-700 whitespace-nowrap"
    >
      {{ orgSlug }}
    </span>

    <!-- User info display -->
    <span
      v-if="showUserInfo && isAuthenticated && username"
      class="text-sm text-gray-600 truncate max-w-[200px]"
      :title="username"
    >
      {{ displayUsername }}
    </span>
    <span
      v-if="showUserInfo && isAuthenticated && providerLabel"
      class="text-xs px-1.5 py-0.5 rounded whitespace-nowrap"
      :class="{
        'bg-blue-100 text-blue-700': provider === 'google',
        'bg-green-100 text-green-700': provider === 'lineworks',
        'bg-gray-100 text-gray-600': provider === 'password',
      }"
    >
      {{ providerLabel }}
    </span>

    <component
      v-if="showCopyUrl && hasLwDomain"
      :is="uButton"
      v-bind="buttonProps"
      @click="handleCopyUrl"
    >
      {{ copyLabel }}
    </component>

    <div v-if="showQr && isAuthenticated" class="relative qr-popover">
      <component
        :is="uButton"
        v-bind="buttonProps"
        @click="qrOpen = !qrOpen"
      >
        QR
      </component>
      <div
        v-if="qrOpen"
        class="absolute right-0 top-full mt-1 bg-white border rounded-lg shadow-lg z-50 p-4"
        style="width: 288px"
      >
        <div
          class="flex justify-center"
          style="max-width: 240px; margin: 0 auto"
          v-html="qrSvg"
        />
        <p class="mt-2 text-[10px] text-gray-400 text-center break-all leading-tight">{{ qrUrl }}</p>
      </div>
    </div>

    <component
      v-if="showApps"
      :is="uButton"
      v-bind="buttonProps"
      @click="handleOpenApps"
    >
      Apps
    </component>

    <component
      v-if="showSettings"
      :is="uButton"
      v-bind="buttonProps"
      @click="handleOpenSettings"
    >
      設定
    </component>

    <component
      v-if="showLogout"
      :is="uButton"
      v-bind="buttonProps"
      @click="handleLogout"
    >
      Logout
    </component>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, resolveComponent, onMounted, onUnmounted } from 'vue'
import { renderSVG } from 'uqr'
import { useAuth } from './useAuth'

const props = withDefaults(defineProps<{
  showCopyUrl?: boolean
  showQr?: boolean
  showApps?: boolean
  showSettings?: boolean
  showLogout?: boolean
  showUserInfo?: boolean
  showOrgSlug?: boolean
}>(), {
  showCopyUrl: true,
  showQr: true,
  showApps: true,
  showSettings: true,
  showLogout: true,
  showUserInfo: true,
  showOrgSlug: false,
})

const emit = defineEmits<{
  (e: 'copy-url', success: boolean): void
  (e: 'logout'): void
  (e: 'open-settings', url: string): void
  (e: 'switch-org', orgId: string): void
}>()

const {
  logout, copyLwLoginUrl, getAppsUrl, getSettingsUrl, getLwDomain, getAutoLoginUrl,
  isAuthenticated, username, provider, providerLabel, orgSlug, orgId, ownerType,
  organizations, isMultiOrg, switchOrganization,
} = useAuth()

const hasLwDomain = computed(() => !!getLwDomain())
const orgMenuOpen = ref(false)
const switching = ref(false)
const qrOpen = ref(false)

const qrUrl = computed(() => {
  if (typeof window === 'undefined') return ''
  return getAutoLoginUrl()
})

const qrSvg = computed(() => {
  if (!qrUrl.value) return ''
  const svg = renderSVG(qrUrl.value, { border: 2, ecc: 'M', pixelSize: 4 })
  return svg.replace('<svg ', '<svg style="width:100%;height:auto" ')
})

function toggleOrgMenu() {
  orgMenuOpen.value = !orgMenuOpen.value
}

function handleClickOutside(e: MouseEvent) {
  const target = e.target as HTMLElement
  if (!target.closest('.org-switcher')) orgMenuOpen.value = false
  if (!target.closest('.qr-popover')) qrOpen.value = false
}

onMounted(() => document.addEventListener('click', handleClickOutside))
onUnmounted(() => document.removeEventListener('click', handleClickOutside))

async function handleSwitchOrg(targetOrgId: string) {
  orgMenuOpen.value = false
  if (targetOrgId === orgId.value || switching.value) return
  switching.value = true
  emit('switch-org', targetOrgId)
  const success = await switchOrganization(targetOrgId)
  if (success) {
    window.location.reload()
  }
  switching.value = false
}

/** メールアドレスの場合は@以前だけ表示 */
const displayUsername = computed(() => {
  const name = username.value
  if (!name) return ''
  if (name.includes('@')) return name.split('@')[0]
  return name
})

const uButton = computed(() => {
  const resolved = resolveComponent('UButton')
  return typeof resolved === 'string' ? 'button' : resolved
})

const buttonProps = computed(() => {
  if (typeof uButton.value === 'string') {
    return { class: 'px-2 py-1 text-sm border rounded' }
  }
  return { color: 'gray' as const }
})

const copyLabel = ref('URL共有')

async function handleCopyUrl() {
  const success = await copyLwLoginUrl()
  emit('copy-url', success)
  if (success) {
    copyLabel.value = 'Copied!'
    setTimeout(() => { copyLabel.value = 'URL共有' }, 2000)
  }
}

function handleLogout() {
  emit('logout')
  logout()
}

function handleOpenApps() {
  window.open(getAppsUrl(), '_blank')
}

function handleOpenSettings() {
  const url = getSettingsUrl()
  emit('open-settings', url)
  window.open(url, '_blank')
}
</script>
