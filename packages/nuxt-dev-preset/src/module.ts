/**
 * @ippoan/nuxt-dev-preset
 *
 * Nuxt module that reads `.ippoan-dev.yaml` from the project root and
 * configures dev-time settings so that accessing the app through the
 * dev-proxy subdomain (`https://<name>-dev.ippoan.org`) works without
 * per-frontend boilerplate.
 *
 * In dev mode it:
 *   - Sets `devServer.host = 0.0.0.0` and `port` from the yaml (unless
 *     already provided via env / CLI).
 *   - Configures Vite HMR to advertise `<name>-dev.ippoan.org` over
 *     wss so reload events survive the tunnel + CF Access hop.
 *
 * Production builds are untouched (module no-ops unless nuxt.options.dev).
 */
import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { defineNuxtModule } from '@nuxt/kit'

interface DevSpec {
  name: string
  port: number
  subdir?: string
  cmd?: string
}

export interface ModuleOptions {
  /** Override the spec path (default: <rootDir>/.ippoan-dev.yaml). */
  specPath?: string
  /** Override the public host pattern (default: <name>-dev.ippoan.org). */
  hostPattern?: (name: string) => string
  /** Disable HMR host rewriting even in dev. */
  hmr?: boolean
}

function parseFlatYaml(text: string): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {}
  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/#.*$/, '').trimEnd()
    if (!line.trim()) continue
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$/)
    if (!m) continue
    const [, key, valRaw] = m
    let val: string | number | boolean = valRaw.trim()
    if (typeof val === 'string' && val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1).replace(/\\"/g, '"')
    else if (typeof val === 'string' && val.startsWith("'") && val.endsWith("'")) val = val.slice(1, -1)
    else if (typeof val === 'string' && /^-?\d+$/.test(val)) val = Number(val)
    else if (val === 'true') val = true
    else if (val === 'false') val = false
    out[key] = val
  }
  return out
}

function loadSpec(path: string): DevSpec | null {
  if (!existsSync(path)) return null
  const raw = readFileSync(path, 'utf8')
  const parsed = parseFlatYaml(raw)
  if (typeof parsed.name !== 'string' || typeof parsed.port !== 'number') return null
  return {
    name: parsed.name,
    port: parsed.port,
    subdir: typeof parsed.subdir === 'string' ? parsed.subdir : undefined,
    cmd: typeof parsed.cmd === 'string' ? parsed.cmd : undefined,
  }
}

export default defineNuxtModule<ModuleOptions>({
  meta: {
    name: '@ippoan/nuxt-dev-preset',
    configKey: 'ippoanDev',
  },
  defaults: {
    hostPattern: (name) => `${name}-dev.ippoan.org`,
    hmr: true,
  },
  setup(options, nuxt) {
    if (!nuxt.options.dev) return

    const specPath = options.specPath || resolve(nuxt.options.rootDir, '.ippoan-dev.yaml')
    const spec = loadSpec(specPath)
    if (!spec) {
      console.warn(`[nuxt-dev-preset] ${specPath} not found or invalid; skipping.`)
      return
    }

    const host = (options.hostPattern || ((n) => `${n}-dev.ippoan.org`))(spec.name)

    // Dev server bind: pick yaml port unless env already sets one.
    const envPort = process.env.PORT ? Number(process.env.PORT) : undefined
    nuxt.options.devServer = {
      ...nuxt.options.devServer,
      host: process.env.HOST || '0.0.0.0',
      port: envPort ?? spec.port,
    }

    // Vite HMR: advertise the public dev-proxy hostname so HMR events
    // travel through the tunnel + CF Access rather than localhost.
    if (options.hmr !== false) {
      nuxt.options.vite = nuxt.options.vite || {}
      const server = (nuxt.options.vite as Record<string, unknown>).server as Record<string, unknown> | undefined || {}
      const existingHmr = (server.hmr as Record<string, unknown> | undefined) || {}
      ;(nuxt.options.vite as Record<string, unknown>).server = {
        ...server,
        hmr: {
          ...existingHmr,
          host,
          protocol: 'wss',
          clientPort: 443,
        },
      }
    }

    console.info(`[nuxt-dev-preset] bound dev server to :${nuxt.options.devServer.port}, public host https://${host}/`)
  },
})
