import { describe, it, expect, vi, afterEach } from 'vitest'
import {
  ensureFreshBuild,
  isStaleBuild,
  type FreshBuildWindow,
} from '../src/versionReload'

/** spy 付きの FreshBuildWindow を組み立てる (未指定パートは省略)。 */
function makeWin(
  opts: {
    store?: Record<string, string>
    getItemThrows?: boolean
    regs?: Array<{ unregister: () => Promise<boolean> }>
    getRegistrationsThrows?: boolean
    cacheKeys?: string[]
    keysThrows?: boolean
    withNavigator?: boolean
    withCaches?: boolean
  } = {},
): {
  win: FreshBuildWindow
  reload: ReturnType<typeof vi.fn>
  setItem: ReturnType<typeof vi.fn>
  unregister: ReturnType<typeof vi.fn>
  cacheDelete: ReturnType<typeof vi.fn>
} {
  const store: Record<string, string> = { ...(opts.store ?? {}) }
  const reload = vi.fn()
  const setItem = vi.fn((k: string, v: string) => {
    store[k] = v
  })
  const unregister = vi.fn(() => Promise.resolve(true))
  const cacheDelete = vi.fn(() => Promise.resolve(true))

  const win: FreshBuildWindow = {
    sessionStorage: {
      getItem: (k: string) => {
        if (opts.getItemThrows) throw new Error('sessionStorage disabled')
        return store[k] ?? null
      },
      setItem,
    },
    location: { reload },
  }
  if (opts.withNavigator !== false) {
    win.navigator = {
      serviceWorker: {
        getRegistrations: () => {
          if (opts.getRegistrationsThrows) return Promise.reject(new Error('sw fail'))
          return Promise.resolve(
            opts.regs ?? [{ unregister }],
          )
        },
      },
    }
  }
  if (opts.withCaches !== false) {
    win.caches = {
      keys: () => {
        if (opts.keysThrows) return Promise.reject(new Error('caches fail'))
        return Promise.resolve(opts.cacheKeys ?? ['precache-v1', 'runtime'])
      },
      delete: cacheDelete,
    }
  }
  return { win, reload, setItem, unregister, cacheDelete }
}

describe('isStaleBuild', () => {
  it('空文字は false (誤発火防止)', () => {
    expect(isStaleBuild('', 'abc')).toBe(false)
    expect(isStaleBuild('abc', '')).toBe(false)
    expect(isStaleBuild('  ', 'abc')).toBe(false)
  })
  it("'dev' は false", () => {
    expect(isStaleBuild('dev', 'abc')).toBe(false)
    expect(isStaleBuild('abc', 'dev')).toBe(false)
  })
  it('一致は false', () => {
    expect(isStaleBuild('abc', 'abc')).toBe(false)
    expect(isStaleBuild(' abc ', 'abc')).toBe(false)
  })
  it('不一致は true', () => {
    expect(isStaleBuild('old', 'new')).toBe(true)
  })
})

describe('ensureFreshBuild', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('window が無ければ no-op (SSR)', async () => {
    // node 環境では window 未定義。opts.win も省略 → false
    expect(await ensureFreshBuild({ buildVersion: 'old', serverVersion: 'new' })).toBe(false)
  })

  it('build == server なら reload しない', async () => {
    const { win, reload } = makeWin()
    expect(await ensureFreshBuild({ buildVersion: 'v1', serverVersion: 'v1', win })).toBe(false)
    expect(reload).not.toHaveBeenCalled()
  })

  it('既に同 server 版で reload 済みなら二度としない', async () => {
    const { win, reload } = makeWin({ store: { 'authclient:freshreload:new': '1' } })
    expect(await ensureFreshBuild({ buildVersion: 'old', serverVersion: 'new', win })).toBe(false)
    expect(reload).not.toHaveBeenCalled()
  })

  it('sessionStorage 不可 (throw) なら no-op', async () => {
    const { win, reload } = makeWin({ getItemThrows: true })
    expect(await ensureFreshBuild({ buildVersion: 'old', serverVersion: 'new', win })).toBe(false)
    expect(reload).not.toHaveBeenCalled()
  })

  it('古いバンドル → SW/caches 破棄 → 1 回 reload → guard 立てる', async () => {
    const { win, reload, setItem, unregister, cacheDelete } = makeWin()
    expect(await ensureFreshBuild({ buildVersion: 'old', serverVersion: 'new', win })).toBe(true)
    expect(setItem).toHaveBeenCalledWith('authclient:freshreload:new', '1')
    expect(unregister).toHaveBeenCalledTimes(1)
    expect(cacheDelete).toHaveBeenCalledTimes(2) // precache-v1 + runtime
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('navigator / caches が無くても reload する', async () => {
    const { win, reload } = makeWin({ withNavigator: false, withCaches: false })
    expect(await ensureFreshBuild({ buildVersion: 'old', serverVersion: 'new', win })).toBe(true)
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('SW/caches 破棄が throw しても reload は行う', async () => {
    const { win, reload } = makeWin({ getRegistrationsThrows: true, keysThrows: true })
    expect(await ensureFreshBuild({ buildVersion: 'old', serverVersion: 'new', win })).toBe(true)
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('namespace を指定すると guard キーに反映される', async () => {
    const { win, setItem } = makeWin()
    await ensureFreshBuild({ buildVersion: 'old', serverVersion: 'new', win, namespace: 'carins' })
    expect(setItem).toHaveBeenCalledWith('carins:freshreload:new', '1')
  })

  it('opts.win 省略時はグローバル window を使う', async () => {
    const { win, reload } = makeWin()
    vi.stubGlobal('window', win)
    expect(await ensureFreshBuild({ buildVersion: 'old', serverVersion: 'new' })).toBe(true)
    expect(reload).toHaveBeenCalledTimes(1)
  })
})
