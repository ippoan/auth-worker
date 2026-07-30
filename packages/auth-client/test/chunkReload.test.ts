import { describe, it, expect, vi } from 'vitest'
import {
  CHUNK_RELOAD_GIVE_UP_MESSAGE,
  CHUNK_RELOAD_MAX_ATTEMPTS,
  CHUNK_RELOAD_STORAGE_KEY,
  CHUNK_RELOAD_WINDOW_MS,
  chunkErrorMessage,
  extractChunkUrl,
  isChunkLoadErrorMessage,
  recoverFromChunkError,
} from '../src/chunkReload'

const NOW = 1_700_000_000_000
const CHUNK_URL = 'https://trouble.ippoan.org/_nuxt/BsuPsWsK.js'

function makeDeps(stored: string | null = null) {
  const store = new Map<string, string>()
  if (stored !== null) store.set(CHUNK_RELOAD_STORAGE_KEY, stored)

  return {
    now: vi.fn(() => NOW),
    getItem: vi.fn((key: string) => store.get(key) ?? null),
    setItem: vi.fn((key: string, value: string) => {
      store.set(key, value)
    }),
    refetch: vi.fn(async (_url: string) => {}),
    reload: vi.fn(),
    giveUp: vi.fn(),
  }
}

/** setItem に書かれた試行回数を取り出す。 */
function storedCount(deps: ReturnType<typeof makeDeps>): number {
  const [, value] = deps.setItem.mock.calls[0]!
  return (JSON.parse(value) as { count: number }).count
}

describe('extractChunkUrl', () => {
  it('dynamic import 失敗メッセージから chunk URL を取り出す', () => {
    expect(
      extractChunkUrl(`Failed to fetch dynamically imported module: ${CHUNK_URL}`),
    ).toBe(CHUNK_URL)
  })

  it('.mjs / .css も取り出す', () => {
    expect(extractChunkUrl('boom https://example.com/a/b.mjs')).toBe('https://example.com/a/b.mjs')
    expect(extractChunkUrl('boom https://example.com/a/b.css')).toBe('https://example.com/a/b.css')
  })

  it('URL を含まないメッセージでは undefined を返す', () => {
    expect(extractChunkUrl('Loading chunk 42 failed')).toBeUndefined()
  })
})

describe('isChunkLoadErrorMessage', () => {
  it('chunk load 失敗の代表的な文言を true と判定する', () => {
    expect(isChunkLoadErrorMessage('Failed to fetch dynamically imported module: /a.js')).toBe(true)
    expect(isChunkLoadErrorMessage('error loading dynamically imported module')).toBe(true)
    expect(isChunkLoadErrorMessage('Importing a module script failed.')).toBe(true)
    expect(isChunkLoadErrorMessage('Loading chunk 3 failed')).toBe(true)
  })

  it('無関係なエラーは false と判定する', () => {
    expect(isChunkLoadErrorMessage('API エラー (500): boom')).toBe(false)
    expect(isChunkLoadErrorMessage('')).toBe(false)
  })
})

describe('chunkErrorMessage', () => {
  it('Error からは message を取り出す', () => {
    expect(chunkErrorMessage(new Error('boom'))).toBe('boom')
  })

  it('文字列はそのまま返す', () => {
    expect(chunkErrorMessage('boom')).toBe('boom')
  })

  it('それ以外は空文字を返す', () => {
    expect(chunkErrorMessage(undefined)).toBe('')
    expect(chunkErrorMessage({ message: 'boom' })).toBe('')
  })
})

describe('recoverFromChunkError', () => {
  it('初回はキャッシュをバイパスして取り直してからリロードする', async () => {
    const deps = makeDeps()

    await expect(recoverFromChunkError(CHUNK_URL, deps)).resolves.toBe('reloaded')

    expect(deps.refetch).toHaveBeenCalledWith(CHUNK_URL)
    expect(deps.reload).toHaveBeenCalledTimes(1)
    expect(deps.giveUp).not.toHaveBeenCalled()
    expect(storedCount(deps)).toBe(1)
  })

  it('URL が取れなかった場合は取り直しを飛ばしてリロードする', async () => {
    const deps = makeDeps()

    await expect(recoverFromChunkError(undefined, deps)).resolves.toBe('reloaded')

    expect(deps.refetch).not.toHaveBeenCalled()
    expect(deps.reload).toHaveBeenCalledTimes(1)
  })

  it('取り直しが失敗してもリロードする', async () => {
    const deps = makeDeps()
    deps.refetch.mockRejectedValueOnce(new Error('offline'))

    await expect(recoverFromChunkError(CHUNK_URL, deps)).resolves.toBe('reloaded')

    expect(deps.reload).toHaveBeenCalledTimes(1)
  })

  it('時間窓内に上限まで試したらリロードせず loud fail する', async () => {
    const deps = makeDeps(JSON.stringify({ count: CHUNK_RELOAD_MAX_ATTEMPTS, ts: NOW }))

    await expect(recoverFromChunkError(CHUNK_URL, deps)).resolves.toBe('gave-up')

    expect(deps.reload).not.toHaveBeenCalled()
    expect(deps.refetch).not.toHaveBeenCalled()
    expect(deps.setItem).not.toHaveBeenCalled()
    expect(deps.giveUp).toHaveBeenCalledWith(CHUNK_RELOAD_GIVE_UP_MESSAGE)
  })

  it('時間窓を過ぎた試行は数えない (再発時にもう一度自動復旧する)', async () => {
    const deps = makeDeps(
      JSON.stringify({
        count: CHUNK_RELOAD_MAX_ATTEMPTS,
        ts: NOW - CHUNK_RELOAD_WINDOW_MS - 1,
      }),
    )

    await expect(recoverFromChunkError(CHUNK_URL, deps)).resolves.toBe('reloaded')

    expect(deps.reload).toHaveBeenCalledTimes(1)
    expect(storedCount(deps)).toBe(1)
  })

  it('時間窓内なら試行回数を積み増す', async () => {
    const deps = makeDeps(JSON.stringify({ count: 1, ts: NOW - 1 }))

    await expect(recoverFromChunkError(CHUNK_URL, deps)).resolves.toBe('reloaded')

    expect(storedCount(deps)).toBe(2)
  })

  it('保存値が壊れていても初回扱いで復旧する', async () => {
    const deps = makeDeps('not-json')

    await expect(recoverFromChunkError(CHUNK_URL, deps)).resolves.toBe('reloaded')

    expect(storedCount(deps)).toBe(1)
  })

  it('保存値の型が想定外でも初回扱いで復旧する', async () => {
    const deps = makeDeps(JSON.stringify({ count: 'many', ts: 'yesterday' }))

    await expect(recoverFromChunkError(CHUNK_URL, deps)).resolves.toBe('reloaded')

    expect(storedCount(deps)).toBe(1)
  })
})
