/**
 * Mock/Live 統一テストヘルパー
 *
 * 環境変数でモード切替:
 *   mock: 環境変数未設定 (デフォルト、CI 高速)
 *   live: API_BASE_URL or ALC_API_URL 設定時 (実 API)
 */
import { vi, expect } from 'vitest'

// ---------------------------------------------------------------------------
// Mode detection
// ---------------------------------------------------------------------------

/** 指定の環境変数が設定されていれば live モード */
export function isLiveEnv(envVar = 'API_BASE_URL'): boolean {
  return !!process.env[envVar]
}

// ---------------------------------------------------------------------------
// Mock fetch helpers
// ---------------------------------------------------------------------------

/** JSON レスポンスを返す mock */
export function okJson(data: unknown = {}) {
  return { ok: true, status: 200, json: () => Promise.resolve(data) }
}

/** 204 No Content レスポンスを返す mock */
export function ok204() {
  return { ok: true, status: 204 }
}

/** エラーレスポンスを返す mock */
export function errResponse(status: number, body = '') {
  return { ok: false, status, statusText: 'Error', text: () => Promise.resolve(body) }
}

// ---------------------------------------------------------------------------
// Stub helpers
// ---------------------------------------------------------------------------

/**
 * mock モード: mockFetch にレスポンスをセット
 * live モード: 何もしない (実 fetch が走る)
 */
export function stubResponse(mockFetch: ReturnType<typeof vi.fn>, response: unknown, isLive: boolean) {
  if (!isLive) mockFetch.mockResolvedValueOnce(response)
}

/** vi.fn() でグローバル fetch を stub する (mock モードのみ) */
export function stubFetch(mockResponse: Response, isLive: boolean): void {
  if (!isLive) {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(mockResponse))
  }
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

/** mock 専用アサーション。live 時は何もしない */
export function assertMock(isLive: boolean, fn: () => void): void {
  if (!isLive) fn()
}

/**
 * live 時に mockFetch.mock.calls のアサーションをスキップ。
 * live 時は全アサーションが no-op になるプロキシを返す。
 */
export function expectMock(isLive: boolean, target: unknown) {
  if (isLive) {
    const noop = new Proxy({}, { get: () => () => noop })
    return noop as ReturnType<typeof expect>
  }
  return expect(target)
}

/**
 * API 呼び出しを実行。live 時は API エラー (4xx/5xx) を許容する。
 * ネットワークエラー (fetch failed) だけ fail にする。
 */
export async function callApi(isLive: boolean, fn: () => Promise<unknown>, toleratePatterns: string[] = ['API エラー']) {
  if (!isLive) {
    await fn()
    return
  }
  try {
    await fn()
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    if (toleratePatterns.some(p => msg.includes(p))) return
    throw e
  }
}
