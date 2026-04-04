/**
 * API 起動待ちポーリング
 */

export interface WaitOptions {
  /** ヘルスチェックパス (default: /api/health) */
  healthPath?: string
  /** 最大リトライ回数 (default: 30) */
  maxRetries?: number
  /** リトライ間隔 ms (default: 1000) */
  interval?: number
}

/** API が起動するまでポーリング */
export async function waitForApi(url: string, opts: WaitOptions = {}): Promise<void> {
  const { healthPath = '/api/health', maxRetries = 30, interval = 1000 } = opts
  for (let i = 0; i < maxRetries; i++) {
    try {
      const res = await fetch(`${url}${healthPath}`)
      if (res.ok) return
    } catch {
      // not ready yet
    }
    await new Promise(r => setTimeout(r, interval))
  }
  throw new Error(`API not ready after ${maxRetries} retries at ${url}`)
}
