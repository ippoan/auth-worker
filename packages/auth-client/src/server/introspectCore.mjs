/**
 * ブラウザ JWT introspection クライアントのコアロジック
 * (pure / テスタブル、h3 非依存)。
 *
 * auth-worker `POST /auth/introspect` (ippoan/auth-worker#290 Phase 1) を叩いて
 * 「この browser JWT は valid か / このアプリ向けに許可されたテナントか」を
 * 取得する。各 consumer は **`JWT_SECRET` (署名鍵) も `APP_TENANT_ACL` も持たず**、
 * 検証・tenant/aud 判定を auth-worker に委譲する (#290 の方針)。
 *
 * API リクエストごとに auth-worker への往復が発生するため、token×origin を
 * キーに short-TTL (default 30s) の in-memory cache で緩和する。cache TTL は
 * JWT 自身の `exp` を超えない (= upstream の authorization より長生きしない)。
 *
 * .mjs + JSDoc なのは **Nitro (rollup) が node_modules の .ts を transpile
 * しない**ため (server route から import される経路)。型は ./index.d.mts。
 *
 * 全ての I/O 依存 (`fetchImpl` / `cache` / `nowMs`) は引数で注入でき、
 * proxyCore.mjs と同じく plain Vitest (pure Node) でテストできる。
 */

/** cache の default TTL (ms)。short-TTL で auth-worker への往復を緩和する。 */
export const DEFAULT_TTL_MS = 30_000
/** cache hit 判定の手前マージン (ms)。期限ギリギリの値を返さない。 */
const REFRESH_BEFORE_MS = 1_000

/**
 * `POST /auth/introspect` 用の fetch params を組み立てる (純粋関数)。
 *
 * 認証は raw shared secret を `Authorization` に載せる (Bearer prefix なし) —
 * auth-worker の `resolveAllSharedSecrets` (#189) と対になる。
 */
export function buildIntrospectRequest({ authWorkerUrl, sharedSecret, token, origin }) {
  return {
    url: `${authWorkerUrl}/auth/introspect`,
    init: {
      method: 'POST',
      headers: {
        Authorization: sharedSecret,
        'Content-Type': 'application/json',
        'User-Agent': 'auth-client/server',
      },
      body: JSON.stringify({ token, origin }),
    },
  }
}

/**
 * auth-worker の応答 JSON を introspection 結果に正規化する (純粋関数)。
 * `active !== true` / 不正な型 / null は全て `{ active: false }` に倒す
 * (fail-closed)。
 */
export function normalizeIntrospectResult(data) {
  if (!data || typeof data !== 'object' || data.active !== true) {
    return { active: false }
  }
  return {
    active: true,
    tenant_id: typeof data.tenant_id === 'string' ? data.tenant_id : '',
    role: typeof data.role === 'string' ? data.role : '',
    email: typeof data.email === 'string' ? data.email : '',
    exp: typeof data.exp === 'number' ? data.exp : undefined,
  }
}

/** cache key。NUL 区切りで token と origin の衝突を避ける。 */
export function cacheKey(token, origin) {
  return `${origin} ${token}`
}

/**
 * cache entry の有効期限 (ms epoch) を計算する。short-TTL の cap を基本とし、
 * JWT の `exp` があればそれを超えない (upstream authorization より長生きしない)。
 */
export function computeCacheExpiryMs(result, nowMs, ttlMs) {
  const cap = nowMs + ttlMs
  if (result.active && typeof result.exp === 'number') {
    return Math.min(cap, result.exp * 1000)
  }
  return cap
}

/** 既定の module-scope cache (Nitro isolate ごとに 1 つ)。 */
const defaultCache = new Map()

/**
 * token を introspect する。cache hit ならそれを返し、miss なら auth-worker に
 * 往復して結果を cache する。
 *
 * @param {object} opts
 * @param {string} opts.authWorkerUrl  auth-worker origin (例: https://auth.ippoan.org)
 * @param {string} opts.sharedSecret   INTERNAL_SHARED_SECRET (raw)
 * @param {string} opts.token          検証対象の browser JWT
 * @param {string} opts.origin         呼び出しアプリの origin (APP_TENANT_ACL 分割用)
 * @param {typeof fetch} [opts.fetchImpl]  fetch 実装 (test 用に注入可)
 * @param {Map} [opts.cache]            cache 実装 (test 用に注入可)
 * @param {number} [opts.ttlMs]         cache TTL cap (ms)
 * @param {number} [opts.nowMs]         現在時刻 (ms epoch、test 用に注入可)
 * @returns {Promise<{active:boolean, tenant_id?:string, role?:string, email?:string, exp?:number}>}
 */
export async function introspectToken(opts) {
  const {
    authWorkerUrl,
    sharedSecret,
    token,
    origin,
    fetchImpl = fetch,
    cache = defaultCache,
    ttlMs = DEFAULT_TTL_MS,
    nowMs = Date.now(),
  } = opts

  // 空 token は往復不要 (auth-worker も active:false を返す)。
  if (!token) return { active: false }

  const key = cacheKey(token, origin)
  const cached = cache.get(key)
  if (cached && cached.expiresAtMs > nowMs + REFRESH_BEFORE_MS) {
    return cached.result
  }

  let result
  try {
    const { url, init } = buildIntrospectRequest({ authWorkerUrl, sharedSecret, token, origin })
    const res = await fetchImpl(url, init)
    // 401 (shared secret 不正) / 503 (設定不備) / その他 non-2xx は fail-closed。
    if (!res.ok) return { active: false }
    result = normalizeIntrospectResult(await res.json())
  } catch {
    // network error / JSON parse 失敗 → fail-closed (cache しない)。
    return { active: false }
  }

  // active のみ cache する。inactive を cache すると token 差し替え後の復帰が
  // TTL 分遅れるため、安全側 (= 毎回 introspect) に倒す。
  if (result.active) {
    cache.set(key, { result, expiresAtMs: computeCacheExpiryMs(result, nowMs, ttlMs) })
  }
  return result
}

/** test / 特殊用途向けに module-scope cache をクリアする。 */
export function _clearIntrospectCache() {
  defaultCache.clear()
}
