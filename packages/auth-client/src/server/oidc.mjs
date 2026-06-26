/**
 * Google OIDC ID token mint (service account key, WebCrypto only)。
 *
 * rust-alc-api#434 step 3: Cloud Run を `--no-allow-unauthenticated` にロックダウンし、
 * CF proxy が `run.invoker` 最小権限の SA key で Google 署名の OIDC ID token を mint
 * して `Authorization: Bearer <id_token>` で転送する。Cloud Run IAM (platform 層) が
 * OIDC を検証し、token 無しの直叩きは 403。app (rust-alc-api) は注入 identity
 * (`X-Tenant-ID` / `X-User-*`) を信頼するだけで OIDC は見ない。
 *
 * metadata server を持たない CF Worker でも、SA key で jwt-bearer assertion を作り
 * token endpoint で id_token に交換できる (`target_audience` claim で aud を指定)。
 * 取得した id_token は **audience 単位で exp 手前までキャッシュ**して mint 回数を抑える。
 *
 * 値 (SA private key) は引数とローカルだけを通り、log / response には出さない。
 */

/** audience -> { token, expMs } の module-level cache (Worker isolate 内で再利用)。 */
const idTokenCache = new Map()

function b64urlFromString(s) {
  return btoa(unescape(encodeURIComponent(s)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function b64urlFromBytes(bytes) {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) を DER バイト列に変換。 */
function pemToPkcs8Bytes(pem) {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '')
  const bin = atob(body)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

async function signRs256(unsigned, privateKeyPem, subtle) {
  const key = await subtle.importKey(
    'pkcs8',
    pemToPkcs8Bytes(privateKeyPem),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = await subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(unsigned),
  )
  return b64urlFromBytes(new Uint8Array(sig))
}

/** id_token (JWT) の payload から `exp` (秒) を取り出す。失敗時は null。 */
function expFromJwt(token) {
  try {
    const payload = token.split('.')[1]
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'))
    const exp = JSON.parse(json).exp
    return typeof exp === 'number' ? exp : null
  } catch {
    return null
  }
}

/**
 * SA key で `audience` 向けの Google OIDC ID token を mint する。
 *
 * @param {string|object} saKeyJson  service account key (JSON 文字列 or parse 済み object)
 * @param {string} audience          OIDC `aud` (= 叩く Cloud Run service の URL)
 * @param {object} [opts]
 * @param {(url,init)=>Promise<Response>} [opts.fetchImpl]  token endpoint 用 fetch (test 注入)
 * @param {SubtleCrypto} [opts.subtle]  WebCrypto subtle (test 注入)
 * @param {number} [opts.now]          現在時刻 (秒、test 注入)
 * @param {boolean} [opts.noCache]     cache を使わない (test 用)
 * @returns {Promise<string>} id_token
 */
export async function mintGoogleIdToken(saKeyJson, audience, opts = {}) {
  if (!audience) throw new Error('mintGoogleIdToken: audience required')
  const nowMs = opts.nowMs ?? Date.now()
  if (!opts.noCache) {
    const cached = idTokenCache.get(audience)
    // exp の 60s 手前までは再利用 (clock skew + 転送 latency マージン)。
    if (cached && cached.expMs - 60_000 > nowMs) return cached.token
  }

  const sa = typeof saKeyJson === 'string' ? JSON.parse(saKeyJson) : saKeyJson
  if (!sa || !sa.client_email || !sa.private_key) {
    throw new Error('mintGoogleIdToken: invalid service account key')
  }
  const subtle = opts.subtle ?? crypto.subtle
  const fetchImpl = opts.fetchImpl ?? fetch
  const tokenUri = sa.token_uri || 'https://oauth2.googleapis.com/token'
  const now = opts.now ?? Math.floor(nowMs / 1000)

  const header = { alg: 'RS256', typ: 'JWT', kid: sa.private_key_id }
  const claims = {
    iss: sa.client_email,
    sub: sa.client_email,
    aud: tokenUri,
    iat: now,
    exp: now + 3600,
    target_audience: audience,
  }
  const unsigned = `${b64urlFromString(JSON.stringify(header))}.${b64urlFromString(JSON.stringify(claims))}`
  const assertion = `${unsigned}.${await signRs256(unsigned, sa.private_key, subtle)}`

  const res = await fetchImpl(tokenUri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }).toString(),
  })
  if (!res.ok) {
    throw new Error(`mintGoogleIdToken: token endpoint ${res.status}`)
  }
  const data = await res.json()
  const idToken = data && data.id_token
  if (!idToken) throw new Error('mintGoogleIdToken: no id_token in response')

  const exp = expFromJwt(idToken)
  const expMs = (exp ?? now + 3600) * 1000
  if (!opts.noCache) idTokenCache.set(audience, { token: idToken, expMs })
  return idToken
}

/** test 用: audience cache を消す。 */
export function _clearIdTokenCache() {
  idTokenCache.clear()
}
