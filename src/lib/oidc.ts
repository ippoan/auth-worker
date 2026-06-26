/**
 * Google OIDC ID token mint (service account key, WebCrypto only)。
 *
 * rust-alc-api#434 step 3 (方式 B = auth-worker 集約): Cloud Run を
 * `--no-allow-unauthenticated` にした rust-alc-api へ、auth-worker の data-proxy
 * (`/alc-proxy/*`) が `run.invoker` 最小 SA key で Google 署名の OIDC ID token を
 * mint して `Authorization: Bearer` で到達する。SA key は **auth-worker 1 箇所**
 * にのみ bind し (blast radius 最小)、consumer には配らない。
 *
 * ロジックは `@ippoan/auth-client/server` の `oidc.mjs` (#306) と同等だが、
 * auth-worker は自身の bundle (TS) なのでここに port する (consumer 向けの
 * ESM .mjs とは別 module 系)。値 (private key) は log / response に出さない。
 */

interface ServiceAccountKey {
  client_email: string
  private_key: string
  private_key_id?: string
  token_uri?: string
}

/** audience -> { token, expMs } の module-level cache (Worker isolate 内で再利用)。 */
const idTokenCache = new Map<string, { token: string; expMs: number }>()

function b64urlFromString(s: string): string {
  return btoa(unescape(encodeURIComponent(s)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlFromBytes(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToPkcs8Bytes(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  const bin = atob(body);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function signRs256(unsigned: string, privateKeyPem: string, subtle: SubtleCrypto): Promise<string> {
  const key = await subtle.importKey(
    "pkcs8",
    pemToPkcs8Bytes(privateKeyPem) as unknown as ArrayBuffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned));
  return b64urlFromBytes(new Uint8Array(sig));
}

function expFromJwt(token: string): number | null {
  try {
    const payload = token.split(".")[1]!;
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    const exp = (JSON.parse(json) as { exp?: unknown }).exp;
    return typeof exp === "number" ? exp : null;
  } catch {
    return null;
  }
}

export interface MintOptions {
  fetchImpl?: typeof fetch;
  subtle?: SubtleCrypto;
  now?: number;
  nowMs?: number;
  noCache?: boolean;
}

/**
 * SA key で `audience` (= 叩く Cloud Run service URL) 向けの Google OIDC ID token
 * を mint する。audience 単位で exp の 60s 手前まで cache。
 */
export async function mintGoogleIdToken(
  saKeyJson: string | ServiceAccountKey,
  audience: string,
  opts: MintOptions = {},
): Promise<string> {
  if (!audience) throw new Error("mintGoogleIdToken: audience required");
  const nowMs = opts.nowMs ?? Date.now();
  if (!opts.noCache) {
    const cached = idTokenCache.get(audience);
    if (cached && cached.expMs - 60_000 > nowMs) return cached.token;
  }

  const sa: ServiceAccountKey = typeof saKeyJson === "string" ? JSON.parse(saKeyJson) : saKeyJson;
  if (!sa || !sa.client_email || !sa.private_key) {
    throw new Error("mintGoogleIdToken: invalid service account key");
  }
  const subtle = opts.subtle ?? crypto.subtle;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const tokenUri = sa.token_uri || "https://oauth2.googleapis.com/token";
  const now = opts.now ?? Math.floor(nowMs / 1000);

  const header = { alg: "RS256", typ: "JWT", kid: sa.private_key_id };
  const claims = {
    iss: sa.client_email,
    sub: sa.client_email,
    aud: tokenUri,
    iat: now,
    exp: now + 3600,
    target_audience: audience,
  };
  const unsigned = `${b64urlFromString(JSON.stringify(header))}.${b64urlFromString(JSON.stringify(claims))}`;
  const assertion = `${unsigned}.${await signRs256(unsigned, sa.private_key, subtle)}`;

  const res = await fetchImpl(tokenUri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }).toString(),
  });
  if (!res.ok) throw new Error(`mintGoogleIdToken: token endpoint ${res.status}`);
  const data = (await res.json()) as { id_token?: string };
  const idToken = data && data.id_token;
  if (!idToken) throw new Error("mintGoogleIdToken: no id_token in response");

  const exp = expFromJwt(idToken);
  const expMs = (exp ?? now + 3600) * 1000;
  if (!opts.noCache) idTokenCache.set(audience, { token: idToken, expMs });
  return idToken;
}

/** test 用: audience cache を消す。 */
export function _clearIdTokenCache(): void {
  idTokenCache.clear();
}
