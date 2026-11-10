/**
 * GitHub Actions の OIDC ID token (RS256) の検証 (Refs ippoan/ci-dashboard#520、ippoan/alc-app#668)。
 *
 * staging の CI 用 token の発行口 (`handlers/ci-staging-token.ts`) だけが使う。鍵は GitHub の JWKS
 * (`GITHUB_OIDC_JWKS_URL`) から取り、isolate の中で `JWKS_CACHE_TTL_MS` だけ持つ。知らない `kid` が来たら
 * 1 回だけ取り直す (GitHub の鍵の入れ替え)。ただし直前の取得から `JWKS_REFETCH_MIN_MS` 経っていなければ
 * 取り直さない (偽の kid で GitHub へのリクエストを増やされないため)。
 *
 * 失敗は理由 (`GithubOidcError.reason`) だけを返す。呼び出し側は理由をログにだけ出し、応答には出さない。
 * token そのものはどこにも出さない。
 */

export const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
export const GITHUB_OIDC_JWKS_URL = `${GITHUB_OIDC_ISSUER}/.well-known/jwks`;
/** `exp` / `nbf` / `iat` に許す時計のずれ (秒)。 */
export const CLOCK_SKEW_SEC = 60;
const JWKS_CACHE_TTL_MS = 60 * 60 * 1000;
const JWKS_REFETCH_MIN_MS = 5 * 60 * 1000;

/** 検証を通った token から使う claim。 */
export interface GithubOidcClaims {
  repository: string;
  repository_owner: string;
  run_id?: string;
  ref?: string;
  exp: number;
}

export type GithubOidcReason =
  | "shape"
  | "alg"
  | "kid"
  | "jwks_fetch"
  | "unknown_kid"
  | "signature"
  | "payload"
  | "iss"
  | "aud"
  | "exp"
  | "nbf"
  | "iat"
  | "repository"
  | "repository_owner";

export class GithubOidcError extends Error {
  constructor(public readonly reason: GithubOidcReason) {
    super(`github oidc: ${reason}`);
  }
}

export interface VerifyGithubOidcOptions {
  /** `aud` に要求する値 (完全一致)。 */
  audience: string;
  /** `repository` に要求する値の一覧 (`owner/name`、完全一致)。 */
  allowedRepositories: readonly string[];
  /** `repository_owner` に要求する値 (完全一致)。 */
  repositoryOwner: string;
}

interface RsaJwk {
  kty: string;
  kid?: string;
  n?: string;
  e?: string;
}

let jwksCache: { keys: RsaJwk[]; fetchedAt: number } | null = null;

/** test 用: JWKS の cache を捨てる。 */
export function _clearGithubJwksCache(): void {
  jwksCache = null;
}

async function fetchJwks(): Promise<RsaJwk[]> {
  let res: Response;
  try {
    res = await fetch(GITHUB_OIDC_JWKS_URL, { headers: { Accept: "application/json" } });
  } catch {
    throw new GithubOidcError("jwks_fetch");
  }
  if (!res.ok) throw new GithubOidcError("jwks_fetch");
  let body: { keys?: unknown };
  try {
    body = (await res.json()) as { keys?: unknown };
  } catch {
    throw new GithubOidcError("jwks_fetch");
  }
  if (!Array.isArray(body.keys)) throw new GithubOidcError("jwks_fetch");
  const keys = (body.keys as RsaJwk[]).filter(
    (k) => k && k.kty === "RSA" && typeof k.kid === "string" && typeof k.n === "string" && typeof k.e === "string",
  );
  jwksCache = { keys, fetchedAt: Date.now() };
  return keys;
}

async function findKey(kid: string): Promise<RsaJwk> {
  const now = Date.now();
  if (jwksCache && now - jwksCache.fetchedAt < JWKS_CACHE_TTL_MS) {
    const hit = jwksCache.keys.find((k) => k.kid === kid);
    if (hit) return hit;
    if (now - jwksCache.fetchedAt < JWKS_REFETCH_MIN_MS) throw new GithubOidcError("unknown_kid");
  }
  const key = (await fetchJwks()).find((k) => k.kid === kid);
  if (!key) throw new GithubOidcError("unknown_kid");
  return key;
}

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function b64urlToJson(s: string): unknown {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * GitHub Actions の OIDC ID token を検証して claim を返す。失敗は `GithubOidcError` を投げる。
 * 順序: 形 → alg/kid → 鍵 → 署名 → iss → aud → exp/nbf/iat → repository_owner → repository。
 */
export async function verifyGithubOidcToken(
  token: string,
  opts: VerifyGithubOidcOptions,
): Promise<GithubOidcClaims> {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) throw new GithubOidcError("shape");
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  let header: unknown;
  try {
    header = b64urlToJson(headerB64);
  } catch {
    throw new GithubOidcError("shape");
  }
  if (!isRecord(header) || header.alg !== "RS256") throw new GithubOidcError("alg");
  if (typeof header.kid !== "string" || !header.kid) throw new GithubOidcError("kid");

  const jwk = await findKey(header.kid);
  let ok: boolean;
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    ok = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      b64urlToBytes(sigB64),
      new TextEncoder().encode(`${headerB64}.${payloadB64}`),
    );
  } catch {
    throw new GithubOidcError("signature");
  }
  if (!ok) throw new GithubOidcError("signature");

  let payload: unknown;
  try {
    payload = b64urlToJson(payloadB64);
  } catch {
    throw new GithubOidcError("payload");
  }
  if (!isRecord(payload)) throw new GithubOidcError("payload");

  if (payload.iss !== GITHUB_OIDC_ISSUER) throw new GithubOidcError("iss");
  const aud = payload.aud;
  const audOk = Array.isArray(aud) ? aud.includes(opts.audience) : aud === opts.audience;
  if (!opts.audience || !audOk) throw new GithubOidcError("aud");

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp + CLOCK_SKEW_SEC <= now) {
    throw new GithubOidcError("exp");
  }
  if (payload.nbf !== undefined && (typeof payload.nbf !== "number" || payload.nbf - CLOCK_SKEW_SEC > now)) {
    throw new GithubOidcError("nbf");
  }
  if (typeof payload.iat !== "number" || payload.iat - CLOCK_SKEW_SEC > now) {
    throw new GithubOidcError("iat");
  }

  if (typeof payload.repository_owner !== "string" || payload.repository_owner !== opts.repositoryOwner) {
    throw new GithubOidcError("repository_owner");
  }
  if (typeof payload.repository !== "string" || !opts.allowedRepositories.includes(payload.repository)) {
    throw new GithubOidcError("repository");
  }

  return {
    repository: payload.repository,
    repository_owner: payload.repository_owner,
    run_id: typeof payload.run_id === "string" ? payload.run_id : undefined,
    ref: typeof payload.ref === "string" ? payload.ref : undefined,
    exp: payload.exp,
  };
}
