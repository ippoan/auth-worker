/**
 * OAuth client_id health check (issue #209)
 *
 * `GET /health/oauth` (Bearer JWT 保護) で各 OAuth provider の認可エンドポイントを
 * `redirect: "manual"` で 1 回叩き、生死判定する。既存 `/api/health` (ALC API
 * proxy) とは関心が違うので独立ハンドラとして実装。
 *
 * PR2 で 4 provider 全部対応:
 *   - google     : client_id 生死を判定可能 (mode = "client_id_check")。
 *                  正常時 302 → `/v3/signin/identifier`、不正時 302 →
 *                  `/signin/oauth/error?authError=...`。
 *   - github_mcp : client_id 正否に関わらず 302 → `github.com/login` を
 *                  返すため、probe では生死を区別できない。**reachability** のみ。
 *   - lineworks  : worker に client_id 無し (rust-alc-api 委譲)。
 *                  `ALC_API_ORIGIN/api/auth/lineworks/redirect` の到達性のみ。
 *   - egov       : Keycloak 依存。`EGOV_AUTH_BASE/.well-known/openid-configuration`
 *                  の到達性 + JSON 整合性。
 *
 * 判定結果には `mode` field を含めて、Google だけが client_id_check で、
 * 他 3 つは reachability であることを explicit に出す。
 *
 * 共通方針:
 *   - 外部 provider への fetch は `redirect: "manual"` + `AbortSignal.timeout(5s)`。
 *   - fetch 失敗 / 想定外応答 → `unknown: true` (HTTP 200。CI は degraded のみで fail)。
 *   - 1 つでも `ok: false` → overall = "degraded" (HTTP 503)。
 */
import type { Env } from "../index";
import { alcOidcToken } from "../lib/alc-data-fetch";
import { internalAuthToken } from "../lib/alc-internal";
import { verifyJwt } from "../lib/jwt";
import { resolveSecret } from "../lib/secret";

/** 外部 provider への probe 1 回のタイムアウト (ms)。 */
const PROBE_TIMEOUT_MS = 5000;

/** `jwt_secret_drift` probe (rust-alc-api canary) 専用の長めタイムアウト。
 *  staging Cloud Run は minScale=0 + PostgreSQL sidecar + migration 全件再適用で
 *  cold-start に 15-30s かかる。5s timeout だと毎回 `unknown` で返ってしまい
 *  drift 検知 probe が機能しないため、本 probe だけ 30s 許容する (Refs #218)。
 *  prod は常時稼働で数百 ms 応答なので max 値を増やしても実行時間は伸びない。 */
const CANARY_PROBE_TIMEOUT_MS = 30000;

type ProbeMode = "client_id_check" | "reachability" | "secret_check";

type ProbeOk = {
  configured: true;
  ok: boolean;
  status: number;
  mode: ProbeMode;
  hint?: string;
};
type ProbeUnknown = {
  configured: true;
  unknown: true;
  mode: ProbeMode;
  hint: string;
};
type ProbeResult = { configured: false } | ProbeOk | ProbeUnknown;

interface HealthOAuthBody {
  checked_at: string;
  overall: "ok" | "degraded" | "unknown";
  providers: Record<string, ProbeResult>;
}

/** 共通: fetch を timeout 付きで実行して `Response | unknown(error)` を返す。 */
async function timedFetch(
  url: string,
  init: RequestInit = {},
): Promise<Response | { _fetchError: string }> {
  try {
    return await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      ...init,
    });
  } catch (e: unknown) {
    return {
      _fetchError: e instanceof Error ? e.message : String(e),
    };
  }
}

function isFetchError(
  v: Response | { _fetchError: string },
): v is { _fetchError: string } {
  return "_fetchError" in v;
}

// ---------------------------------------------------------------------------
// google — client_id_check
// ---------------------------------------------------------------------------

async function probeGoogle(env: Env): Promise<ProbeResult> {
  const mode: ProbeMode = "client_id_check";
  const clientId = await resolveSecret(env.GOOGLE_CLIENT_ID);
  if (!clientId) return { configured: false };

  const u = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  u.searchParams.set("client_id", clientId);
  u.searchParams.set(
    "redirect_uri",
    `${env.AUTH_WORKER_ORIGIN}/oauth/google/callback`,
  );
  u.searchParams.set("response_type", "code");
  u.searchParams.set("scope", "openid email profile");

  const res = await timedFetch(u.toString());
  if (isFetchError(res)) {
    return { configured: true, unknown: true, mode, hint: `fetch failed: ${res._fetchError}` };
  }

  // Refs #209: 実応答観測で、Google は client_id 正否に関わらず HTTP 302 で
  // `accounts.google.com` に飛ばす。判定は **Location の path / query**:
  //   正常: path `/v3/signin/identifier` 等 (authError= 無し)
  //   異常: path `/signin/oauth/error?authError=Cg5pbnZhbGlkX2NsaWVudBI...`
  //         (base64 で "invalid_client / The OAuth client was not found.")
  const loc = res.headers.get("location") ?? "";
  if (res.status >= 300 && res.status < 400 && loc) {
    let locUrl: URL | null = null;
    try {
      locUrl = new URL(loc);
    } catch {
      /* malformed Location */
    }
    if (locUrl && locUrl.host === "accounts.google.com") {
      const errPath = locUrl.pathname.startsWith("/signin/oauth/error");
      const hasErr = locUrl.searchParams.has("authError") ||
        locUrl.searchParams.has("error");
      if (errPath || hasErr) {
        return {
          configured: true,
          ok: false,
          status: res.status,
          mode,
          hint: "invalid_client — client_id may be wrong",
        };
      }
      return { configured: true, ok: true, status: res.status, mode };
    }
    return {
      configured: true,
      unknown: true,
      mode,
      hint: `redirected to unexpected host ${locUrl?.host ?? "(malformed Location)"}`,
    };
  }

  // 30x 以外 (4xx / 5xx / 200) は将来 Google が挙動を変えた場合の防御。
  let body = "";
  try {
    body = (await res.text()).slice(0, 1024);
  } catch {
    /* swallow */
  }
  const invalid =
    /OAuth client was not found/i.test(body) ||
    /invalid[_ ]client/i.test(body) ||
    res.status >= 400;
  if (invalid) {
    return {
      configured: true,
      ok: false,
      status: res.status,
      mode,
      hint: "invalid_client — client_id may be wrong",
    };
  }
  return { configured: true, unknown: true, mode, hint: `unexpected status ${res.status}` };
}

// ---------------------------------------------------------------------------
// google_secret — secret_check
//
// OAuth2 spec の token endpoint に意図的に invalid な code を投げて、
// error 種別 で client_secret の正否を判定する (= 標準的な monitoring 技法)。
//
//   creds OK  / code bad : 400 {"error":"invalid_grant"}     ← 期待
//   creds bad            : 401 {"error":"invalid_client"}    ← 検知目標
//
// 実 token は発行されないので安全。client_secret 値は HTTPS body 内のみで
// log / response に echo されない。
// ---------------------------------------------------------------------------

async function probeGoogleSecret(env: Env): Promise<ProbeResult> {
  const mode: ProbeMode = "secret_check";
  const clientId = await resolveSecret(env.GOOGLE_CLIENT_ID);
  const clientSecret = await resolveSecret(env.GOOGLE_CLIENT_SECRET);
  if (!clientId || !clientSecret) return { configured: false };

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: "health_probe_intentionally_invalid",
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: `${env.AUTH_WORKER_ORIGIN}/oauth/google/callback`,
  });

  const res = await timedFetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (isFetchError(res)) {
    return { configured: true, unknown: true, mode, hint: `fetch failed: ${res._fetchError}` };
  }

  let json: { error?: string } = {};
  try {
    json = (await res.json()) as { error?: string };
  } catch {
    /* swallow — provider may change response shape */
  }
  const err = json.error ?? "";

  // creds accepted, code rejected — what we want
  if (res.status === 400 && err === "invalid_grant") {
    return { configured: true, ok: true, status: res.status, mode };
  }
  // creds drift — exactly the failure mode we are detecting
  if (err === "invalid_client") {
    return {
      configured: true,
      ok: false,
      status: res.status,
      mode,
      hint: "invalid_client — GOOGLE_CLIENT_ID/SECRET pair rejected by token endpoint",
    };
  }
  // unexpected — Google が仕様変更したとき誤検知しないよう unknown 扱い
  return {
    configured: true,
    unknown: true,
    mode,
    hint: `unexpected ${res.status} ${err || "(no error field)"}`,
  };
}

// ---------------------------------------------------------------------------
// github_mcp — reachability only (client_id 正否は probe で区別不能)
// ---------------------------------------------------------------------------

async function probeGithubMcp(env: Env): Promise<ProbeResult> {
  const mode: ProbeMode = "reachability";
  const clientId = await resolveSecret(env.GITHUB_MCP_CLIENT_ID);
  if (!clientId) return { configured: false };

  // 実応答観測 (PR2 着手前): GitHub は client_id の正否に関わらず
  // 302 → `github.com/login?...` を返す。empty / nonexistent / 不正形式
  // すべて同じ。**reachability のみ**を確認する。
  const u = new URL("https://github.com/login/oauth/authorize");
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", `${env.AUTH_WORKER_ORIGIN}/mcp/auth_callback`);
  u.searchParams.set("scope", "read:user");

  const res = await timedFetch(u.toString());
  if (isFetchError(res)) {
    return { configured: true, unknown: true, mode, hint: `fetch failed: ${res._fetchError}` };
  }

  const loc = res.headers.get("location") ?? "";
  if (res.status >= 300 && res.status < 400 && loc) {
    let locUrl: URL | null = null;
    try {
      locUrl = new URL(loc);
    } catch {
      /* malformed Location */
    }
    if (locUrl && locUrl.host === "github.com") {
      return { configured: true, ok: true, status: res.status, mode };
    }
    return {
      configured: true,
      unknown: true,
      mode,
      hint: `redirected to unexpected host ${locUrl?.host ?? "(malformed Location)"}`,
    };
  }
  // 30x 以外 → GitHub 側の障害 or 仕様変更。reachability 失敗扱い。
  return {
    configured: true,
    ok: false,
    status: res.status,
    mode,
    hint: `expected 30x to github.com but got ${res.status}`,
  };
}

// ---------------------------------------------------------------------------
// github_mcp_secret — secret_check
//
// GitHub の OAuth token endpoint に invalid な code を投げて error 種別で
// client_secret の正否を判定する。GitHub は標準 OAuth2 と違って HTTP 200 で
// error を body に返す:
//
//   creds OK  / code bad : 200 {"error":"bad_verification_code"}        ← 期待
//   creds bad            : 200 {"error":"incorrect_client_credentials"} ← 検知目標
//
// `Accept: application/json` を付けて JSON 応答を強制する (デフォは form-urlencoded)。
// ---------------------------------------------------------------------------

async function probeGithubMcpSecret(env: Env): Promise<ProbeResult> {
  const mode: ProbeMode = "secret_check";
  const clientId = await resolveSecret(env.GITHUB_MCP_CLIENT_ID);
  const clientSecret = await resolveSecret(env.GITHUB_MCP_CLIENT_SECRET);
  if (!clientId || !clientSecret) return { configured: false };

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code: "health_probe_intentionally_invalid",
    redirect_uri: `${env.AUTH_WORKER_ORIGIN}/mcp/auth_callback`,
  });

  const res = await timedFetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json",
    },
    body: body.toString(),
  });
  if (isFetchError(res)) {
    return { configured: true, unknown: true, mode, hint: `fetch failed: ${res._fetchError}` };
  }

  let json: { error?: string } = {};
  try {
    json = (await res.json()) as { error?: string };
  } catch {
    /* swallow */
  }
  const err = json.error ?? "";

  if (err === "bad_verification_code") {
    return { configured: true, ok: true, status: res.status, mode };
  }
  if (err === "incorrect_client_credentials") {
    return {
      configured: true,
      ok: false,
      status: res.status,
      mode,
      hint: "incorrect_client_credentials — GITHUB_MCP_CLIENT_ID/SECRET pair rejected",
    };
  }
  return {
    configured: true,
    unknown: true,
    mode,
    hint: `unexpected ${res.status} ${err || "(no error field)"}`,
  };
}

// ---------------------------------------------------------------------------
// jwt_secret_drift — secret_check (Refs #218)
//
// auth-worker と rust-alc-api は HS256 鍵 `JWT_SECRET` を物理共有している。
// 片方だけ rotate された / Secrets Store 移行漏れで drift すると、ユーザー
// ログイン後の cookie verify が silent fail して redirect loop に陥る。
//
// rust-alc-api 側の `GET /api/internal/health/jwt-canary?challenge=<hex>` に
// 32-byte random challenge を投げ、返ってきた HMAC-SHA256(challenge) を
// auth-worker 側の `JWT_SECRET` で再計算した値と比較する:
//
//   一致      → ok (両者の JWT_SECRET が一致)
//   不一致    → degraded (drift 検知)
//   401       → degraded (internal JWT 自体が拒否される = drift の典型)
//   404       → unknown (rust-alc-api がまだ canary endpoint を持たない旧版)
//   その他    → unknown (上流障害 / 仕様変更)
//
// secret 値そのものは body / log / response に echo されない。HMAC tag のみ。
// ---------------------------------------------------------------------------

async function probeJwtDrift(env: Env): Promise<ProbeResult> {
  const mode: ProbeMode = "secret_check";
  if (!env.ALC_API_ORIGIN) return { configured: false };

  // JWT_SECRET の null チェックは handler 入口の auth guard が既に弾いて
  // いるので、probe 到達時点で `resolveSecret` が null を返す経路は無い。
  // race で null になる ev は同 handler の verifyJwt も同様に落ちて 500 になる
  // ので、ここでは throw させて /health/oauth 全体の 500 で異常検知させる
  // (二重 try/catch を書かない)。
  const jwtSecret = (await resolveSecret(env.JWT_SECRET))!;
  const challengeBytes = new Uint8Array(32);
  crypto.getRandomValues(challengeBytes);
  const challengeHex = bytesToHex(challengeBytes);
  // #434 lockdown: rust は allUsers 削除後 Google OIDC (aud=alc-api-internal) を
  // 要求する。`internalAuthToken` は INTERNAL_AUTH_OIDC=1 の時 OIDC を、それ以外は
  // 従来の internal JWT (HS256) を返す (`alc-internal.ts` と同ロジックを共有)。
  // canary endpoint 自体の HMAC 計算は JWT_SECRET のみに依存するため、transport が
  // OIDC に変わっても drift 検知の意味は変わらない。
  const internalJwt = await internalAuthToken(env);

  const url =
    `${env.ALC_API_ORIGIN}/api/internal/health/jwt-canary?challenge=${challengeHex}`;
  const res = await timedFetch(url, {
    headers: { Authorization: `Bearer ${internalJwt}` },
    // staging cold-start (15-30s) を踏み倒すため default 5s timeout を override
    signal: AbortSignal.timeout(CANARY_PROBE_TIMEOUT_MS),
  });
  if (isFetchError(res)) {
    return { configured: true, unknown: true, mode, hint: `fetch failed: ${res._fetchError}` };
  }

  // 401 → require_internal_jwt が拒否した (JWT_SECRET drift、または OIDC の
  // aud/custom-audiences 未設定)。
  if (res.status === 401) {
    return {
      configured: true,
      ok: false,
      status: 401,
      mode,
      hint: "internal auth rejected by rust-alc-api — JWT_SECRET drift or OIDC audience mismatch",
    };
  }
  // 404 → rust-alc-api が canary endpoint を持たない旧版 (= deploy 順序)。
  if (res.status === 404) {
    return {
      configured: true,
      unknown: true,
      mode,
      hint: "canary endpoint not deployed on rust-alc-api (pre #218 build)",
    };
  }
  if (res.status !== 200) {
    return { configured: true, unknown: true, mode, hint: `unexpected status ${res.status}` };
  }

  let json: { signature?: unknown } = {};
  try {
    json = (await res.json()) as { signature?: unknown };
  } catch {
    /* swallow */
  }
  const sig = typeof json.signature === "string" ? json.signature : "";
  if (!/^[0-9a-f]{64}$/.test(sig)) {
    return {
      configured: true,
      unknown: true,
      mode,
      hint: "canary response missing/invalid signature",
    };
  }

  const expected = await hmacSha256Hex(jwtSecret, challengeBytes);
  if (timingSafeHexEqual(sig, expected)) {
    return { configured: true, ok: true, status: 200, mode };
  }
  return {
    configured: true,
    ok: false,
    status: 200,
    mode,
    hint: "signature mismatch — JWT_SECRET drift between auth-worker and rust-alc-api",
  };
}

function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) {
    s += b.toString(16).padStart(2, "0");
  }
  return s;
}

async function hmacSha256Hex(secret: string, data: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, data);
  return bytesToHex(new Uint8Array(sig));
}

/** lowercase hex 文字列同士の constant-time 比較。
 *  caller が同一長 (HMAC-SHA256 hex = 64 chars) を保証する前提。 */
function timingSafeHexEqual(a: string, b: string): boolean {
  // 呼び出し元 (probeJwtDrift) は事前に `/^[0-9a-f]{64}$/.test(sig)` で
  // sig 側を 64 chars に固定し、expected 側も hmacSha256Hex で必ず 64 chars
  // 返るので length チェックは不要 (= dead branch を作らない)。
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ---------------------------------------------------------------------------
// lineworks — reachability only (client_id は rust-alc-api 側)
// ---------------------------------------------------------------------------

async function probeLineworks(env: Env): Promise<ProbeResult> {
  const mode: ProbeMode = "reachability";
  // LINE WORKS の credentials は rust-alc-api 側の `bot_secret_encrypted` に
  // 暗号化保存されており、worker env には無い。**reachability** として
  // rust-alc-api の lineworks redirect endpoint がパラメータ不足で正規に
  // 400 を返すかを確認する (404 や 5xx なら rust-alc-api 側の障害)。
  if (!env.ALC_API_ORIGIN) return { configured: false };

  // #434 lockdown: rust は allUsers 削除後 Google OIDC (aud=ALC_API_ORIGIN) を
  // 要求する。mint 不可 (SA key 未設定 = lockdown 前) は Authorization 無しで
  // fail-open する。
  const oidc = await alcOidcToken(env);
  const url = `${env.ALC_API_ORIGIN}/api/auth/lineworks/redirect`;
  const res = await timedFetch(
    url,
    oidc ? { headers: { Authorization: `Bearer ${oidc}` } } : undefined,
  );
  if (isFetchError(res)) {
    return { configured: true, unknown: true, mode, hint: `fetch failed: ${res._fetchError}` };
  }

  // パラメータ無しなので 400/422 (Bad Request) が期待される — これは
  // 「rust-alc-api 生きてて lineworks route が登録されてる」の証拠。
  // 5xx → backend 障害。404 → route 未登録 (deploy 破損)。
  if (res.status === 400 || res.status === 422) {
    return { configured: true, ok: true, status: res.status, mode };
  }
  if (res.status >= 500 || res.status === 404) {
    return {
      configured: true,
      ok: false,
      status: res.status,
      mode,
      hint: `rust-alc-api lineworks route returned ${res.status}`,
    };
  }
  return {
    configured: true,
    unknown: true,
    mode,
    hint: `unexpected status ${res.status}`,
  };
}

// ---------------------------------------------------------------------------
// egov — reachability of Keycloak OIDC discovery
// ---------------------------------------------------------------------------

async function probeEgov(env: Env): Promise<ProbeResult> {
  const mode: ProbeMode = "reachability";
  if (!env.EGOV_CLIENT_ID || !env.EGOV_AUTH_BASE) return { configured: false };

  // Keycloak の標準 OIDC discovery。issuer / authorization_endpoint /
  // token_endpoint が揃っていれば「Keycloak realm が生きて公開されてる」と判定。
  const url = `${env.EGOV_AUTH_BASE.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const res = await timedFetch(url);
  if (isFetchError(res)) {
    return { configured: true, unknown: true, mode, hint: `fetch failed: ${res._fetchError}` };
  }

  if (res.status === 401 || res.status === 403) {
    // e-Gov sandbox (sbx) は well-known endpoint を Basic auth / IP allowlist で
    // 保護しているため、認証なしの probe は 401 (Basic challenge) / 403 を返す。
    // socket レベルには到達できているので "configured + reachable" だが、
    // discovery JSON の検証ができないので unknown 扱いにする (CI fail 防止)。
    // prod の e-Gov 本番 endpoint が同じ status を返す事態は本物の障害だが、
    // それは workflow_dispatch → target=prod で別途検知する設計。
    return {
      configured: true,
      unknown: true,
      mode,
      hint: `well-known returned ${res.status} (likely sandbox auth gate)`,
    };
  }

  if (res.status !== 200) {
    return {
      configured: true,
      ok: false,
      status: res.status,
      mode,
      hint: `well-known returned ${res.status}`,
    };
  }
  let json: unknown;
  try {
    json = await res.json();
  } catch (e: unknown) {
    return {
      configured: true,
      unknown: true,
      mode,
      hint: `well-known body is not JSON: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
  const obj = json as { issuer?: unknown; authorization_endpoint?: unknown; token_endpoint?: unknown };
  const validIssuer = typeof obj.issuer === "string" && obj.issuer.length > 0;
  const validAuthz = typeof obj.authorization_endpoint === "string" &&
    obj.authorization_endpoint.length > 0;
  const validToken = typeof obj.token_endpoint === "string" && obj.token_endpoint.length > 0;
  if (!validIssuer || !validAuthz || !validToken) {
    return {
      configured: true,
      ok: false,
      status: 200,
      mode,
      hint: "well-known JSON missing required fields (issuer / authorization_endpoint / token_endpoint)",
    };
  }
  return { configured: true, ok: true, status: 200, mode };
}

// ---------------------------------------------------------------------------
// secrets_format — secret_check (Refs #208)
//
// Secrets Store binding から resolveSecret した値の **format** を検査する。
// 外部 provider は叩かず、値そのものも response / log に出さない (問題のある
// secret 名と症状だけを hint に出す)。PR #205 で 7 secret を Secrets Store
// binding 化したが、GCP/CF へ `echo` で投入すると末尾に `\n` が混入し、消費側
// の string compare (OAuth audience / HMAC 鍵 / webhook secret) が silent fail
// する (#208: GOOGLE_CLIENT_ID 末尾 `\n` → rust-alc-api InvalidAudience)。
// Google / JWT_SECRET は既存 probe が creds drift を検知するが、開発用の
// GITHUB_MCP_* / GITHUB_WEBHOOK_SECRET は実走しないと露見しないため、format を
// 直接検査する:
//   - GITHUB_MCP_CLIENT_ID / _SECRET / GITHUB_WEBHOOK_SECRET:
//     末尾 whitespace (`echo` 投入の `\n` 混入) を検出
//   - GITHUB_MCP_USER_ALLOWLIST: JSON.parse + Array.isArray (placeholder /
//     壊れた JSON / 末尾改行を検出)
//
// 1 つでも問題があれば ok:false → overall=degraded (HTTP 503) で
// oauth-health.yml CI (staging post-deploy + 毎日 schedule) が拾う。
// 4 secret すべて未 bind の env では configured:false で skip。
// ---------------------------------------------------------------------------

async function probeSecretsFormat(env: Env): Promise<ProbeResult> {
  const mode: ProbeMode = "secret_check";
  const entries: Array<{ name: string; value: string | null; json: boolean }> = [
    { name: "GITHUB_MCP_CLIENT_ID", value: await resolveSecret(env.GITHUB_MCP_CLIENT_ID), json: false },
    { name: "GITHUB_MCP_CLIENT_SECRET", value: await resolveSecret(env.GITHUB_MCP_CLIENT_SECRET), json: false },
    { name: "GITHUB_WEBHOOK_SECRET", value: await resolveSecret(env.GITHUB_WEBHOOK_SECRET), json: false },
    { name: "GITHUB_MCP_USER_ALLOWLIST", value: await resolveSecret(env.GITHUB_MCP_USER_ALLOWLIST), json: true },
  ];
  const configured = entries.filter((e) => e.value !== null);
  if (configured.length === 0) return { configured: false };

  // 値そのものは hint に載せない。secret 名 + 症状だけを集める。
  const problems: string[] = [];
  for (const e of configured) {
    const v = e.value as string;
    if (/\s$/.test(v)) {
      problems.push(`${e.name}: trailing whitespace`);
    }
    if (e.json) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(v);
      } catch {
        problems.push(`${e.name}: invalid JSON`);
        continue;
      }
      if (!Array.isArray(parsed)) {
        problems.push(`${e.name}: not a JSON array`);
      }
    }
  }
  if (problems.length > 0) {
    return { configured: true, ok: false, status: 200, mode, hint: problems.join("; ") };
  }
  return { configured: true, ok: true, status: 200, mode };
}

// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------

function computeOverall(
  providers: Record<string, ProbeResult>,
): "ok" | "degraded" | "unknown" {
  const values = Object.values(providers);
  if (values.some((p) => "ok" in p && p.ok === false)) return "degraded";
  if (values.some((p) => "unknown" in p && p.unknown === true)) return "unknown";
  return "ok";
}

export async function handleHealthOAuth(
  request: Request,
  env: Env,
): Promise<Response> {
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) {
    return new Response("server not configured", { status: 503 });
  }

  const auth = request.headers.get("authorization") ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  // Refs #218: token に env claim があれば WORKER_ENV と一致を強制
  const payload = token ? await verifyJwt(token, jwtSecret, env.WORKER_ENV) : null;
  if (!payload) {
    return new Response("unauthorized", { status: 401 });
  }

  // 8 probe 並列実行 (Promise.all)。1 つの probe の latency が全体を
  // 引っ張らないように、各々が 5s timeout 内で完結する。
  // *_secret probe は token endpoint に invalid code を投げて
  // client_secret 正否を判定する (Refs #217)。
  // jwt_secret_drift は rust-alc-api の canary endpoint と HMAC を突き合わせ
  // て JWT_SECRET の drift を検知する (Refs #218)。
  // secrets_format は Secrets Store binding の値の format (末尾 whitespace /
  // JSON 整合) を値非開示で検査する (Refs #208)。
  const [
    google,
    google_secret,
    github_mcp,
    github_mcp_secret,
    lineworks,
    egov,
    jwt_secret_drift,
    secrets_format,
  ] = await Promise.all([
    probeGoogle(env),
    probeGoogleSecret(env),
    probeGithubMcp(env),
    probeGithubMcpSecret(env),
    probeLineworks(env),
    probeEgov(env),
    probeJwtDrift(env),
    probeSecretsFormat(env),
  ]);
  const providers: Record<string, ProbeResult> = {
    google,
    google_secret,
    github_mcp,
    github_mcp_secret,
    lineworks,
    egov,
    jwt_secret_drift,
    secrets_format,
  };
  const overall = computeOverall(providers);

  console.log(JSON.stringify({
    event: "health_oauth",
    overall,
    // provider 名 + 判定だけ。client_id 等は出さない。
    summary: Object.fromEntries(
      Object.entries(providers).map(([k, v]) => [
        k,
        "configured" in v && v.configured === false
          ? "skip"
          : "unknown" in v
            ? "unknown"
            : v.ok ? "ok" : "fail",
      ]),
    ),
  }));

  const body: HealthOAuthBody = {
    checked_at: new Date().toISOString(),
    overall,
    providers,
  };
  return new Response(JSON.stringify(body), {
    status: overall === "degraded" ? 503 : 200,
    headers: { "Content-Type": "application/json" },
  });
}
