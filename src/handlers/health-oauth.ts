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
import { verifyJwt } from "../lib/jwt";
import { resolveSecret } from "../lib/secret";

/** 外部 provider への probe 1 回のタイムアウト (ms)。 */
const PROBE_TIMEOUT_MS = 5000;

type ProbeMode = "client_id_check" | "reachability";

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
// lineworks — reachability only (client_id は rust-alc-api 側)
// ---------------------------------------------------------------------------

async function probeLineworks(env: Env): Promise<ProbeResult> {
  const mode: ProbeMode = "reachability";
  // LINE WORKS の credentials は rust-alc-api 側の `bot_secret_encrypted` に
  // 暗号化保存されており、worker env には無い。**reachability** として
  // rust-alc-api の lineworks redirect endpoint がパラメータ不足で正規に
  // 400 を返すかを確認する (404 や 5xx なら rust-alc-api 側の障害)。
  if (!env.ALC_API_ORIGIN) return { configured: false };

  const url = `${env.ALC_API_ORIGIN}/api/auth/lineworks/redirect`;
  const res = await timedFetch(url);
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
  const payload = token ? await verifyJwt(token, jwtSecret) : null;
  if (!payload) {
    return new Response("unauthorized", { status: 401 });
  }

  // 4 provider 並列実行 (Promise.all)。1 つの probe の latency が全体を
  // 引っ張らないように、各々が 5s timeout 内で完結する。
  const [google, github_mcp, lineworks, egov] = await Promise.all([
    probeGoogle(env),
    probeGithubMcp(env),
    probeLineworks(env),
    probeEgov(env),
  ]);
  const providers: Record<string, ProbeResult> = { google, github_mcp, lineworks, egov };
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
