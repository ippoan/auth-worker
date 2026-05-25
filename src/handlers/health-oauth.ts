/**
 * OAuth client_id health check (issue #209)
 *
 * `GET /health/oauth` (Bearer JWT 保護) で各 OAuth provider の認可エンドポイントを
 * `redirect: "manual"` で 1 回叩き、status + 本文の特徴から client_id の生死を判定する。
 * 既存 `/api/health` (ALC API proxy) とは関心が違うので独立ハンドラとして実装。
 *
 * PR1 では Google のみ実装。残り 3 provider (github_mcp / lineworks / egov) は PR2 で追加。
 *
 * 判定方針:
 *   - 正常: 認可エンドポイントがログイン/同意画面へ 302 リダイレクト
 *   - 不正: provider 側がエラー応答 (Google なら 400 + "The OAuth client was not found")
 *   - 不明: fetch 失敗 / タイムアウト等 → `ok: false` ではなく `unknown: true` 扱い
 *           (誤検知防止。CI は overall === "degraded" のみで fail させる)
 */
import type { Env } from "../index";
import { verifyJwt } from "../lib/jwt";
import { resolveSecret } from "../lib/secret";

/** 外部 provider への probe 1 回のタイムアウト (ms)。 */
const PROBE_TIMEOUT_MS = 5000;

type ProbeOk = { configured: true; ok: boolean; status: number; hint?: string };
type ProbeUnknown = { configured: true; unknown: true; hint: string };
type ProbeResult = { configured: false } | ProbeOk | ProbeUnknown;

interface HealthOAuthBody {
  checked_at: string;
  overall: "ok" | "degraded" | "unknown";
  providers: Record<string, ProbeResult>;
}

async function probeGoogle(env: Env): Promise<ProbeResult> {
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

  let res: Response;
  try {
    res = await fetch(u.toString(), {
      redirect: "manual",
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
  } catch (e: unknown) {
    return {
      configured: true,
      unknown: true,
      hint: `fetch failed: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  // Refs #209: 実応答観測 (PR1 merge 後、staging deploy 不要で curl 検証済) で、
  // Google は client_id 正否に関わらず HTTP 302 で同じ host (`accounts.google.com`)
  // に飛ばす。判定は **Location の path / query** で行う:
  //   正常: path `/v3/signin/identifier` 等 (ログイン画面) — `authError=` 無し
  //   異常: path `/signin/oauth/error?authError=...` (base64 で
  //         `invalid_client / The OAuth client was not found.` 等)
  // 旧実装は `/[?&]error=/` のみ見ていたため `authError=` (大文字 A) を取りこぼし、
  // invalid_client を ok と誤判定していた。
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
          hint: "invalid_client — client_id may be wrong",
        };
      }
      return { configured: true, ok: true, status: res.status };
    }
    return {
      configured: true,
      unknown: true,
      hint: `redirected to unexpected host ${locUrl?.host ?? "(malformed Location)"}`,
    };
  }

  // 30x 以外 (4xx / 5xx / 200) は実応答観測では確認されなかったが、
  // 将来 Google が挙動を変えた場合の防御として本文を sniff する。
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
      hint: "invalid_client — client_id may be wrong",
    };
  }
  return {
    configured: true,
    unknown: true,
    hint: `unexpected status ${res.status}`,
  };
}

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

  const providers: Record<string, ProbeResult> = {
    google: await probeGoogle(env),
    // PR2: github_mcp / lineworks / egov を追加
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
