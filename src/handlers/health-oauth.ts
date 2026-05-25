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

  // 正: 302 で accounts.google.com のセッション/同意画面へ。
  //     Cloudflare Workers fetch は `redirect: "manual"` で 30x を保持する。
  // 誤: 400 + 本文 "The OAuth client was not found."
  //     (status 400 ではなく 200 で error HTML を返すこともあるので本文も見る)
  const loc = res.headers.get("location") ?? "";
  if (res.status >= 300 && res.status < 400 && loc) {
    const ok = !/[?&]error=/.test(loc);
    return ok
      ? { configured: true, ok: true, status: res.status }
      : {
          configured: true,
          ok: false,
          status: res.status,
          hint: "authorization endpoint redirected to error",
        };
  }

  // 4xx / 5xx / 200 with error body → ok:false。本文を一度だけ読む。
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
