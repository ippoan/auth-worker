/**
 * `GET /health/wif` (Bearer JWT 保護) — rust-alc-api#434 step 3 (方式 B) の
 * OIDC mint 機構が生きているかの health probe。
 *
 * `ALC_API_PROXY_SA_KEY` (= `run.invoker` 最小 SA key) で `ALC_API_ORIGIN` を
 * audience とする Google OIDC ID token を **実際に 1 回 mint** し、成否だけを返す。
 * Cloud Run を `--no-allow-unauthenticated` にした後、auth-worker の data-proxy
 * (`/alc-proxy/*`) が backend に到達できるか == この mint が通るか、なので、
 * SA key rotation 漏れ / 鍵失効 / Google token endpoint 障害を deploy 前後や
 * 定期 schedule で検知できる。
 *
 * 値非開示:
 *   - mint した id_token そのものは log / response に **一切出さない**。
 *   - 出すのは `ok` / `audience` (= ALC_API_ORIGIN、既知) / `mode` / `hint` だけ。
 *   - SA private key も当然出さない。
 *
 * mint は `noCache: true` で毎回フル経路 (assertion 署名 → token endpoint) を
 * 走らせる。cache hit で「鍵が失効しても暫く ok を返す」を防ぐ。
 *
 * Bearer JWT 保護: 実 token を毎回 mint = Google token endpoint quota を消費
 * するため、`/health/oauth` と同じく JWT_SECRET 署名の Bearer を要求する。
 *
 * Refs ippoan/rust-alc-api#434 (step 3 / Cloud Run IAM lockdown)。
 */
import type { Env } from "../index";
import { verifyJwt } from "../lib/jwt";
import { resolveSecret } from "../lib/secret";
import { mintGoogleIdToken } from "../lib/oidc";

type ProbeResult =
  | { configured: false }
  | { configured: true; ok: true; audience: string }
  | { configured: true; ok: false; audience: string; hint: string }
  | { configured: true; unknown: true; audience: string; hint: string };

interface HealthWifBody {
  checked_at: string;
  overall: "ok" | "degraded" | "unknown";
  oidc_mint: ProbeResult;
}

/** SA key で audience (= ALC_API_ORIGIN) 向けの OIDC ID token を 1 回 mint して成否判定。 */
async function probeOidcMint(env: Env): Promise<ProbeResult> {
  const saKey = await resolveSecret(env.ALC_API_PROXY_SA_KEY);
  // SA key 未 bind (= まだ step 3 を配線していない env、例: prod) は skip。
  if (!saKey) return { configured: false };

  const audience = env.ALC_API_ORIGIN ?? "";
  if (!audience) {
    return {
      configured: true,
      unknown: true,
      audience: "",
      hint: "ALC_API_ORIGIN not set — no audience to mint for",
    };
  }

  try {
    // noCache: 毎回フル経路を走らせる (cache hit で失効を見逃さない)。
    // 返り値 (id_token) は捨てる。値は response / log に出さない。
    await mintGoogleIdToken(saKey, audience, { noCache: true });
    return { configured: true, ok: true, audience };
  } catch (e: unknown) {
    // oidc.ts の throw 文言は値非依存 (例: "token endpoint 401" /
    // "invalid service account key")。そのまま hint に載せて良い。
    return {
      configured: true,
      ok: false,
      audience,
      hint: e instanceof Error ? e.message : String(e),
    };
  }
}

function computeOverall(p: ProbeResult): "ok" | "degraded" | "unknown" {
  if ("ok" in p && p.ok === false) return "degraded";
  if (("unknown" in p && p.unknown === true) || ("configured" in p && p.configured === false)) {
    return "unknown";
  }
  return "ok";
}

export async function handleHealthWif(request: Request, env: Env): Promise<Response> {
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) {
    return new Response("server not configured", { status: 503 });
  }

  const auth = request.headers.get("authorization") ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  // env claim があれば WORKER_ENV と一致を強制 (/health/oauth と同方針)。
  const payload = token ? await verifyJwt(token, jwtSecret, env.WORKER_ENV) : null;
  if (!payload) {
    return new Response("unauthorized", { status: 401 });
  }

  const oidc_mint = await probeOidcMint(env);
  const overall = computeOverall(oidc_mint);

  console.log(JSON.stringify({
    event: "health_wif",
    overall,
    // 判定だけ。audience / token は出さない。
    mint: "configured" in oidc_mint && oidc_mint.configured === false
      ? "skip"
      : "unknown" in oidc_mint
        ? "unknown"
        : oidc_mint.ok ? "ok" : "fail",
  }));

  const body: HealthWifBody = {
    checked_at: new Date().toISOString(),
    overall,
    oidc_mint,
  };
  return new Response(JSON.stringify(body), {
    status: overall === "degraded" ? 503 : 200,
    headers: { "Content-Type": "application/json" },
  });
}
