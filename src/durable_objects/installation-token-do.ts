/**
 * `InstallationTokenStore` — GitHub App installation access token を installation_id
 * ごとに 1 instance で cache する Durable Object。
 *
 * Phase 1 admin auth (issue #42 follow-up) のキャッシュ層。`/mcp/admin/exec` で
 * branch protection 更新等の write 操作を行う際、毎回 App JWT を組み立てて
 * `/app/installations/{id}/access_tokens` を叩くと latency + rate-limit が問題に
 * なるので、本 DO で 1h 有効な installation token を保持する。
 *
 * - DO id は `idFromName(installation_id)` で派生 → 同一 installation の同時
 *   refresh は DO の single-thread 化で自然に直列化される。
 * - Cache hit 条件: 残 TTL > 5min。5min buffer は GitHub 側の clock skew /
 *   network 遅延を吸収するための保守値 (token は 1h 有効、buffer 5min なら
 *   実 cache 時間 ~55min)。
 * - Refresh 失敗 (non-2xx) は throw して caller に状態を伝える。失敗 token は
 *   storage に書かない (= 次回呼び出しで再 refresh)。
 */

import { pemToCryptoKey, signAppJwt } from "../lib/github-app-token";

interface CachedToken {
  token: string;
  /** Unix epoch seconds. GitHub の `expires_at` (RFC3339) を秒に変換した値。 */
  expires_at_epoch_sec: number;
}

/** DO が必要とする env subset。secret は env 経由で受け取る (binding 経由ではない)。 */
export interface InstallationTokenEnv {
  GITHUB_APP_ID?: string;
  GITHUB_APP_PRIVATE_KEY?: string;
}

/** Cache hit と判定する残 TTL の下限 (秒)。これより短ければ refresh する。 */
const TOKEN_REFRESH_BUFFER_SEC = 5 * 60;

const STORAGE_KEY = "cached_token";
const GITHUB_API = "https://api.github.com";
const GITHUB_UA = "ippoan-auth-worker";

export class InstallationTokenStore implements DurableObject {
  state: DurableObjectState;
  env: InstallationTokenEnv;
  /** in-memory cache; storage は cold start / hibernation 跨ぎ用 backup。 */
  private cached: CachedToken | null = null;

  constructor(state: DurableObjectState, env: InstallationTokenEnv) {
    this.state = state;
    this.env = env;
  }

  async fetch(req: Request): Promise<Response> {
    if (!this.env.GITHUB_APP_ID || !this.env.GITHUB_APP_PRIVATE_KEY) {
      return new Response(
        JSON.stringify({ error: "github_app_not_configured" }),
        { status: 503, headers: { "Content-Type": "application/json" } },
      );
    }
    const installationId = this.state.id.name;
    if (!installationId) {
      return new Response(
        JSON.stringify({ error: "installation_id_missing" }),
        { status: 500, headers: { "Content-Type": "application/json" } },
      );
    }
    try {
      const token = await this.getOrRefresh(installationId);
      return new Response(JSON.stringify(token), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return new Response(
        JSON.stringify({ error: "installation_token_refresh_failed", message: msg }),
        { status: 502, headers: { "Content-Type": "application/json" } },
      );
    }
  }

  private async getOrRefresh(installationId: string): Promise<CachedToken> {
    if (!this.cached) {
      const stored = await this.state.storage.get<CachedToken>(STORAGE_KEY);
      if (stored) this.cached = stored;
    }
    const nowSec = Math.floor(Date.now() / 1000);
    if (
      this.cached &&
      this.cached.expires_at_epoch_sec - nowSec > TOKEN_REFRESH_BUFFER_SEC
    ) {
      return this.cached;
    }
    const fresh = await this.refresh(installationId, nowSec);
    this.cached = fresh;
    await this.state.storage.put(STORAGE_KEY, fresh);
    return fresh;
  }

  private async refresh(
    installationId: string,
    nowSec: number,
  ): Promise<CachedToken> {
    const appId = this.env.GITHUB_APP_ID!;
    const pem = this.env.GITHUB_APP_PRIVATE_KEY!;
    const key = await pemToCryptoKey(pem);
    const appJwt = await signAppJwt(appId, key, nowSec);
    const url = `${GITHUB_API}/app/installations/${encodeURIComponent(installationId)}/access_tokens`;
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${appJwt}`,
        Accept: "application/vnd.github+json",
        "User-Agent": GITHUB_UA,
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });
    if (!resp.ok) {
      const body = await resp.text();
      throw new Error(`github_app_installation_token_failed: status=${resp.status} body=${body}`);
    }
    const parsed = (await resp.json()) as { token?: string; expires_at?: string };
    if (!parsed.token || !parsed.expires_at) {
      throw new Error("github_app_installation_token_invalid_response");
    }
    const expiresAtMs = Date.parse(parsed.expires_at);
    if (Number.isNaN(expiresAtMs)) {
      throw new Error(`github_app_installation_token_invalid_expires_at: ${parsed.expires_at}`);
    }
    return {
      token: parsed.token,
      expires_at_epoch_sec: Math.floor(expiresAtMs / 1000),
    };
  }
}
