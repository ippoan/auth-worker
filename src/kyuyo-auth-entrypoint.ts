/**
 * Workers RPC entrypoint — 次の 2 つの呼び手が **service binding 越しにだけ**呼ぶ
 * 認可の口 (Refs ohishi-exp/rust-ichibanboshi#322)。
 *   ① 給与大臣の読み出し Worker (`ichibanboshi-kyuyo`、rust-ichibanboshi の workers/kyuyo)
 *   ② nuxt-dtako-admin の relay (`dtako-scraper-relay`、binding `AUTH_KYUYO`)。
 *      給与閲覧の口 (wage-range / wage-snapshot) の認可確認に使う
 *      (Refs ohishi-exp/nuxt-dtako-admin#1195)
 *
 * 旧経路は rust-ichibanboshi `src/kyuyo/introspect.rs` が `POST /auth/introspect`
 * にブラウザ JWT を送り、返った email を rust 側の allowlist と照合していた。
 * Worker 側に secret も allowlist も持たせないため、**「給与を見てよいか」を
 * auth-worker が答える** (`SmbIngestEntrypoint` と同じ形)。
 *
 * ★ **`InternalEntrypoint` / `SmbIngestEntrypoint` とは別 class にしている** —
 * 呼べるメソッドは binding の `entrypoint = "..."` ごとに決まるので、この entrypoint を
 * bind した Worker (給与大臣 Worker と relay) は `authorize` しか呼べず、他の entrypoint を
 * bind した呼び手は `authorize` を呼べない (blast radius を binding 単位に閉じる)。
 *
 * ★ **呼び手に選ばせないもの**:
 *   - origin — `KYUYO_APP_ORIGIN` に固定 (どちらの呼び手も給与画面 (dtako) のための口なので定数)
 *   - allowlist — AUTH_CONFIG KV の `kyuyo-allowed-emails` で固定 (未設定なら 503)
 * 呼び手が渡せるのはブラウザ JWT だけ。
 *
 * ★ **`USER_ACL` / introspect の `org_wide` は流用しない** — あちらは「テナント
 * 境界を越えてよい人」で、流用すると USER_ACL の全員が給与を見られる。
 *
 * 失敗は throw せず `{status, body, contentType}` で返す (`SmbIngestEntrypoint` と同じ流儀)。
 */
import { WorkerEntrypoint } from "cloudflare:workers";
import type { Env } from "./index";
import { introspectToken } from "./handlers/auth-introspect";
import { alcRpcError, type AlcRpcResult } from "./lib/alc-tenant-forward";
import { getKyuyoAllowedEmails } from "./lib/config";
import { resolveMcpJwtSecret, verifyMcpJwt } from "./lib/mcp-jwt";
import { resolveSecret } from "./lib/secret";

/** 給与画面の origin。`APP_TENANT_ACL` / `app-orgs` の判定はこの origin で引く。 */
const KYUYO_APP_ORIGIN = "https://dtako.ippoan.org";

/**
 * `authorizeMcp` が受け付ける binding_jwt の `iss`。kyuyo-mcp の AS は auth-worker-staging
 * (kyuyo-mcp の `AUTH_WORKER_ORIGIN`) で、mint 時の `iss` は発行元の `AUTH_WORKER_ORIGIN`。
 * kyuyo-mcp の resource origin を許可しているのは staging の vars だけ (本番の
 * `MCP_RESOURCE_ORIGINS_ALLOWLIST` に無い) なので、本番発行の kyuyo-mcp 向け token は無い。
 * `iss` の無い旧 token も受けない。
 * `MCP_JWT_SECRET` は本番と staging で同じ Secrets Store entry なので、本番の auth-worker でも
 * staging 発行の token の署名を検証できる — だからこそ `iss` と `aud` を明示列挙で縛る。
 */
const KYUYO_MCP_ISSUERS: readonly string[] = ["https://auth-staging.ippoan.org"];

/**
 * `authorizeMcp` が受け付ける binding_jwt の `aud` の origin。`aud` は MCP client が
 * `/authorize` に送った resource URI そのもの (path は client 次第) なので、origin で比べる。
 * 他の MCP (gmail-mcp 等) 向けの token は同じ鍵で署名されていても通さない
 * (`audPredicate` = 全 resource 許可は使わない)。
 */
const KYUYO_MCP_AUD_ORIGIN = "https://kyuyo-mcp.ippoan.org";

function isKyuyoMcpAud(aud: string): boolean {
  try {
    return new URL(aud).origin === KYUYO_MCP_AUD_ORIGIN;
  } catch {
    return false;
  }
}

export class KyuyoAuthEntrypoint extends WorkerEntrypoint<Env> {
  /**
   * ブラウザ JWT の持ち主が給与を見てよいかを返す。
   *   200 `{allowed:true, email}` / 401 unauthorized / 403 forbidden /
   *   503 kyuyo_allowlist_unset・server_error
   */
  async authorize(token: string): Promise<AlcRpcResult> {
    // ── 設定の確定 (どちらか欠けたら判定しない = fail-closed) ─────────────────
    const jwtSecret = await resolveSecret(this.env.JWT_SECRET);
    if (!jwtSecret) return alcRpcError(503, "server_error");
    // 空の一覧で全員拒否にはしない — 「設定不備」として 503 にし、気づけるようにする。
    const allowed = await getKyuyoAllowedEmails(this.env);
    if (!allowed) return alcRpcError(503, "kyuyo_allowlist_unset");

    // ── `/auth/introspect` と同じ判定 ────────────────────────────────────────
    const result = await introspectToken(
      this.env,
      jwtSecret,
      typeof token === "string" ? token : "",
      KYUYO_APP_ORIGIN,
    );
    if (!result.active) return alcRpcError(401, "unauthorized");

    const email = result.email.trim().toLowerCase();
    if (!allowed.includes(email)) return alcRpcError(403, "forbidden");

    return {
      status: 200,
      body: JSON.stringify({ allowed: true, email }),
      contentType: "application/json",
    };
  }

  /**
   * kyuyo-mcp (MCP client) から受け取った **binding_jwt** の持ち主が給与を見てよいかを返す
   * (Refs #p414)。呼び手は給与大臣 Worker で、`X-Kyuyo-Auth: mcp` のときだけここを呼ぶ。
   * 応答の形は `authorize` と同じ:
   *   200 `{allowed:true, email}` / 401 unauthorized / 403 forbidden /
   *   503 kyuyo_allowlist_unset・server_error
   *
   * ★ **`authorize` とは検証器を混ぜない** — こちらは `MCP_JWT_SECRET` の HS256 (署名・期限・
   *   `aud`・`iss`) だけで、ブラウザ JWT (`JWT_SECRET`) は 401。逆に `authorize` は binding_jwt を
   *   401 にする。どちらの token も相手のメソッドでは通らない。
   * ★ **allowlist は `authorize` と同じ** — AUTH_CONFIG KV の `kyuyo-allowed-emails`
   *   (`getKyuyoAllowedEmails`)。MCP でも一覧外の人は 403。
   * ★ **テナントの origin ACL (`APP_TENANT_ACL` / `app-orgs` + `TENANT_ACL`) は当てない** —
   *   binding_jwt には `tenant_id` claim が無く、照合する対象が無い。代わりに「Google ログイン
   *   した本人の email が一覧にある」ことだけを条件にする (一覧が給与を見てよい人の正本)。
   * ★ **Google flow の token に限る** — `sub` が `google:` で `email` claim があるもの。
   *   GitHub flow の token は email を持たないので 401。
   */
  async authorizeMcp(token: string): Promise<AlcRpcResult> {
    // ── 設定の確定 (どちらか欠けたら判定しない = fail-closed) ─────────────────
    const jwtSecret = await resolveMcpJwtSecret(this.env.MCP_JWT_SECRET);
    if (!jwtSecret) return alcRpcError(503, "server_error");
    const allowed = await getKyuyoAllowedEmails(this.env);
    if (!allowed) return alcRpcError(503, "kyuyo_allowlist_unset");

    // ── binding_jwt の検証 (署名・exp・aud → iss → Google flow) ─────────────
    const payload = await verifyMcpJwt(
      typeof token === "string" ? token : "",
      jwtSecret,
      isKyuyoMcpAud,
    );
    if (
      !payload ||
      typeof payload.iss !== "string" ||
      !KYUYO_MCP_ISSUERS.includes(payload.iss) ||
      typeof payload.sub !== "string" ||
      !payload.sub.startsWith("google:") ||
      typeof payload.email !== "string"
    ) {
      return alcRpcError(401, "unauthorized");
    }

    const email = payload.email.trim().toLowerCase();
    if (!allowed.includes(email)) return alcRpcError(403, "forbidden");

    return {
      status: 200,
      body: JSON.stringify({ allowed: true, email }),
      contentType: "application/json",
    };
  }
}
