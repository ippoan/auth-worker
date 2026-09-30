/**
 * Workers RPC entrypoint — 給与大臣の読み出し Worker (`ichibanboshi-kyuyo`、
 * rust-ichibanboshi の workers/kyuyo) が **service binding 越しにだけ**呼ぶ
 * 認可の口 (Refs ohishi-exp/rust-ichibanboshi#322)。
 *
 * 旧経路は rust-ichibanboshi `src/kyuyo/introspect.rs` が `POST /auth/introspect`
 * にブラウザ JWT を送り、返った email を rust 側の allowlist と照合していた。
 * Worker 側に secret も allowlist も持たせないため、**「給与を見てよいか」を
 * auth-worker が答える** (`SmbIngestEntrypoint` と同じ形)。
 *
 * ★ **`InternalEntrypoint` / `SmbIngestEntrypoint` とは別 class にしている** —
 * 呼べるメソッドは binding の `entrypoint = "..."` ごとに決まるので、給与 Worker は
 * `authorize` しか呼べず、他の呼び手は `authorize` を呼べない (blast radius を
 * binding 単位に閉じる)。
 *
 * ★ **呼び手に選ばせないもの**:
 *   - origin — `KYUYO_APP_ORIGIN` に固定 (binding の consumer が固定なので定数)
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
import { resolveSecret } from "./lib/secret";

/** 給与画面の origin。`APP_TENANT_ACL` / `app-orgs` の判定はこの origin で引く。 */
const KYUYO_APP_ORIGIN = "https://dtako.ippoan.org";

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
}
