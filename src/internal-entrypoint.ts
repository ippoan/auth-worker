/**
 * Workers RPC entrypoint (`WorkerEntrypoint`) — **service binding からしか呼べない**
 * 内部専用の口 (issue #483)。
 *
 * `export default { fetch }` (src/index.ts) は `auth.ippoan.org` の公開ハンドラと
 * **同一のもの**なので、binding 越しの呼び出しと公開 HTTPS を区別できない。
 * だから `/device-data-proxy` は「binding の内側にいるのに bearer (device JWT) を
 * 提示する」形になっていた (pairing・KV 投入・credential 管理が全部必要)。
 *
 * **RPC の名前付きメソッドは HTTP の面に出ない** — 呼べるのは
 * `[[services]] entrypoint = "InternalEntrypoint"` を宣言した同一アカウントの
 * worker だけで、呼び元はプラットフォーム保証。よって credential は要らない。
 * 残る境界は「このアカウントの、binding を宣言した worker なら呼べる」で、
 * 漏れうる bearer より強い (#434 の X-Tenant-ID 詐称懸念は RPC には当たらない)。
 *
 * ★ **汎用の転送口にしないこと。** allowlist は**引数ではなくこのファイルに埋める**
 * (`FORWARDABLE_PATHS`)。「任意 path を転送する」形にすると #482 と同じ穴を
 * 自分で開けることになる。
 *
 * 値 (OIDC / SA key) は log / 戻り値に出さない。
 */
import { WorkerEntrypoint } from "cloudflare:workers";
import type { Env } from "./index";
import { resolveSecret } from "./lib/secret";
import { mintGoogleIdToken } from "./lib/oidc";

/**
 * rust-alc-api へ転送を許可する path。**この 2 本だけ** (dtako-scraper-relay の
 * スクレイプ履歴、Refs ohishi-exp/nuxt-dtako-admin#931 / #933)。
 *
 * `/device-data-proxy` の `ROLE_PATH_ALLOWLIST[device-dtako-relay]` と同じ 2 本で、
 * **method は見ない** — `/api/scraper/history` の 1 行で GET (履歴を読む =
 * #933) と POST (無人実行を載せる = #931) の両方が通る。読めない履歴に書いても
 * 意味が無いので意図的にそうしている。
 */
const FORWARDABLE_PATHS: ReadonlySet<string> = new Set([
  "/api/scraper/history",
  "/api/dtako/events/etags",
]);

/** `forwardAlcTenantData` の引数。RPC 越しに渡るので serializable な素の値だけ。 */
export interface ForwardAlcTenantDataInput {
  /** 転送先に `X-Tenant-ID` として注入する tenant。空なら 400。 */
  tenantId: string;
  /** rust-alc-api 側の path。`FORWARDABLE_PATHS` に無ければ**転送せず** 403。 */
  path: string;
  method: string;
  /** `?a=1&b=2` (先頭 `?` は有っても無くても良い)。 */
  search?: string;
  body?: string;
  contentType?: string;
}

/**
 * `forwardAlcTenantData` の戻り値。
 *
 * ★ `Response` をそのまま返さない — RPC 越しの `Response` は寿命の扱いが増えるだけで、
 * この用途 (小さい JSON) には要らない。**素の serializable オブジェクト**にする。
 */
export interface ForwardAlcTenantDataResult {
  status: number;
  body: string;
  contentType: string | null;
}

function errorResult(status: number, error: string): ForwardAlcTenantDataResult {
  return { status, body: JSON.stringify({ error }), contentType: "application/json" };
}

export class InternalEntrypoint extends WorkerEntrypoint<Env> {
  /**
   * dtako-scraper-relay (service binding 越し) が rust-alc-api の tenant data 経路
   * (`require_tenant_header`) を叩くための転送。
   *
   * 失敗は **throw せず戻り値**で返す (呼び手が握り潰しにくい形にする — RPC の
   * throw は呼び元で `try {} catch {}` に消されがちで、403 が「取得 0 件」に
   * 化けるのが一番まずい)。
   */
  async forwardAlcTenantData(
    input: ForwardAlcTenantDataInput,
  ): Promise<ForwardAlcTenantDataResult> {
    // ── ① tenant (転送先の `require_tenant_header` に渡る唯一の identity) ──────
    const tenantId = input.tenantId || "";
    if (!tenantId) return errorResult(400, "tenant_id required");

    // ── ② path allowlist。★ ここより前に fetch を一切しない ────────────────────
    //     (allowlist 外は「転送しない」だけでなく、OIDC mint すらしない)
    const path = input.path || "";
    if (!FORWARDABLE_PATHS.has(path)) return errorResult(403, "forbidden");

    // ── ③ env guard ──────────────────────────────────────────────────────────
    const saKey = await resolveSecret(this.env.ALC_API_PROXY_SA_KEY);
    if (!saKey) return errorResult(503, "internal entrypoint not configured");
    const apiOrigin = this.env.ALC_API_ORIGIN;
    if (!apiOrigin) return errorResult(503, "server_error");

    // ── ④ OIDC mint (Cloud Run IAM lockdown 用、aud=service URL) ──────────────
    let idToken: string;
    try {
      idToken = await mintGoogleIdToken(saKey, apiOrigin);
    } catch {
      return errorResult(502, "upstream auth error"); // 詳細は log のみ
    }

    // ── ⑤ forward ────────────────────────────────────────────────────────────
    const rawSearch = input.search || "";
    const search = !rawSearch || rawSearch.startsWith("?") ? rawSearch : `?${rawSearch}`;
    const target = `${apiOrigin.replace(/\/$/, "")}${path}${search}`;

    const headers: Record<string, string> = {
      Authorization: `Bearer ${idToken}`,
      "X-Tenant-ID": tenantId,
    };
    if (input.contentType) headers["Content-Type"] = input.contentType;

    const method = (input.method || "GET").toUpperCase();
    const hasBody = method !== "GET" && method !== "HEAD";

    const res = await fetch(target, {
      method,
      headers,
      body: hasBody ? input.body : undefined,
    });

    return {
      status: res.status,
      body: await res.text(),
      contentType: res.headers.get("content-type"),
    };
  }
}

export { FORWARDABLE_PATHS as INTERNAL_ENTRYPOINT_FORWARDABLE_PATHS };
