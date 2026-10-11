/**
 * Workers RPC entrypoint — 勤怠 Worker `ichibanboshi-kintai` (rust-ichibanboshi の
 * `workers/kintai/worker`) が **service binding 越しにだけ**呼ぶ alc 読みの口
 * (Refs ohishi-exp/rust-ichibanboshi#322)。
 *
 * 勤怠 Worker が alc (rust-alc-api) から読むのは運行イベントの 2 path だけ:
 *   - `GET /api/dtako/events/etags` — 運行の識別子だけ (`dtakoEtags`)
 *   - `GET /api/dtako/events` — 運行イベント本体。`driver_cd` を省くと期間内の全乗務員 (`dtakoEvents`)
 * 受け側の 2 path は GET だけ (rust-alc-api `crates/alc-dtako/src/dtako_events.rs:116`)。
 *
 * ★ **`InternalEntrypoint` とは別 class にしている** — InternalEntrypoint の
 * `FORWARDABLE_PATHS` は path だけを見て tenant を呼び手任せにしているので、そこに
 * events を足すと、既に bind している relay (dtako-scraper-relay) / timecard-cf-worker まで
 * 任意 tenant の全乗務員の運行イベント本体を読めるようになる。呼べるメソッドは binding の
 * `entrypoint = "..."` ごとに決まるので、分けておけば blast radius を binding 単位に閉じられる。
 * **呼び手 = 勤怠 Worker だけ**。
 *
 * ★ **呼び手に選ばせないもの**:
 *   - tenant — AUTH_CONFIG KV の `kintai-alc-tenant` で固定 (無い・空・UUID でない → 503、fail-closed)
 *   - path / method — 上の 2 path の GET に固定
 * 呼び手が渡せるのは query だけで、それも**鍵の allowlist** で絞る (知らない鍵・同じ鍵の重複は
 * 400 で Cloud Run を呼ばない)。**値の形は検査しない** — 受け側 (serde が日付を検査し
 * page_size を clamp する) と二重に持つと drift するため。
 *
 * 失敗は throw せず `{status, body, contentType}` で返す (`InternalEntrypoint` と同じ流儀)。
 */
import { WorkerEntrypoint } from "cloudflare:workers";
import type { Env } from "./index";
import {
  alcRpcError,
  forwardAlcTenantRequest,
  resolveKvTenant,
  type AlcRpcResult,
} from "./lib/alc-tenant-forward";

/** 読み先 tenant (UUID 文字列) を置く AUTH_CONFIG KV のキー。値はこの repo に入れない。 */
const TENANT_KEY = "kintai-alc-tenant";

const ETAGS_PATH = "/api/dtako/events/etags";
const ETAGS_KEYS: ReadonlySet<string> = new Set(["date_from", "date_to"]);

const EVENTS_PATH = "/api/dtako/events";
const EVENTS_KEYS: ReadonlySet<string> = new Set([
  "date_from",
  "date_to",
  "driver_cd",
  "page_size",
  "after_driver_cd",
]);

/**
 * `search` (`a=1&b=2`、先頭 `?` は有っても無くても良い) の鍵を allowlist で検査し、
 * 通ったら転送する query を返す。知らない鍵・同じ鍵の重複 → `null`。
 * 転送するのは検査した `URLSearchParams` を直した文字列 (検査したものと送るものを一致させる)。
 */
function checkQuery(search: unknown, allowed: ReadonlySet<string>): string | null {
  if (typeof search !== "string") return null;
  const params = new URLSearchParams(search.startsWith("?") ? search.slice(1) : search);
  const seen = new Set<string>();
  for (const key of params.keys()) {
    if (!allowed.has(key) || seen.has(key)) return null;
    seen.add(key);
  }
  return params.toString();
}

export class KintaiAlcEntrypoint extends WorkerEntrypoint<Env> {
  /** `GET /api/dtako/events/etags` (tenant は KV 固定)。 */
  async dtakoEtags(search: string): Promise<AlcRpcResult> {
    return this.forward(ETAGS_PATH, ETAGS_KEYS, search);
  }

  /** `GET /api/dtako/events` (tenant は KV 固定)。 */
  async dtakoEvents(search: string): Promise<AlcRpcResult> {
    return this.forward(EVENTS_PATH, EVENTS_KEYS, search);
  }

  private async forward(
    path: string,
    allowed: ReadonlySet<string>,
    search: string,
  ): Promise<AlcRpcResult> {
    const query = checkQuery(search, allowed);
    if (query === null) return alcRpcError(400, "query_not_allowed");

    // ★ tenant は KV からだけ。無い・空・UUID でない → Cloud Run を呼ばない。
    const tenantId = await resolveKvTenant(this.env, TENANT_KEY);
    if (!tenantId) return alcRpcError(503, "kintai_alc_tenant_unset");

    return forwardAlcTenantRequest(this.env, { tenantId, path, method: "GET", search: query });
  }
}
