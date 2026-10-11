/**
 * Workers RPC entrypoint — smb Worker (SMB の車検証 PDF を取り込む Cron worker) が
 * **service binding 越しにだけ**呼ぶ口 (Refs ohishi-exp/smb-watch#14)。
 *
 * 旧経路は社内の box (smb-watch) → carins `/api/device-upload` → auth-worker
 * `/device-data-proxy/api/files` (device JWT) → rust-alc-api `POST /api/files`
 * だった。box を Worker に置き換えるにあたり、**公開の upload 口と device JWT を
 * 無くし**、呼び手の identity はプラットフォーム保証の service binding に寄せる
 * (`InternalEntrypoint` の #483 と同じ考え方)。
 *
 * ★ **`InternalEntrypoint` とは別 class にしている** — 呼べるメソッドは binding の
 * `entrypoint = "..."` ごとに決まるので、分けておけば InternalEntrypoint の呼び手
 * (dtako-scraper-relay / timecard-cf-worker) は `ingestFile` を呼べず、smb Worker は
 * `forwardAlcTenantData` を呼べない (blast radius を binding 単位に閉じる)。
 *
 * ★ **呼び手に選ばせないもの**:
 *   - tenant — AUTH_CONFIG KV の `smb-ingest-tenant` で固定 (未設定なら fail-closed)
 *   - path / method — `POST /api/files` に固定
 *   - 通知の宛先 — `device-notify-targets` map の `smb-ingest` で固定
 * 呼び手が渡せるのはファイルの中身と通知の本文だけ。smb Worker が乗っ取られても
 * 「決まった tenant に PDF が増える / 決まった相手に文字列が飛ぶ」に留まる。
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
import {
  MAX_NOTIFY_TEXT_LEN,
  resolveNotifyRecipient,
  sendDeviceNotify,
} from "./lib/device-notify-send";

/** 取り込み先 tenant (UUID 文字列) を置く AUTH_CONFIG KV のキー。値はこの repo に入れない。 */
const TENANT_KEY = "smb-ingest-tenant";

/** `device-notify-targets` map の中で smb Worker の宛先を引く key。 */
const NOTIFY_KEY = "smb-ingest";

/** rust-alc-api の carins ファイル登録 (`{filename, type, content(base64)}`)。 */
const INGEST_PATH = "/api/files";

/** `contentBase64.length` の上限 (16 MiB)。超えたら Cloud Run を呼ばず 413。 */
const MAX_CONTENT_BASE64_LEN = 16 * 1024 * 1024;

/** `ingestFile` の引数。RPC 越しに渡るので serializable な素の値だけ。 */
export interface SmbIngestFileInput {
  filename: string;
  /** rust 側の `type` (保存時の Content-Type)。例 `application/pdf`。 */
  contentType: string;
  contentBase64: string;
}

export class SmbIngestEntrypoint extends WorkerEntrypoint<Env> {
  /** 1 ファイルを tenant (KV 固定) の carins ファイルとして登録する。 */
  async ingestFile(input: SmbIngestFileInput): Promise<AlcRpcResult> {
    const filename = input?.filename;
    const contentType = input?.contentType;
    const contentBase64 = input?.contentBase64;
    if (typeof filename !== "string" || !filename) return alcRpcError(400, "filename required");
    if (typeof contentType !== "string" || !contentType) {
      return alcRpcError(400, "contentType required");
    }
    if (typeof contentBase64 !== "string" || !contentBase64) {
      return alcRpcError(400, "contentBase64 required");
    }
    if (contentBase64.length > MAX_CONTENT_BASE64_LEN) {
      return alcRpcError(413, "payload_too_large");
    }

    // ★ tenant は KV からだけ。無い・空・UUID でない → Cloud Run を呼ばない。
    const tenantId = await resolveKvTenant(this.env, TENANT_KEY);
    if (!tenantId) return alcRpcError(503, "smb_ingest_tenant_unset");

    return forwardAlcTenantRequest(this.env, {
      tenantId,
      path: INGEST_PATH,
      method: "POST",
      body: JSON.stringify({ filename, type: contentType, content: contentBase64 }),
      contentType: "application/json",
    });
  }

  /** smb Worker の実行結果を LINE WORKS へ流す (宛先は KV 固定)。 */
  async notify(text: string): Promise<AlcRpcResult> {
    if (typeof text !== "string" || text.length === 0) return alcRpcError(400, "text required");
    if (text.length > MAX_NOTIFY_TEXT_LEN) {
      return alcRpcError(400, `text は ${MAX_NOTIFY_TEXT_LEN} 文字以内`);
    }

    const recipientId = await resolveNotifyRecipient(this.env, NOTIFY_KEY);
    if (!recipientId) return alcRpcError(503, "recipient_unset");

    const apiOrigin = this.env.ALC_API_ORIGIN;
    if (!apiOrigin) return alcRpcError(503, "server_error");

    const res = await sendDeviceNotify(this.env, apiOrigin, recipientId, text, {
      event: "smb_ingest_notify_upstream_failed",
    });
    return {
      status: res.status,
      body: await res.text(),
      contentType: res.headers.get("content-type"),
    };
  }
}
