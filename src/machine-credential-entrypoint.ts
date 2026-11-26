/**
 * Workers RPC entrypoint — 機械用資格情報のチケットの口 (Refs ohishi-exp/rust-leave-worker#1)。
 * **service binding 越しにだけ**呼ばれる (`[[services]] entrypoint = "MachineCredentialEntrypoint"`)。
 *
 * 呼び手:
 *   - nuxt-leave (`/dav/**` の受け口): PUT の `Authorization: Basic ...` と PDF の sha256 で `issueTicket`
 *   - rust-leave-worker (R2 通知の Queue): R2 の customMetadata のチケットで `verifyTicket`
 *
 * ★ **公開の fetch 面に Basic の分岐を足さない** — 足すと「Basic を持たない者が X-Tenant-ID を名乗る」
 * (#434) の形を再び開くため。Basic を受けるのはこの RPC だけで、tenant は資格情報の KV からだけ決まる。
 *
 * ★ **etc-scan は APP_TENANT_ACL の dtako origin で tenant を照合する (Refs ohishi-exp/nuxt-dtako-admin#1287)**。
 * 用途ごとの照合先は `MACHINE_CRED_APP_ORIGINS` (`lib/machine-credential.ts`) 1 か所。表にある用途は、
 * 発行でも検証でも資格情報の tenant を `checkAppTenant` (機械なので email は渡さない) に通し、
 * 許されなければ null (発行後に ACL から外された tenant のチケットも検証で止まる)。
 * `apps` にその origin が無い・`APP_TENANT_ACL` が無い/壊れているときは `checkAppTenant` の既存仕様どおり通る。
 * 表に無い用途 (leave-scan・fuel-utran) は照合しない。
 *
 * ★ **`InternalEntrypoint` とは別 class** — 呼べるメソッドは binding の `entrypoint` ごとに決まるので、
 * 分けておけば他の binding の呼び手はチケットを発行できない (blast radius を binding 単位に閉じる)。
 *
 * 戻り値は serializable な素のオブジェクトか null。**throw しない**。
失敗の理由は区別して返さない — ただし `verifyTicket` だけは、一時的な失敗 (資格情報を alc-auth-worker に
確かめられなかった・例外) を `{ error: "unavailable" }` で無効 (null) と区別する (呼び手に再試行させるため)。
 */
import { WorkerEntrypoint } from "cloudflare:workers";
import type { Env } from "./index";
import { checkAppTenant } from "./lib/acl";
import { machineCredAppOrigin } from "./lib/machine-credential";
import {
  issueTicket,
  verifyTicket,
  type MachineTicketUnavailable,
} from "./lib/machine-ticket";

export class MachineCredentialEntrypoint extends WorkerEntrypoint<Env> {
  /** Basic を照合し、通ればチケットを発行する。通らなければ null。 */
  async issueTicket(
    authorization: string,
    purpose: string,
    sha256: string,
  ): Promise<{ ticket: string; tenantId: string; username: string } | null> {
    if (typeof authorization !== "string" || typeof purpose !== "string") return null;
    try {
      const issued = await issueTicket(this.env, authorization, purpose, sha256);
      return issued && appAllows(this.env, purpose, issued.tenantId) ? issued : null;
    } catch (err) {
      logFailure("machine_ticket_issue_failed", err);
      return null;
    }
  }

  /**
   * チケットを検証する。通れば `{tenantId, username, sha256}`、無効なら null、
   * 一時的な失敗 (alc-auth-worker に確かめられなかった・例外) なら `{ error: "unavailable" }`。
   */
  async verifyTicket(
    ticket: string,
    purpose: string,
  ): Promise<
    { tenantId: string; username: string; sha256: string } | MachineTicketUnavailable | null
  > {
    if (typeof ticket !== "string" || typeof purpose !== "string") return null;
    try {
      const verified = await verifyTicket(this.env, ticket, purpose);
      if (verified && "tenantId" in verified && !appAllows(this.env, purpose, verified.tenantId)) {
        return null;
      }
      return verified;
    } catch (err) {
      logFailure("machine_ticket_verify_failed", err);
      return { error: "unavailable" };
    }
  }
}

/** 用途に照合先の app origin があれば、tenant がその app に許されているか (無ければ true)。 */
function appAllows(env: Env, purpose: string, tenantId: string): boolean {
  const origin = machineCredAppOrigin(purpose);
  return origin === null || checkAppTenant(env, origin, tenantId);
}

/** 例外の種類だけを出す (Authorization・チケットの中身は出さない)。 */
function logFailure(event: string, err: unknown): void {
  console.error(JSON.stringify({ event, error: err instanceof Error ? err.name : "unknown" }));
}
