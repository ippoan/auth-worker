/**
 * Workers RPC entrypoint — kiosk 端末の再ペアリングの credential の発行 (W6b-b、Refs ippoan/rust-alc-api#680)。
 * **service binding 越しにだけ**呼ばれる (`[[services]] entrypoint = "DevicePairEntrypoint"`)。
 *
 * 呼び手: ippoan/alc-devices-worker の `POST /api/devices/re-pair` (rust-alc-api の `device_pair_client` が
 * `POST /device/pair-internal` を共有の秘密付きで叩いていたものの置き換え。binding で呼ぶので共有の秘密を持たせない)。
 *
 * 発行は `/device/pair-internal` と同じ処理 ([`mintPairedCredential`]) を、rust と同じ引数 (role `device-kiosk`・
 * 同じ label の旧 credential を失効) で通す。tenant は呼び手の申告を受けず、端末の ID から引く (fail-closed)。
 *
 * ★ **`InternalEntrypoint` とは別 class** — 呼べるメソッドは binding の `entrypoint` ごとに決まるので、
 * 分けておけば他の binding の呼び手は credential を発行できない。
 *
 * 戻り値は serializable な素のオブジェクトか null。**throw しない**。失敗の理由は返さず、ログに固定の語で出す。
 */
import { WorkerEntrypoint } from "cloudflare:workers";
import type { Env } from "./index";
import { mintPairedCredential } from "./handlers/device";

/** kiosk 端末の再ペアリングで発行する role (rust-alc-api の `RE_PAIR_ROLE`) */
export const RE_PAIR_ROLE = "device-kiosk";

export class DevicePairEntrypoint extends WorkerEntrypoint<Env> {
  /** 端末の ID と label で credential を発行する。発行できなければ null。 */
  async pairInternal(
    deviceId: string,
    label: string,
  ): Promise<{ device_id: string; device_secret: string } | null> {
    if (typeof deviceId !== "string" || !deviceId || typeof label !== "string" || !label) return null;
    try {
      const minted = await mintPairedCredential(this.env, {
        deviceId,
        requestedTenantId: "",
        label,
        role: RE_PAIR_ROLE,
        siteId: undefined,
        replaceLabel: true,
      });
      if (!minted.ok) {
        console.error(JSON.stringify({ event: "device_pair_rpc_denied", reason: minted.reason }));
        return null;
      }
      return { device_id: minted.cred.device_id, device_secret: minted.cred.device_secret };
    } catch (err) {
      console.error(
        JSON.stringify({ event: "device_pair_rpc_failed", error: err instanceof Error ? err.name : "unknown" }),
      );
      return null;
    }
  }
}
