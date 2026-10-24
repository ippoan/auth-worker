/**
 * `GET /internal/device-labels?tenant_id=<id>`
 *
 * テナントの未失効の device の id と label だけを返す server-to-server 専用 API
 * (ippoan/alc-app#403)。alc-app のサーバが端末一覧の表示と、キオスクが報告した
 * `device_id` の登録済み照合に使う。
 *
 * 認証は `/internal/hub-devices` と同じ shared secret 検査を共用する。
 * `/internal/hub-devices` は label を返さないまま (こちらだけが返す)。
 *
 * レスポンス: `{ devices: [{ device_id, label }, ...] }`。label が無い record は null。
 * `all=1` のときだけ失効済みも含め、各要素に `revoked: boolean` を足す。all=1 は名前の表示用で、
 * 登録済みの照合には使わない。返すのは id と label と revoked だけ。shared secret を持つ worker なら
 * 読める範囲は既定と同じ。
 * kind / role / site_id / dev_device / secret_hash / tenant_id / 時刻は返さない。
 */
import type { Env } from "../index";
import { listDeviceRecordsByTenant } from "../lib/device";
import { jsonNoStore, rejectUnlessSharedSecret } from "./internal-hub-devices";

export async function handleInternalDeviceLabels(request: Request, env: Env): Promise<Response> {
  const rejected = await rejectUnlessSharedSecret(request, env);
  if (rejected) return rejected;

  const params = new URL(request.url).searchParams;
  const tenantId = params.get("tenant_id");
  if (!tenantId) {
    return jsonNoStore({ error: "tenant_id_required" }, 400);
  }

  if (params.get("all") === "1") {
    const records = await listDeviceRecordsByTenant(env, tenantId, { includeRevoked: true });
    return jsonNoStore({
      devices: records.map((r) => ({
        device_id: r.device_id,
        label: r.label ?? null,
        revoked: r.revoked === true,
      })),
    });
  }

  const records = await listDeviceRecordsByTenant(env, tenantId);
  return jsonNoStore({
    devices: records.map((r) => ({ device_id: r.device_id, label: r.label ?? null })),
  });
}
