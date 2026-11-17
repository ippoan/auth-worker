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
import { listDeviceRecordsByTenant, renameDeviceLabel } from "../lib/device";
import { isValidLabel } from "./alarm-key";
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

/**
 * `POST /internal/device-labels/rename` — body `{ tenant_id, device_id, label }`
 *
 * 登録簿の device の label を書き換える server-to-server 専用 API (管理画面「端末のファーム」の
 * 改名、Refs ippoan/alc-app-s3#352)。認証は上と同じ shared secret。label の規則は鍵ラベルと
 * 同じ 1〜64 文字。
 *
 * 応答: 200 `{ ok, device_id, label }` / 400 (入力不正) / 404 `not_found` (無い・tenant 違い) /
 * 409 `revoked` / 409 `duplicate_label` (同じ tenant の有効な別の device がその label)。
 */
export async function handleInternalDeviceLabelRename(request: Request, env: Env): Promise<Response> {
  const rejected = await rejectUnlessSharedSecret(request, env);
  if (rejected) return rejected;

  let body: Record<string, unknown> = {};
  try {
    const v = await request.json();
    if (v && typeof v === "object") body = v as Record<string, unknown>;
  } catch {
    // 空 body は下の検査で弾く
  }
  const tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  if (!tenantId) return jsonNoStore({ error: "tenant_id_required" }, 400);
  if (!deviceId) return jsonNoStore({ error: "device_id_required" }, 400);
  const label = body.label;
  if (!isValidLabel(label)) return jsonNoStore({ error: "invalid_label" }, 400);

  const result = await renameDeviceLabel(env, tenantId, deviceId, label);
  if (!result.ok) return jsonNoStore({ error: result.reason }, result.reason === "not_found" ? 404 : 409);
  return jsonNoStore({ ok: true, device_id: deviceId, label });
}
