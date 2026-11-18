import { describe, it, expect } from "vitest";
import {
  handleInternalAlarmKeyLabel,
  handleInternalAlarmKeyRename,
  handleInternalDeviceLabelRename,
  handleInternalDeviceLabels,
} from "../../src/handlers/internal-device-labels";
import { handleInternalHubDevices } from "../../src/handlers/internal-hub-devices";
import {
  createDeviceCredential,
  createDeviceCredentialReplacingLabel,
  getDeviceRecord,
  revokeDeviceCredential,
  DEVICE_ROLE_HUB,
  DEVICE_ROLE_KIOSK,
} from "../../src/lib/device";
import { createMockEnv, createMockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ORIGIN = "https://auth.test.example";
const SECRET = "test-internal-shared-secret-32chr";
const NOW = Math.floor(Date.now() / 1000);

function makeEnv(overrides: Partial<Env> = {}): Env {
  return createMockEnv({ INTERNAL_SHARED_SECRET: SECRET, AUTH_CONFIG: createMockKV(), ...overrides });
}

function req(auth?: string | null, query = "?tenant_id=tenant-a", path = "device-labels"): Request {
  const headers: Record<string, string> = {};
  if (auth !== null && auth !== undefined) headers.Authorization = auth;
  return new Request(`${ORIGIN}/internal/${path}${query}`, { method: "GET", headers });
}

describe("GET /internal/device-labels — 認可 (/internal/hub-devices と同じ拒否)", () => {
  it.each([
    ["secret 無し", undefined],
    ["secret 違い", "wrong-secret"],
  ])("%s → 401 で登録簿の中身を返さない", async (_n, auth) => {
    const env = makeEnv();
    await createDeviceCredential(env, "tenant-a", "secret-label-xyz", NOW, DEVICE_ROLE_KIOSK);
    const res = await handleInternalDeviceLabels(req(auth), env);
    const hub = await handleInternalHubDevices(req(auth, "", "hub-devices"), env);
    expect(res.status).toBe(401);
    const text = await res.text();
    expect(text).toBe(await hub.text());
    expect(text).toBe(JSON.stringify({ error: "unauthorized" }));
    expect(text).not.toContain("secret-label-xyz");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("INTERNAL_SHARED_SECRET* が未 bind → 503 (hub-devices と同じ)", async () => {
    const env = makeEnv({ INTERNAL_SHARED_SECRET: undefined });
    const res = await handleInternalDeviceLabels(req(SECRET), env);
    const hub = await handleInternalHubDevices(req(SECRET, "", "hub-devices"), env);
    expect(res.status).toBe(503);
    expect(await res.text()).toBe(await hub.text());
  });
});

describe("GET /internal/device-labels — 応答", () => {
  it("そのテナントの未失効の端末だけ。別テナント・失効は返らない", async () => {
    const env = makeEnv();
    const a1 = await createDeviceCredential(env, "tenant-a", "hub-a", NOW, DEVICE_ROLE_HUB);
    const a2 = await createDeviceCredential(env, "tenant-a", "kiosk-a", NOW + 1, DEVICE_ROLE_KIOSK, undefined, true);
    const gone = await createDeviceCredential(env, "tenant-a", "revoked-a", NOW + 2, DEVICE_ROLE_KIOSK);
    await createDeviceCredential(env, "tenant-b", "other-b", NOW, DEVICE_ROLE_KIOSK);
    await revokeDeviceCredential(env, gone.device_id);

    const res = await handleInternalDeviceLabels(req(SECRET), env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = (await res.json()) as { devices: Array<Record<string, unknown>> };
    expect(body.devices).toEqual([
      { device_id: a2.device_id, label: "kiosk-a" },
      { device_id: a1.device_id, label: "hub-a" },
    ]);
    for (const d of body.devices) expect(Object.keys(d).sort()).toEqual(["device_id", "label"]);
    expect(Object.keys(body)).toEqual(["devices"]);
  });

  it("all 無しは失効済みを返さず revoked キーも付けない (all=0 も同じ)", async () => {
    const env = makeEnv();
    const live = await createDeviceCredential(env, "tenant-a", "live-a", NOW, DEVICE_ROLE_KIOSK);
    const gone = await createDeviceCredential(env, "tenant-a", "gone-a", NOW + 1, DEVICE_ROLE_KIOSK);
    await revokeDeviceCredential(env, gone.device_id);
    for (const q of ["?tenant_id=tenant-a", "?tenant_id=tenant-a&all=0"]) {
      const body = (await (await handleInternalDeviceLabels(req(SECRET, q), env)).json()) as {
        devices: Array<Record<string, unknown>>;
      };
      expect(body.devices).toEqual([{ device_id: live.device_id, label: "live-a" }]);
      expect("revoked" in (body.devices[0] ?? {})).toBe(false);
    }
  });

  it("all=1 は失効済みも revoked: true で返し、有効は revoked: false。他テナントは載らない", async () => {
    const env = makeEnv();
    const live = await createDeviceCredential(env, "tenant-a", "live-a", NOW, DEVICE_ROLE_KIOSK);
    const gone = await createDeviceCredential(env, "tenant-a", "gone-a", NOW + 1, DEVICE_ROLE_KIOSK);
    await createDeviceCredential(env, "tenant-b", "other-b", NOW + 2, DEVICE_ROLE_KIOSK);
    const goneB = await createDeviceCredential(env, "tenant-b", "gone-b", NOW + 3, DEVICE_ROLE_KIOSK);
    await revokeDeviceCredential(env, gone.device_id);
    await revokeDeviceCredential(env, goneB.device_id);

    const res = await handleInternalDeviceLabels(req(SECRET, "?tenant_id=tenant-a&all=1"), env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = (await res.json()) as { devices: Array<Record<string, unknown>> };
    expect(body.devices).toEqual([
      { device_id: gone.device_id, label: "gone-a", revoked: true },
      { device_id: live.device_id, label: "live-a", revoked: false },
    ]);
    for (const d of body.devices) expect(Object.keys(d).sort()).toEqual(["device_id", "label", "revoked"]);
  });

  it("all=1 でも secret 無しは従来どおり 401", async () => {
    const env = makeEnv();
    const res = await handleInternalDeviceLabels(req(undefined, "?tenant_id=tenant-a&all=1"), env);
    expect(res.status).toBe(401);
    expect(await res.text()).toBe(JSON.stringify({ error: "unauthorized" }));
  });

  it("label が無い record は label: null", async () => {
    const env = makeEnv();
    const c = await createDeviceCredential(env, "tenant-a", "x", NOW, DEVICE_ROLE_KIOSK);
    const raw = JSON.parse((await env.AUTH_CONFIG.get(`device:${c.device_id}`)) as string);
    delete raw.label;
    await env.AUTH_CONFIG.put(`device:${c.device_id}`, JSON.stringify(raw));
    const body = (await (await handleInternalDeviceLabels(req(SECRET), env)).json()) as {
      devices: unknown[];
    };
    expect(body.devices).toEqual([{ device_id: c.device_id, label: null }]);
  });

  it("端末が 0 台のテナント → { devices: [] }", async () => {
    const env = makeEnv();
    const res = await handleInternalDeviceLabels(req(SECRET, "?tenant_id=tenant-empty"), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ devices: [] });
  });

  it.each(["", "?tenant_id=", "?other=1"])("tenant_id 無し/空 (%s) → 400", async (q) => {
    const res = await handleInternalDeviceLabels(req(SECRET, q), makeEnv());
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "tenant_id_required" });
  });
});

describe("POST /internal/device-labels/rename (Refs ippoan/alc-app-s3#352)", () => {
  function post(body: unknown, auth: string | null = SECRET): Request {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (auth !== null) headers.Authorization = auth;
    return new Request(`${ORIGIN}/internal/device-labels/rename`, {
      method: "POST",
      headers,
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
  }
  const kvData = (env: Env) => (env.AUTH_CONFIG as unknown as { _data: Record<string, string> })._data;

  it("label を書き換え、索引を張り替える (旧名で引けず新名で引ける)", async () => {
    const env = makeEnv();
    const cred = await createDeviceCredentialReplacingLabel(env, "tenant-a", "cores3", NOW, DEVICE_ROLE_HUB);
    const before = await getDeviceRecord(env, cred.device_id);

    const res = await handleInternalDeviceLabelRename(
      post({ tenant_id: "tenant-a", device_id: cred.device_id, label: "1号車" }),
      env,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(await res.json()).toEqual({ ok: true, device_id: cred.device_id, label: "1号車" });
    expect(await getDeviceRecord(env, cred.device_id)).toEqual({ ...before, label: "1号車" });
    expect(kvData(env)["device-label:tenant-a:cores3"]).toBeUndefined();
    expect(kvData(env)["device-label:tenant-a:1号車"]).toBe(cred.device_id);

    // 新名での再発行は改名した device を失効させる (= 新名で引ける)
    await createDeviceCredentialReplacingLabel(env, "tenant-a", "1号車", NOW + 1, DEVICE_ROLE_HUB);
    expect((await getDeviceRecord(env, cred.device_id))?.revoked).toBe(true);
  });

  it("旧名の索引が別の device を指していれば消さない", async () => {
    const env = makeEnv();
    const a = await createDeviceCredential(env, "tenant-a", "shared", NOW, DEVICE_ROLE_KIOSK);
    const b = await createDeviceCredentialReplacingLabel(env, "tenant-a", "other", NOW, DEVICE_ROLE_KIOSK);
    kvData(env)["device-label:tenant-a:shared"] = b.device_id;
    const res = await handleInternalDeviceLabelRename(
      post({ tenant_id: "tenant-a", device_id: a.device_id, label: "renamed" }),
      env,
    );
    expect(res.status).toBe(200);
    expect(kvData(env)["device-label:tenant-a:shared"]).toBe(b.device_id);
    expect(kvData(env)["device-label:tenant-a:renamed"]).toBe(a.device_id);
  });

  it("同じ label への改名は 200 で何も書かない", async () => {
    const env = makeEnv();
    const cred = await createDeviceCredentialReplacingLabel(env, "tenant-a", "cores3", NOW, DEVICE_ROLE_HUB);
    const snapshot = { ...kvData(env) };
    const res = await handleInternalDeviceLabelRename(
      post({ tenant_id: "tenant-a", device_id: cred.device_id, label: "cores3" }),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, device_id: cred.device_id, label: "cores3" });
    expect(kvData(env)).toEqual(snapshot);
  });

  it("新しい label の索引が同じ tenant の有効な別の device を指す → 409 duplicate_label で何も書かない", async () => {
    const env = makeEnv();
    const a = await createDeviceCredentialReplacingLabel(env, "tenant-a", "a", NOW, DEVICE_ROLE_HUB);
    await createDeviceCredentialReplacingLabel(env, "tenant-a", "taken", NOW, DEVICE_ROLE_HUB);
    const snapshot = { ...kvData(env) };
    const res = await handleInternalDeviceLabelRename(
      post({ tenant_id: "tenant-a", device_id: a.device_id, label: "taken" }),
      env,
    );
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "duplicate_label" });
    expect(kvData(env)).toEqual(snapshot);
  });

  it("索引が失効済み・不在・他 tenant の device を指すなら空きとして上書きする", async () => {
    const env = makeEnv();
    const a = await createDeviceCredentialReplacingLabel(env, "tenant-a", "a", NOW, DEVICE_ROLE_HUB);
    const gone = await createDeviceCredentialReplacingLabel(env, "tenant-a", "old", NOW, DEVICE_ROLE_HUB);
    await revokeDeviceCredential(env, gone.device_id);
    const foreign = await createDeviceCredential(env, "tenant-b", "x", NOW, DEVICE_ROLE_HUB);
    kvData(env)["device-label:tenant-a:ghost"] = "no-such-device";
    kvData(env)["device-label:tenant-a:foreign"] = foreign.device_id;

    for (const label of ["old", "ghost", "foreign"]) {
      const res = await handleInternalDeviceLabelRename(
        post({ tenant_id: "tenant-a", device_id: a.device_id, label }),
        env,
      );
      expect(res.status).toBe(200);
      expect(kvData(env)[`device-label:tenant-a:${label}`]).toBe(a.device_id);
    }
  });

  it("無い device と他 tenant の device は同じ 404", async () => {
    const env = makeEnv();
    const b = await createDeviceCredential(env, "tenant-b", "b", NOW, DEVICE_ROLE_HUB);
    const other = await handleInternalDeviceLabelRename(post({ tenant_id: "tenant-a", device_id: b.device_id, label: "x" }), env);
    const missing = await handleInternalDeviceLabelRename(post({ tenant_id: "tenant-a", device_id: "nope", label: "x" }), env);
    expect(other.status).toBe(404);
    expect(missing.status).toBe(404);
    expect(await other.text()).toBe(await missing.text());
    expect((await getDeviceRecord(env, b.device_id))?.label).toBe("b");
  });

  it("失効済み → 409 revoked", async () => {
    const env = makeEnv();
    const cred = await createDeviceCredential(env, "tenant-a", "a", NOW, DEVICE_ROLE_HUB);
    await revokeDeviceCredential(env, cred.device_id);
    const res = await handleInternalDeviceLabelRename(post({ tenant_id: "tenant-a", device_id: cred.device_id, label: "x" }), env);
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "revoked" });
  });

  it.each([
    ["tenant_id 無し", { device_id: "d", label: "x" }, "tenant_id_required"],
    ["device_id 無し", { tenant_id: "tenant-a", label: "x" }, "device_id_required"],
    ["label 無し", { tenant_id: "tenant-a", device_id: "d" }, "invalid_label"],
    ["label 空", { tenant_id: "tenant-a", device_id: "d", label: "" }, "invalid_label"],
    ["label 65 文字", { tenant_id: "tenant-a", device_id: "d", label: "x".repeat(65) }, "invalid_label"],
    ["壊れた body", "{not json", "tenant_id_required"],
    ["body が null", "null", "tenant_id_required"],
  ])("%s → 400", async (_n, body, error) => {
    const env = makeEnv();
    const res = await handleInternalDeviceLabelRename(post(body), env);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error });
  });

  it.each([
    ["secret 無し", null],
    ["secret 違い", "wrong-secret"],
  ])("%s → 401 で書き換えない", async (_n, auth) => {
    const env = makeEnv();
    const cred = await createDeviceCredential(env, "tenant-a", "a", NOW, DEVICE_ROLE_HUB);
    const res = await handleInternalDeviceLabelRename(
      post({ tenant_id: "tenant-a", device_id: cred.device_id, label: "x" }, auth),
      env,
    );
    expect(res.status).toBe(401);
    expect((await getDeviceRecord(env, cred.device_id))?.label).toBe("a");
  });
});

describe("POST /internal/alarm-keys/rename (Refs ippoan/alc-app-s3#352)", () => {
  function post(body: unknown, auth: string | null = SECRET): Request {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (auth !== null) headers.Authorization = auth;
    return new Request(`${ORIGIN}/internal/alarm-keys/rename`, {
      method: "POST",
      headers,
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
  }
  const kvData = (env: Env) => (env.AUTH_CONFIG as unknown as { _data: Record<string, string> })._data;

  /** 鍵の record と tenant 索引を KV に直接置く (値はダミー)。 */
  function putKey(env: Env, fp: string, tenant: string, label: string, revoked = false): void {
    const data = kvData(env);
    data[`alarmkey:${fp}`] = JSON.stringify({
      pubkey: `pk-${fp}`,
      tenant_id: tenant,
      label,
      usage: "kiosk",
      created_at: NOW,
      ...(revoked ? { revoked_at: NOW } : {}),
    });
    const idxKey = `alarmkeys:${tenant}`;
    const idx = data[idxKey] ? (JSON.parse(data[idxKey]!) as string[]) : [];
    data[idxKey] = JSON.stringify([...idx, fp]);
  }
  const labelOf = (env: Env, fp: string) => JSON.parse(kvData(env)[`alarmkey:${fp}`]!).label as string;

  it("label だけを書き換え、他の欄は変えない", async () => {
    const env = makeEnv();
    putKey(env, "aaaa000000000001", "tenant-a", "seat-1");
    const before = JSON.parse(kvData(env)["alarmkey:aaaa000000000001"]!);
    const res = await handleInternalAlarmKeyRename(
      post({ tenant_id: "tenant-a", fingerprint: "aaaa000000000001", label: "管理者席" }),
      env,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(await res.json()).toEqual({ ok: true, fingerprint: "aaaa000000000001", label: "管理者席" });
    expect(JSON.parse(kvData(env)["alarmkey:aaaa000000000001"]!)).toEqual({ ...before, label: "管理者席" });
  });

  it("自分と同じ label への改名は 200 で何も書かない", async () => {
    const env = makeEnv();
    putKey(env, "aaaa000000000001", "tenant-a", "seat-1");
    const snapshot = { ...kvData(env) };
    const res = await handleInternalAlarmKeyRename(
      post({ tenant_id: "tenant-a", fingerprint: "aaaa000000000001", label: "seat-1" }),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, fingerprint: "aaaa000000000001", label: "seat-1" });
    expect(kvData(env)).toEqual(snapshot);
  });

  it("同じ tenant の有効な別の鍵と同じ label → 409 duplicate_label。失効済み・他 tenant の同名は妨げない", async () => {
    const env = makeEnv();
    putKey(env, "aaaa000000000001", "tenant-a", "seat-1");
    putKey(env, "aaaa000000000002", "tenant-a", "taken");
    putKey(env, "aaaa000000000003", "tenant-a", "free", true);
    putKey(env, "bbbb000000000001", "tenant-b", "elsewhere");

    const dup = await handleInternalAlarmKeyRename(
      post({ tenant_id: "tenant-a", fingerprint: "aaaa000000000001", label: "taken" }),
      env,
    );
    expect(dup.status).toBe(409);
    expect(await dup.json()).toEqual({ error: "duplicate_label" });
    expect(labelOf(env, "aaaa000000000001")).toBe("seat-1");
    for (const label of ["free", "elsewhere"]) {
      const ok = await handleInternalAlarmKeyRename(
        post({ tenant_id: "tenant-a", fingerprint: "aaaa000000000001", label }),
        env,
      );
      expect(ok.status).toBe(200);
      expect(labelOf(env, "aaaa000000000001")).toBe(label);
    }
  });

  it("無い鍵と他 tenant の鍵は同じ 404 で書き換えない", async () => {
    const env = makeEnv();
    putKey(env, "bbbb000000000001", "tenant-b", "b");
    const other = await handleInternalAlarmKeyRename(
      post({ tenant_id: "tenant-a", fingerprint: "bbbb000000000001", label: "x" }),
      env,
    );
    const missing = await handleInternalAlarmKeyRename(
      post({ tenant_id: "tenant-a", fingerprint: "0000000000000000", label: "x" }),
      env,
    );
    expect(other.status).toBe(404);
    expect(missing.status).toBe(404);
    expect(await other.text()).toBe(await missing.text());
    expect(labelOf(env, "bbbb000000000001")).toBe("b");
  });

  it("失効済み → 409 revoked", async () => {
    const env = makeEnv();
    putKey(env, "aaaa000000000001", "tenant-a", "seat-1", true);
    const res = await handleInternalAlarmKeyRename(
      post({ tenant_id: "tenant-a", fingerprint: "aaaa000000000001", label: "x" }),
      env,
    );
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "revoked" });
  });

  it.each([
    ["tenant_id 無し", { fingerprint: "f", label: "x" }, "tenant_id_required"],
    ["fingerprint 無し", { tenant_id: "tenant-a", label: "x" }, "fingerprint_required"],
    ["label 無し", { tenant_id: "tenant-a", fingerprint: "f" }, "invalid_label"],
    ["label 空", { tenant_id: "tenant-a", fingerprint: "f", label: "" }, "invalid_label"],
    ["label 65 文字", { tenant_id: "tenant-a", fingerprint: "f", label: "x".repeat(65) }, "invalid_label"],
    ["壊れた body", "{not json", "tenant_id_required"],
    ["body が null", "null", "tenant_id_required"],
  ])("%s → 400", async (_n, body, error) => {
    const env = makeEnv();
    const res = await handleInternalAlarmKeyRename(post(body), env);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error });
  });

  it.each([
    ["secret 無し", null],
    ["secret 違い", "wrong-secret"],
  ])("%s → 401 で書き換えない", async (_n, auth) => {
    const env = makeEnv();
    putKey(env, "aaaa000000000001", "tenant-a", "seat-1");
    const res = await handleInternalAlarmKeyRename(
      post({ tenant_id: "tenant-a", fingerprint: "aaaa000000000001", label: "x" }, auth),
      env,
    );
    expect(res.status).toBe(401);
    expect(labelOf(env, "aaaa000000000001")).toBe("seat-1");
  });
});

describe("GET /internal/alarm-keys/label (Refs ippoan/alc-app-s3#352)", () => {
  const kvData = (env: Env) => (env.AUTH_CONFIG as unknown as { _data: Record<string, string> })._data;

  /** 鍵の record を KV に直接置く (値はダミー)。 */
  function putKey(env: Env, fp: string, tenant: string, extra: Record<string, unknown> = {}): void {
    kvData(env)[`alarmkey:${fp}`] = JSON.stringify({
      pubkey: `pk-${fp}`,
      tenant_id: tenant,
      label: "seat-1",
      usage: "kiosk",
      created_at: NOW,
      dev_device: true,
      ...extra,
    });
  }
  const get = (auth: string | null | undefined, query: string) => req(auth, query, "alarm-keys/label");

  it.each([
    ["secret 無し", undefined],
    ["secret 違い", "wrong-secret"],
  ])("%s → 401 で名前を返さない", async (_n, auth) => {
    const env = makeEnv();
    putKey(env, "aaaa000000000001", "tenant-a");
    const res = await handleInternalAlarmKeyLabel(get(auth, "?tenant_id=tenant-a&fingerprint=aaaa000000000001"), env);
    expect(res.status).toBe(401);
    expect(await res.text()).toBe(JSON.stringify({ error: "unauthorized" }));
  });

  it.each([
    ["?fingerprint=aaaa000000000001", "tenant_id_required"],
    ["?tenant_id=&fingerprint=aaaa000000000001", "tenant_id_required"],
    ["?tenant_id=tenant-a", "fingerprint_required"],
    ["?tenant_id=tenant-a&fingerprint=", "fingerprint_required"],
  ])("%s → 400 %s", async (q, error) => {
    const res = await handleInternalAlarmKeyLabel(get(SECRET, q), makeEnv());
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error });
  });

  it("無い鍵と他 tenant の鍵は同じ 404 (存在を漏らさない)", async () => {
    const env = makeEnv();
    putKey(env, "aaaa000000000001", "tenant-b");
    const other = await handleInternalAlarmKeyLabel(get(SECRET, "?tenant_id=tenant-a&fingerprint=aaaa000000000001"), env);
    const missing = await handleInternalAlarmKeyLabel(get(SECRET, "?tenant_id=tenant-a&fingerprint=ffff000000000009"), env);
    expect(other.status).toBe(404);
    expect(missing.status).toBe(404);
    expect(await other.text()).toBe(await missing.text());
    expect(other.headers.get("Cache-Control")).toBe("no-store");
  });

  it("label を返し、公開鍵・usage・dev_device・時刻・tenant_id は返さない", async () => {
    const env = makeEnv();
    putKey(env, "aaaa000000000001", "tenant-a");
    const res = await handleInternalAlarmKeyLabel(get(SECRET, "?tenant_id=tenant-a&fingerprint=aaaa000000000001"), env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(await res.json()).toEqual({ fingerprint: "aaaa000000000001", label: "seat-1", revoked: false });
  });

  it("label の無い record は label: null", async () => {
    const env = makeEnv();
    putKey(env, "aaaa000000000001", "tenant-a", { label: undefined });
    const res = await handleInternalAlarmKeyLabel(get(SECRET, "?tenant_id=tenant-a&fingerprint=aaaa000000000001"), env);
    expect(await res.json()).toEqual({ fingerprint: "aaaa000000000001", label: null, revoked: false });
  });

  it("失効済みの鍵は revoked: true", async () => {
    const env = makeEnv();
    putKey(env, "aaaa000000000001", "tenant-a", { revoked_at: NOW });
    const res = await handleInternalAlarmKeyLabel(get(SECRET, "?tenant_id=tenant-a&fingerprint=aaaa000000000001"), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ fingerprint: "aaaa000000000001", label: "seat-1", revoked: true });
  });
});
