import { describe, it, expect } from "vitest";
import {
  handleDeviceSetupPage,
  handleDeviceSetupPair,
  handleDeviceSetupList,
  handleDeviceSetupOta,
  handleDeviceSetupOtaStatus,
  handleDeviceSetupConnected,
  handleDeviceSetupVersion,
} from "../../src/handlers/device-setup";
import { createDeviceCredential, getDeviceRecord } from "../../src/lib/device";
import { createMockKV } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import type { Env } from "../../src/index";

const SECRET = "device-setup-test-secret";
const ENV = "staging";
const ISSUER = "https://auth.ippoan.org";

function makeEnv(overrides: Record<string, unknown> = {}): Env {
  return {
    AUTH_CONFIG: createMockKV(),
    JWT_SECRET: SECRET,
    WORKER_ENV: ENV,
    ...overrides,
  } as unknown as Env;
}

async function opCookie(claims: Record<string, unknown> = {}): Promise<Record<string, string>> {
  const token = await signTestJwt(
    { tenant_id: "tenant-1", email: "op@example.com", env: ENV, ...claims },
    SECRET,
  );
  return { Cookie: `logi_auth_token=${token}` };
}

function getReq(path: string, headers: Record<string, string> = {}): Request {
  return new Request(`${ISSUER}${path}`, { method: "GET", headers });
}

function postJson(path: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`${ISSUER}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

/** POST /device/setup/pair の応答 (成功時)。 */
interface PairResponse {
  device_id: string;
  device_secret: string;
  tenant_id: string;
  label: string;
  role: string;
}

describe("handleDeviceSetupPage", () => {
  it("redirects to /login when not authenticated", async () => {
    const res = await handleDeviceSetupPage(getReq("/device/setup"), makeEnv());
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("/login?redirect_uri=");
  });

  it("shows an error page (no redirect) when a cookie exists but fails verification", async () => {
    // 期限切れ/不正 cookie で /login へ 302 すると、ログイン済みブラウザで
    // login → callback → 本ページ → login … の無限リダイレクトになるため
    const res = await handleDeviceSetupPage(
      getReq("/device/setup", { Cookie: "logi_auth_token=broken" }),
      makeEnv(),
    );
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("セッションを確認できません");
  });

  it("shows the error page for a session without tenant_id (org unselected)", async () => {
    const token = await signTestJwt({ email: "op@example.com", env: ENV }, SECRET);
    const res = await handleDeviceSetupPage(
      getReq("/device/setup", { Cookie: `logi_auth_token=${token}` }),
      makeEnv(),
    );
    expect(res.status).toBe(403);
  });

  it("serves the WebSerial setup page for an operator session", async () => {
    const res = await handleDeviceSetupPage(getReq("/device/setup", await opCookie()), makeEnv());
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("navigator.serial");
    expect(html).toContain("AUTH SET");
    // 測定記録の送り先は origin から自動判定 (operator への入力欄は無い)
    expect(html).not.toContain('id="wsurl"');
    expect(html).toContain("alc-recorder-staging");
    // 実行前に現在の登録状態を表示し、登録済みなら上書き確認する
    expect(html).toContain("AUTH STATUS");
    expect(html).toContain("上書き登録しますか");
    // ポート open 時のリセット対策: PING/PONG で起動完了を待ってから進む
    expect(html).toContain("PONG");
    expect(html).toContain("setSignals");
    // operator の email を表示 (どのテナントで登録されるかの確認用)
    expect(html).toContain("op@example.com");
    // 登録済みデバイス一覧 (ページ表示時に /device/setup/list を読む)
    expect(html).toContain("登録済みデバイス");
    expect(html).toContain("/device/setup/list");
    // OTA UI: URL 欄 + 更新トリガ + 進捗ポーリング
    expect(html).toContain("/device/setup/ota");
    expect(html).toContain("alc-hub-cores3-app.bin");
    expect(html).toContain("startOta");
    // 接続状態 + バージョン照会 + 最新版
    expect(html).toContain("/device/setup/connected");
    expect(html).toContain("/device/setup/version");
    expect(html).toContain("/device/setup/latest");
    expect(html).toContain("queryVersion");
  });
});

describe("handleDeviceSetupList", () => {
  it("rejects without session (401)", async () => {
    const res = await handleDeviceSetupList(getReq("/device/setup/list"), makeEnv());
    expect(res.status).toBe(401);
  });

  it("returns only the operator tenant's active credentials, newest first", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    // tenant-1 に 2 台 (同 label replace で 1 台は revoke) + 別 label 1 台
    const revoked = (await (
      await handleDeviceSetupPair(
        postJson("/device/setup/pair", { label: "cores3-a", replace_label: true }, headers),
        env,
      )
    ).json()) as PairResponse;
    const current = (await (
      await handleDeviceSetupPair(
        postJson("/device/setup/pair", { label: "cores3-a", replace_label: true }, headers),
        env,
      )
    ).json()) as PairResponse;
    const other = (await (
      await handleDeviceSetupPair(
        postJson("/device/setup/pair", { label: "cores3-b" }, headers),
        env,
      )
    ).json()) as PairResponse;
    // 他テナントの credential は一覧に出ない
    const otherTenantCookie = await opCookie({ tenant_id: "tenant-2" });
    await handleDeviceSetupPair(
      postJson("/device/setup/pair", { label: "cores3-x" }, { ...otherTenantCookie, Origin: ISSUER }),
      env,
    );

    const res = await handleDeviceSetupList(getReq("/device/setup/list", await opCookie()), env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      devices: Array<{ device_id: string; label: string; role: string; created_at: number }>;
    };
    const ids = body.devices.map((d) => d.device_id);
    expect(ids).toContain(current.device_id);
    expect(ids).toContain(other.device_id);
    expect(ids).not.toContain(revoked.device_id); // revoke 済みは出ない
    expect(ids.length).toBe(2);
    for (const d of body.devices) {
      expect(d.role).toBe("device-hub");
      expect(d.created_at).toBeGreaterThan(0);
      // secret は KV に hash しか無く、応答にも含まれない
      expect(d).not.toHaveProperty("device_secret");
      expect(d).not.toHaveProperty("secret_hash");
    }
    // 発行日時降順
    const times = body.devices.map((d) => d.created_at);
    expect([...times].sort((a, b) => b - a)).toEqual(times);
  });

  it("returns an empty list for a tenant with no devices", async () => {
    const res = await handleDeviceSetupList(
      getReq("/device/setup/list", await opCookie({ tenant_id: "tenant-empty" })),
      makeEnv(),
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ devices: [] });
  });

  it("device-hub 以外の role (dtako-ingest 等) は一覧に出さない (CoreS3 専用ページ)", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    // CoreS3 ハブ 1 台 (device-hub)
    const hub = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "cores3" }, headers), env)
    ).json()) as PairResponse;
    // 同 tenant の別種デバイス (直接 KV に device-dtako-ingest で発行)
    const now = Math.floor(Date.now() / 1000);
    const other = await createDeviceCredential(env, "tenant-1", "scraper", now, "device-dtako-ingest");

    const res = await handleDeviceSetupList(getReq("/device/setup/list", await opCookie()), env);
    const body = (await res.json()) as { devices: Array<{ device_id: string; role: string }> };
    const ids = body.devices.map((d) => d.device_id);
    expect(ids).toContain(hub.device_id);
    expect(ids).not.toContain(other.device_id); // 別種は除外
    expect(body.devices.every((d) => d.role === "device-hub")).toBe(true);
  });
});

describe("handleDeviceSetupPair", () => {
  it("rejects without session (401) and with wrong origin (403)", async () => {
    const env = makeEnv();
    const res = await handleDeviceSetupPair(postJson("/device/setup/pair", {}), env);
    expect(res.status).toBe(401);

    const cookie = await opCookie();
    const bad = await handleDeviceSetupPair(
      postJson("/device/setup/pair", {}, { ...cookie, Origin: "https://evil.example" }),
      env,
    );
    expect(bad.status).toBe(403);
  });

  it("mints a device-hub credential bound to the operator tenant", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const res = await handleDeviceSetupPair(
      postJson("/device/setup/pair", { label: "cores3-abc" }, headers),
      env,
    );
    expect(res.status).toBe(201);
    const body = (await res.json()) as PairResponse;
    expect(body.device_id).toBeTruthy();
    expect(body.device_secret).toBeTruthy();
    expect(body.tenant_id).toBe("tenant-1");
    expect(body.role).toBe("device-hub");
    expect(body.label).toBe("cores3-abc");
    const record = await getDeviceRecord(env, body.device_id);
    expect(record?.tenant_id).toBe("tenant-1");
    expect(record?.role).toBe("device-hub");
  });

  it("defaults the label and tolerates an empty body", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const req = new Request(`${ISSUER}/device/setup/pair`, {
      method: "POST",
      headers,
    });
    const res = await handleDeviceSetupPair(req, env);
    expect(res.status).toBe(201);
    const body = (await res.json()) as PairResponse;
    expect(body.label).toBe("cores3");
  });

  it("replace_label revokes the previous credential for the same label", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const first = (await (
      await handleDeviceSetupPair(
        postJson("/device/setup/pair", { label: "cores3-abc", replace_label: true }, headers),
        env,
      )
    ).json()) as PairResponse;
    const second = (await (
      await handleDeviceSetupPair(
        postJson("/device/setup/pair", { label: "cores3-abc", replace_label: true }, headers),
        env,
      )
    ).json()) as PairResponse;
    expect(second.device_id).not.toBe(first.device_id);
    // 旧 credential は revoke され、新しい方だけが有効
    const oldRecord = await getDeviceRecord(env, first.device_id);
    expect(oldRecord?.revoked).toBe(true);
    const newRecord = await getDeviceRecord(env, second.device_id);
    expect(newRecord?.revoked).toBe(false);
    expect(newRecord?.role).toBe("device-hub");
  });
});

describe("handleDeviceSetupOta / handleDeviceSetupOtaStatus", () => {
  /** ALC_RECORDER の service binding を模した Fetcher。呼び出しを記録する。 */
  function mockRecorder(handler: (req: Request) => Response) {
    const calls: Array<{ url: string; method: string; auth: string | null; body: string }> = [];
    const fetcher = {
      async fetch(input: RequestInfo, init?: RequestInit): Promise<Response> {
        const req = new Request(input as string, init);
        calls.push({
          url: req.url,
          method: req.method,
          auth: req.headers.get("Authorization"),
          body: init?.body ? String(init.body) : "",
        });
        return handler(req);
      },
    };
    return { fetcher, calls };
  }

  /** OTA 用 env: recorder binding + shared secret + operator の device を仕込む。 */
  async function otaEnv(recorder: unknown) {
    const env = makeEnv({
      ALC_RECORDER: recorder,
      INTERNAL_SHARED_SECRET: "shared-abc",
    });
    // tenant-1 の有効な device を 1 台発行しておく
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const cred = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "cores3" }, headers), env)
    ).json()) as PairResponse;
    return { env, deviceId: cred.device_id };
  }

  it("OTA トリガ: recorder に action:ota を shared secret 付きで転送し id を返す", async () => {
    const { fetcher, calls } = mockRecorder(
      () => new Response(JSON.stringify({ id: "cmd-1", delivered: 1 }), { status: 202 }),
    );
    const { env, deviceId } = await otaEnv(fetcher);

    const res = await handleDeviceSetupOta(
      postJson(
        "/device/setup/ota",
        { device_id: deviceId, url: "https://x/app.bin" },
        { ...(await opCookie()), Origin: ISSUER },
      ),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: "cmd-1" });
    expect(calls.length).toBe(1);
    const call = calls[0]!;
    expect(call.method).toBe("POST");
    expect(call.auth).toBe("shared-abc");
    expect(call.url).toContain(`/tenants/tenant-1/devices/${deviceId}/command`);
    expect(JSON.parse(call.body)).toEqual({ payload: { action: "ota", url: "https://x/app.bin" } });
  });

  it("他テナントの device_id は 403 (recorder を叩かない)", async () => {
    const { fetcher, calls } = mockRecorder(() => new Response("{}", { status: 202 }));
    const { env } = await otaEnv(fetcher);
    // 別テナントで発行した device
    const otherHeaders = { ...(await opCookie({ tenant_id: "tenant-2" })), Origin: ISSUER };
    const other = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "x" }, otherHeaders), env)
    ).json()) as PairResponse;

    const res = await handleDeviceSetupOta(
      postJson(
        "/device/setup/ota",
        { device_id: other.device_id, url: "https://x/app.bin" },
        { ...(await opCookie()), Origin: ISSUER },
      ),
      env,
    );
    expect(res.status).toBe(403);
    expect(calls.length).toBe(0);
  });

  it("不正入力・認証: session なし 401 / bad origin 403 / url 不正 400 / device 未接続 409", async () => {
    const { fetcher } = mockRecorder(() => new Response("{}", { status: 404 }));
    const { env, deviceId } = await otaEnv(fetcher);

    expect(
      (await handleDeviceSetupOta(postJson("/device/setup/ota", {}), env)).status,
    ).toBe(401);
    expect(
      (
        await handleDeviceSetupOta(
          postJson("/device/setup/ota", {}, { ...(await opCookie()), Origin: "https://evil" }),
          env,
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await handleDeviceSetupOta(
          postJson(
            "/device/setup/ota",
            { device_id: deviceId, url: "ftp://x" },
            { ...(await opCookie()), Origin: ISSUER },
          ),
          env,
        )
      ).status,
    ).toBe(400);
    // recorder が 404 (device not connected) → 409
    const notConn = await handleDeviceSetupOta(
      postJson(
        "/device/setup/ota",
        { device_id: deviceId, url: "https://x/app.bin" },
        { ...(await opCookie()), Origin: ISSUER },
      ),
      env,
    );
    expect(notConn.status).toBe(409);
  });

  it("recorder binding 未設定は 503", async () => {
    const env = makeEnv({ INTERNAL_SHARED_SECRET: "s" });
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const cred = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", {}, headers), env)
    ).json()) as PairResponse;
    const res = await handleDeviceSetupOta(
      postJson(
        "/device/setup/ota",
        { device_id: cred.device_id, url: "https://x/app.bin" },
        headers,
      ),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("進捗ポーリング: recorder の command_result payload を透過する", async () => {
    const { fetcher } = mockRecorder(
      () =>
        new Response(
          JSON.stringify({ payload: { phase: "download", received: 65536, total: 1831920 } }),
          { status: 200 },
        ),
    );
    const env = makeEnv({ ALC_RECORDER: fetcher, INTERNAL_SHARED_SECRET: "shared-abc" });
    const res = await handleDeviceSetupOtaStatus(
      getReq("/device/setup/ota/cmd-1", await opCookie()),
      env,
      "cmd-1",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ phase: "download", received: 65536, total: 1831920 });
  });

  it("進捗ポーリング: recorder 404 (まだ結果なし) は phase:pending", async () => {
    const { fetcher } = mockRecorder(() => new Response("{}", { status: 404 }));
    const env = makeEnv({ ALC_RECORDER: fetcher, INTERNAL_SHARED_SECRET: "shared-abc" });
    const res = await handleDeviceSetupOtaStatus(
      getReq("/device/setup/ota/cmd-x", await opCookie()),
      env,
      "cmd-x",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ phase: "pending" });
  });

  it("接続一覧: recorder /tenants/:t/devices を透過する", async () => {
    const { fetcher, calls } = mockRecorder(
      () => new Response(JSON.stringify({ devices: ["dev-a", "dev-b"] }), { status: 200 }),
    );
    const env = makeEnv({ ALC_RECORDER: fetcher, INTERNAL_SHARED_SECRET: "shared-abc" });
    const res = await handleDeviceSetupConnected(
      getReq("/device/setup/connected", await opCookie()),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ devices: ["dev-a", "dev-b"] });
    expect(calls[0]!.url).toContain("/tenants/tenant-1/devices");
    expect(calls[0]!.auth).toBe("shared-abc");
  });

  it("接続一覧: recorder 未設定は空配列 (fail-open)", async () => {
    const res = await handleDeviceSetupConnected(
      getReq("/device/setup/connected", await opCookie()),
      makeEnv(),
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ devices: [] });
  });

  it("バージョン照会: recorder に action:version を送り id を返す", async () => {
    const { fetcher, calls } = mockRecorder(
      () => new Response(JSON.stringify({ id: "ver-1" }), { status: 202 }),
    );
    const { env, deviceId } = await otaEnv(fetcher);
    const res = await handleDeviceSetupVersion(
      postJson(
        "/device/setup/version",
        { device_id: deviceId },
        { ...(await opCookie()), Origin: ISSUER },
      ),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: "ver-1" });
    expect(JSON.parse(calls[0]!.body)).toEqual({ payload: { action: "version" } });
  });

  it("バージョン照会: 他テナントの device は 403", async () => {
    const { fetcher } = mockRecorder(() => new Response("{}", { status: 202 }));
    const { env } = await otaEnv(fetcher);
    const otherHeaders = { ...(await opCookie({ tenant_id: "tenant-2" })), Origin: ISSUER };
    const other = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "y" }, otherHeaders), env)
    ).json()) as PairResponse;
    const res = await handleDeviceSetupVersion(
      postJson(
        "/device/setup/version",
        { device_id: other.device_id },
        { ...(await opCookie()), Origin: ISSUER },
      ),
      env,
    );
    expect(res.status).toBe(403);
  });
});
