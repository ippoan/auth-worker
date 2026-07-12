import { describe, it, expect } from "vitest";
import { handleDeviceSetupPage, handleDeviceSetupPair } from "../../src/handlers/device-setup";
import { getDeviceRecord } from "../../src/lib/device";
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
    // operator の email を表示 (どのテナントで登録されるかの確認用)
    expect(html).toContain("op@example.com");
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
