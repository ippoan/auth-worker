import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv, createMockKV, TEST_JWT_SECRET } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import { DEVICE_ROLE, DEVICE_ROLE_DTAKO_INGEST } from "../../src/lib/device";

// internal JWT の mint 実体は lib/alc-internal 側でテスト済み。ここでは handler の
// flow (device JWT 検証 → role→宛先 → body 検証 → forward) を固定する。
vi.mock("../../src/lib/alc-internal", () => ({
  internalAuthToken: vi.fn(async () => "fake-internal-jwt"),
}));

import { handleDeviceNotify } from "../../src/handlers/device-notify";

const TENANT = "11111111-1111-1111-1111-111111111111";
/** 本番に入る値と同じ形の UUID (テスト固有のダミー — src には焼かない)。 */
const RECIPIENT = "22222222-2222-2222-2222-222222222222";

const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

/** `device-notify-targets` を持つ AUTH_CONFIG KV 付きの env。 */
function env(overrides: Record<string, unknown> = {}) {
  return createMockEnv({
    AUTH_CONFIG: createMockKV({
      "origins:prod": "https://app1.test.example",
      "device-notify-targets": JSON.stringify({ [DEVICE_ROLE]: RECIPIENT }),
    }),
    ...overrides,
  });
}

/** `device-notify-targets` が **無い** env (本番 KV 未投入の状態)。 */
function envWithoutTargets(overrides: Record<string, unknown> = {}) {
  return createMockEnv({
    AUTH_CONFIG: createMockKV({ "origins:prod": "https://app1.test.example" }),
    ...overrides,
  });
}

async function deviceToken(claims: Record<string, unknown> = {}): Promise<string> {
  return signTestJwt(
    { sub: "device-carins-1", tenant_id: TENANT, role: DEVICE_ROLE, ...claims },
    TEST_JWT_SECRET,
  );
}

function req(
  init: RequestInit & { token?: string | null; path?: string } = {},
): Request {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init.headers as Record<string, string>),
  };
  if (init.token !== null && init.token !== undefined) {
    headers["Authorization"] = `Bearer ${init.token}`;
  }
  return new Request(`https://auth.ippoan.org${init.path ?? "/device-notify"}`, {
    method: init.method ?? "POST",
    headers,
    body: init.body,
  });
}

function okFetch() {
  const fetchMock = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
      new Response(JSON.stringify({ ok: true }), { status: 200 }),
  );
  globalThis.fetch = fetchMock as unknown as typeof fetch;
  return fetchMock;
}

describe("handleDeviceNotify (ippoan/nuxt-pwa-carins#54、無人 box の LINE WORKS 通知)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("正常: 宛先は KV の role→map 由来で、internal token を付けて rust へ POST する", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceNotify(
      req({ token: await deviceToken(), body: JSON.stringify({ text: "found=3 uploaded=3 failed=0" }) }),
      env(),
    );
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/internal/lineworks/send");
    expect((init as RequestInit).method).toBe("POST");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-internal-jwt");
    expect(h["Content-Type"]).toBe("application/json");
    // ★ 宛先は呼び手の申告ではなく KV 由来 (device は選べない)。
    expect(JSON.parse(String((init as RequestInit).body))).toEqual({
      recipient_id: RECIPIENT,
      text: "found=3 uploaded=3 failed=0",
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // ★ 一番大事: 宛先を device に選ばせない。黙って無視せず 400 で弾く
  //   (無視すると設定ミスが「意図しない相手に届いた」の形でしか顕在化しない)。
  // ─────────────────────────────────────────────────────────────────────────
  it("★ body に recipient_id が入っていたら 400 (盗難時に任意の相手へ DM させない)", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceNotify(
      req({
        token: await deviceToken(),
        body: JSON.stringify({ text: "hi", recipient_id: "33333333-3333-3333-3333-333333333333" }),
      }),
      env(),
    );
    expect(res.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("body に channel_id が入っていたら 400", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceNotify(
      req({ token: await deviceToken(), body: JSON.stringify({ text: "hi", channel_id: "c-1" }) }),
      env(),
    );
    expect(res.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("text 欠落 / 空文字は 400", async () => {
    for (const body of [JSON.stringify({}), JSON.stringify({ text: "" })]) {
      const res = await handleDeviceNotify(req({ token: await deviceToken(), body }), env());
      expect(res.status, body).toBe(400);
    }
  });

  it("text が 1000 文字は通り、1001 文字は 400", async () => {
    const fetchMock = okFetch();
    const ok = await handleDeviceNotify(
      req({ token: await deviceToken(), body: JSON.stringify({ text: "あ".repeat(1000) }) }),
      env(),
    );
    expect(ok.status).toBe(200);
    const tooLong = await handleDeviceNotify(
      req({ token: await deviceToken(), body: JSON.stringify({ text: "あ".repeat(1001) }) }),
      env(),
    );
    expect(tooLong.status).toBe(400);
    expect(fetchMock).toHaveBeenCalledTimes(1); // 通ったのは 1000 文字の 1 回だけ
  });

  it("JSON でない body は 400", async () => {
    const res = await handleDeviceNotify(
      req({ token: await deviceToken(), body: "not-json" }),
      env(),
    );
    expect(res.status).toBe(400);
  });

  it("Authorization ヘッダー欠落は 401", async () => {
    const res = await handleDeviceNotify(
      req({ token: null, body: JSON.stringify({ text: "hi" }) }),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("不正な device JWT は 401", async () => {
    const res = await handleDeviceNotify(
      req({ token: "garbage", body: JSON.stringify({ text: "hi" }) }),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("tenant_id / role クレーム欠落は 401", async () => {
    for (const claims of [{ tenant_id: undefined }, { role: undefined }]) {
      const res = await handleDeviceNotify(
        req({ token: await deviceToken(claims), body: JSON.stringify({ text: "hi" }) }),
        env(),
      );
      expect(res.status, JSON.stringify(claims)).toBe(401);
    }
  });

  it("map に無い role は 403 (通知先が決まっていない device に送らせない)", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceNotify(
      req({
        token: await deviceToken({ role: DEVICE_ROLE_DTAKO_INGEST }),
        body: JSON.stringify({ text: "hi" }),
      }),
      env(),
    );
    expect(res.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // ★ 本番 KV への値の投入は運用側の仕事。未投入のまま「送れたつもり」に
  //   ならないこと (fail-closed) をここで固定する。
  it("★ KV に device-notify-targets が無ければ 403 (fail-closed)", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceNotify(
      req({ token: await deviceToken(), body: JSON.stringify({ text: "hi" }) }),
      envWithoutTargets(),
    );
    expect(res.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("KV の値が壊れた JSON / 配列でも 403 (パース不能を素通ししない)", async () => {
    for (const raw of ["{not json", "[]"]) {
      const res = await handleDeviceNotify(
        req({ token: await deviceToken(), body: JSON.stringify({ text: "hi" }) }),
        createMockEnv({
          AUTH_CONFIG: createMockKV({ "device-notify-targets": raw }),
        }),
      );
      expect(res.status, raw).toBe(403);
    }
  });

  it("JWT_SECRET 未 bind は 503", async () => {
    const res = await handleDeviceNotify(
      req({ token: await deviceToken(), body: JSON.stringify({ text: "hi" }) }),
      env({ JWT_SECRET: undefined }),
    );
    expect(res.status).toBe(503);
  });

  it("ALC_API_ORIGIN 未設定は 503", async () => {
    const res = await handleDeviceNotify(
      req({ token: await deviceToken(), body: JSON.stringify({ text: "hi" }) }),
      env({ ALC_API_ORIGIN: undefined }),
    );
    expect(res.status).toBe(503);
  });

  it("上流が非 2xx なら 502 (本文はそのまま返さない)", async () => {
    const fetchMock = vi.fn(
      async (): Promise<Response> => new Response("channel not found", { status: 404 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const res = await handleDeviceNotify(
      req({ token: await deviceToken(), body: JSON.stringify({ text: "hi" }) }),
      env(),
    );
    expect(res.status).toBe(502);
    expect(await res.text()).not.toContain("channel not found");
  });

  it("internal token の mint に失敗したら 502", async () => {
    const { internalAuthToken } = await import("../../src/lib/alc-internal");
    (internalAuthToken as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("boom"),
    );
    const res = await handleDeviceNotify(
      req({ token: await deviceToken(), body: JSON.stringify({ text: "hi" }) }),
      env(),
    );
    expect(res.status).toBe(502);
  });

  it("POST 以外 (GET / PUT) は 405", async () => {
    for (const method of ["GET", "PUT"]) {
      const res = await handleDeviceNotify(
        req({ method, token: await deviceToken(), ...(method === "PUT" ? { body: "{}" } : {}) }),
        env(),
      );
      expect(res.status, method).toBe(405);
      expect(res.headers.get("Allow")).toBe("POST");
    }
  });
});
