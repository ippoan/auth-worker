import { describe, it, expect } from "vitest";
import { createMockEnv, createMockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";
import { MACHINE_RELAY_ROUTES, handleMachineRelay } from "../../src/handlers/machine-relay";
import { createMachineCredential, revokeMachineCredential } from "../../src/lib/machine-credential";

/** テスト固有のダミー値 (本番の値ではない)。 */
const TENANT = "88888888-8888-8888-8888-888888888888";
const SHARED = "test-internal-shared-secret-for-relay";
const ORIGIN = "https://auth.test.example";

interface Captured {
  url: string;
  method: string;
  headers: Headers;
  body: string;
}

function fakeBinding(res: () => Response = () => new Response("ok", { status: 201 })) {
  const calls: Captured[] = [];
  const fetcher = {
    fetch: async (input: Request) => {
      calls.push({
        url: input.url,
        method: input.method,
        headers: input.headers,
        body: input.body ? await input.text() : "",
      });
      return res();
    },
  } as unknown as Fetcher;
  return { fetcher, calls };
}

async function setup(overrides: Partial<Env> = {}) {
  const binding = fakeBinding();
  const e = createMockEnv({
    AUTH_CONFIG: createMockKV(),
    MACHINE_CRED_ENV: "prod",
    INTERNAL_SHARED_SECRET: SHARED,
    LEAVE_APP: binding.fetcher,
    ...overrides,
  });
  const c = (await createMachineCredential(e, TENANT, "leave-scan", "複合機"))!;
  const auth = `Basic ${btoa(`${c.username}:${c.password}`)}`;
  return { e, c, auth, calls: binding.calls };
}

function put(path: string, headers: Record<string, string> = {}, body: string | null = "PDFDATA"): Request {
  return new Request(`${ORIGIN}${path}`, { method: "PUT", headers, body });
}

describe("handleMachineRelay (/m/<purpose>/*、Refs ohishi-exp/rust-leave-worker#1)", () => {
  it("用途の表は leave-scan → LEAVE_APP の /dav だけ", () => {
    expect(MACHINE_RELAY_ROUTES).toEqual({ "leave-scan": { binding: "LEAVE_APP", pathPrefix: "/dav" } });
  });

  it("★ Basic が通れば method・path・query・body・Authorization をそのまま中継し、X-Internal-Shared-Secret を付ける", async () => {
    const { e, auth, calls } = await setup();
    const res = await handleMachineRelay(
      put("/m/leave-scan/scan/20261013.pdf?x=1", { Authorization: auth, "Content-Type": "application/pdf", Depth: "0" }),
      e,
    );
    expect(res.status).toBe(201);
    expect(calls).toHaveLength(1);
    const c = calls[0]!;
    expect(new URL(c.url).pathname).toBe("/dav/scan/20261013.pdf");
    expect(new URL(c.url).search).toBe("?x=1");
    expect(c.method).toBe("PUT");
    expect(c.body).toBe("PDFDATA");
    expect(c.headers.get("Authorization")).toBe(auth);
    expect(c.headers.get("Content-Type")).toBe("application/pdf");
    expect(c.headers.get("Depth")).toBe("0");
    expect(c.headers.get("X-Internal-Shared-Secret")).toBe(SHARED);
  });

  it("★ 送り手の詐称ヘッダー (X-Internal-* / X-Tenant-* / X-User-* / X-Alc-*) と Cookie は消す。X-Tenant-ID は付けない", async () => {
    const { e, auth, calls } = await setup();
    await handleMachineRelay(
      put("/m/leave-scan/a.pdf", {
        Authorization: auth,
        "X-Internal-Shared-Secret": "forged",
        "X-Tenant-ID": "forged-tenant",
        "X-User-ID": "u",
        "X-User-Email": "e@example.com",
        "X-Alc-Proxy-Secret": "forged",
        Cookie: "logi_auth_token=forged",
      }),
      e,
    );
    const h = calls[0]!.headers;
    expect(h.get("X-Internal-Shared-Secret")).toBe(SHARED);
    expect(h.get("X-Tenant-ID")).toBeNull();
    expect(h.get("X-User-ID")).toBeNull();
    expect(h.get("X-User-Email")).toBeNull();
    expect(h.get("X-Alc-Proxy-Secret")).toBeNull();
    expect(h.get("Cookie")).toBeNull();
  });

  it("応答 (status・ヘッダー・本文) はそのまま返す", async () => {
    const binding = fakeBinding(
      () => new Response("<multistatus/>", { status: 207, headers: { "Content-Type": "application/xml", DAV: "1" } }),
    );
    const { e, auth } = await setup({ LEAVE_APP: binding.fetcher });
    const res = await handleMachineRelay(new Request(`${ORIGIN}/m/leave-scan/`, { method: "PROPFIND", headers: { Authorization: auth } }), e);
    expect(res.status).toBe(207);
    expect(res.headers.get("DAV")).toBe("1");
    expect(await res.text()).toBe("<multistatus/>");
    expect(binding.calls[0]!.method).toBe("PROPFIND");
    expect(binding.calls[0]!.body).toBe("");
    expect(new URL(binding.calls[0]!.url).pathname).toBe("/dav/");
  });

  it("/m/leave-scan (末尾の / なし) は /dav/ へ", async () => {
    const { e, auth, calls } = await setup();
    await handleMachineRelay(new Request(`${ORIGIN}/m/leave-scan`, { headers: { Authorization: auth } }), e);
    expect(new URL(calls[0]!.url).pathname).toBe("/dav/");
  });

  it("★ 401 は理由を区別しない (無し / 不一致 / 失効 / 用途違い) + WWW-Authenticate: Basic。中継しない", async () => {
    const { e, c, auth, calls } = await setup();
    const kv = e.AUTH_CONFIG as unknown as { _data: Record<string, string> };
    const other = "mc_0123456789abcdef";
    kv._data[`mcred:prod:${other}`] = JSON.stringify({
      username: other, tenant_id: TENANT, purpose: "other", label: "x",
      secret_hash: "0".repeat(64), created_at: new Date().toISOString(), revoked: false,
    });
    const cases: (string | undefined)[] = [
      undefined,
      `Basic ${btoa(`${c.username}:wrong`)}`,
      `Basic ${btoa(`${other}:x`)}`, // 用途違い
      "Bearer something",
    ];
    for (const a of cases) {
      const res = await handleMachineRelay(put("/m/leave-scan/a.pdf", a ? { Authorization: a } : {}, null), e);
      expect(res.status).toBe(401);
      expect(res.headers.get("WWW-Authenticate")).toBe('Basic realm="leave-scan", charset="UTF-8"');
      expect(await res.json()).toEqual({ error: "Unauthorized" });
    }
    await revokeMachineCredential(e, TENANT, c.username);
    const revoked = await handleMachineRelay(put("/m/leave-scan/a.pdf", { Authorization: auth }), e);
    expect(revoked.status).toBe(401);
    expect(calls).toHaveLength(0);
  });

  it("表に無い purpose・形の違う path → 404 (Basic を見る前)", async () => {
    const { e, auth, calls } = await setup();
    for (const p of ["/m/other/a.pdf", "/m/toString/a", "/m/", "/m//a"]) {
      const res = await handleMachineRelay(put(p, { Authorization: auth }), e);
      expect(res.status).toBe(404);
      expect(res.headers.get("WWW-Authenticate")).toBeNull();
    }
    expect(calls).toHaveLength(0);
  });

  it("binding 未定義・INTERNAL_SHARED_SECRET 未設定 → 503 (Basic が通った後)", async () => {
    const a = await setup({ LEAVE_APP: undefined });
    expect((await handleMachineRelay(put("/m/leave-scan/a.pdf", { Authorization: a.auth }), a.e)).status).toBe(503);
    const b = await setup({ INTERNAL_SHARED_SECRET: undefined });
    expect((await handleMachineRelay(put("/m/leave-scan/a.pdf", { Authorization: b.auth }), b.e)).status).toBe(503);
    expect(b.calls).toHaveLength(0);
    // Basic が通らなければ 503 より先に 401
    expect((await handleMachineRelay(put("/m/leave-scan/a.pdf", {}), a.e)).status).toBe(401);
  });

  it("staging の資格情報は MACHINE_CRED_ENV=prod の口では 401", async () => {
    const kv = createMockKV();
    const staging = await setup({ AUTH_CONFIG: kv, MACHINE_CRED_ENV: "staging" });
    const prod = createMockEnv({
      AUTH_CONFIG: kv, MACHINE_CRED_ENV: "prod", INTERNAL_SHARED_SECRET: SHARED, LEAVE_APP: fakeBinding().fetcher,
    });
    expect((await handleMachineRelay(put("/m/leave-scan/a.pdf", { Authorization: staging.auth }), prod)).status).toBe(401);
  });
});
