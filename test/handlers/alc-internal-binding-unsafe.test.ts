import { describe, it, expect, vi, afterAll } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async () => "fake-oidc-token"),
}));

// 振り分け表の判定だけを差し替える: 内部用から引いたら、どの path でも binding を返す
// (表の内部用の行が増えたときの形を先に固定するため。`isUnsafeBackendPath` と転送は本物)。
const bindingFetch = vi.fn(async (_url: string, _init?: RequestInit) => new Response("from-binding"));
vi.mock("../../src/lib/alc-backend-route", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/lib/alc-backend-route")>();
  return {
    ...actual,
    resolveAlcBinding: vi.fn(() => ({ fetcher: { fetch: bindingFetch } as unknown as Fetcher, host: "alc-test" })),
  };
});

import { handleAlcInternalProxy } from "../../src/handlers/alc-internal-proxy";

const PROXY_SECRET = "test-internal-shared-secret-32!!";
const TENANT = "11111111-1111-1111-1111-111111111111";
const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

function req(path: string) {
  return new Request(`https://auth.test.example${path}`, {
    method: "PATCH",
    headers: { "X-Alc-Proxy-Secret": PROXY_SECRET, "X-Tenant-ID": TENANT },
    body: "{}",
  });
}

describe("alc-internal-proxy の binding 経路 (表が内部用に binding を返すとき)", () => {
  it("許可リストを通った path でも、%2e%2e%2f を含むなら 403 で binding に届かない", async () => {
    const cloudRun = vi.fn(async () => new Response("from-cloud-run"));
    globalThis.fetch = cloudRun as unknown as typeof fetch;
    const env = createMockEnv({ ALC_API_PROXY_SA_KEY: "{}", INTERNAL_SHARED_SECRET: PROXY_SECRET });

    const unsafe = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/dtako/tickets/%2e%2e%2fadmin/scraped"),
      env,
    );
    expect(unsafe.status).toBe(403);
    expect(bindingFetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();

    // 同じ行の普通の path は binding へ届く (差し替えが効いていることの確認)
    const safe = await handleAlcInternalProxy(req("/alc-internal-proxy/api/dtako/tickets/ticket-1/scraped"), env);
    expect(await safe.text()).toBe("from-binding");
    expect(bindingFetch).toHaveBeenCalledTimes(1);
    expect(bindingFetch.mock.calls[0]![0]).toBe("https://alc-test/api/dtako/tickets/ticket-1/scraped");
    expect(cloudRun).not.toHaveBeenCalled();
  });
});
