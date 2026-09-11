import { describe, it, expect, vi, afterEach } from "vitest";
import {
  getCredsFromConfig,
  pickLineworksBotConfigId,
} from "../../src/lib/lineworks-bot-creds";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { makeJwt } from "../helpers/live-env";

const env = createMockEnv({});
const token = makeJwt(TEST_JWT_SECRET, { tenant_id: "tenant-1" });

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** rust 宛の fetch だけを URL で振り分ける (OIDC mint 等の他の fetch に順番を食われないように)。 */
function routeRust(routes: Record<string, () => Response>): ReturnType<typeof vi.fn> {
  const f = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    for (const [suffix, respond] of Object.entries(routes)) {
      if (url.endsWith(suffix)) return respond();
    }
    return new Response("unexpected", { status: 599 });
  });
  vi.stubGlobal("fetch", f);
  return f;
}

/** rust (ALC_API_ORIGIN) 宛の呼び出しだけを `{ url, init }` で返す。 */
function rustCalls(f: ReturnType<typeof vi.fn>): Array<{ url: string; init: RequestInit }> {
  return f.mock.calls
    .map((c) => ({ url: String(c[0]), init: c[1] as RequestInit }))
    .filter(({ url }) => url.startsWith(env.ALC_API_ORIGIN));
}

afterEach(() => vi.unstubAllGlobals());

describe("getCredsFromConfig", () => {
  it("refuses an unverifiable token without calling rust", async () => {
    const f = routeRust({});
    await expect(getCredsFromConfig(env, "not-a-jwt", "bc1")).rejects.toThrow("Unauthorized");
    expect(rustCalls(f)).toEqual([]);
  });

  it("forwards tenant identity headers (#434) and maps the secrets without bot_secret", async () => {
    const f = routeRust({
      "/secrets": () =>
        json({
          client_id: "cid",
          client_secret: "cs",
          service_account: "sa",
          private_key: "pk",
          bot_id: "bid",
          bot_secret: "bs",
        }),
    });
    const creds = await getCredsFromConfig(env, token, "bc/1");
    expect(creds).toEqual({
      clientId: "cid",
      clientSecret: "cs",
      serviceAccount: "sa",
      privateKey: "pk",
      botId: "bid",
    });
    const calls = rustCalls(f);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`${env.ALC_API_ORIGIN}/api/admin/bot/configs/bc%2F1/secrets`);
    expect(calls[0]!.init.headers).toMatchObject({ "X-Tenant-ID": "tenant-1", "X-User-Role": "admin" });
  });

  it("throws with the rust status and message when the secrets request fails", async () => {
    routeRust({ "/secrets": () => new Response("forbidden", { status: 403 }) });
    await expect(getCredsFromConfig(env, token, "bc1")).rejects.toThrow(
      "Failed to get bot config: 403 forbidden",
    );
  });
});

describe("pickLineworksBotConfigId", () => {
  it("returns the first enabled lineworks config in rust's order", async () => {
    const f = routeRust({
      "/api/admin/bot/configs": () =>
        json({
          configs: [
            { id: "c-line", provider: "line", enabled: true, name: "a" },
            { id: "c-off", provider: "lineworks", enabled: false, name: "b" },
            { id: "c-on", provider: "lineworks", enabled: true, name: "z" },
            { id: "c-on2", provider: "lineworks", enabled: true, name: "c" },
          ],
        }),
    });
    await expect(pickLineworksBotConfigId(env, token)).resolves.toBe("c-on");
    const calls = rustCalls(f);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.init.headers).toMatchObject({ "X-Tenant-ID": "tenant-1" });
  });

  it("returns null when the tenant has no enabled lineworks config", async () => {
    routeRust({
      "/api/admin/bot/configs": () =>
        json({ configs: [{ id: "c-off", provider: "lineworks", enabled: false, name: "b" }] }),
    });
    await expect(pickLineworksBotConfigId(env, token)).resolves.toBeNull();
  });

  it("throws when the list request fails", async () => {
    routeRust({ "/api/admin/bot/configs": () => new Response("nope", { status: 500 }) });
    await expect(pickLineworksBotConfigId(env, token)).rejects.toThrow(
      "Failed to list bot configs: 500",
    );
  });

  it("refuses an unverifiable token", async () => {
    routeRust({});
    await expect(pickLineworksBotConfigId(env, "not-a-jwt")).rejects.toThrow("Unauthorized");
  });
});
