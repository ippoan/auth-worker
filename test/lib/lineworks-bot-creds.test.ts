import { describe, it, expect, vi, afterEach } from "vitest";
import {
  getBotAccess,
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

/** ALC_LINEWORKS の binding の偽物。token の口の応答を差し替え、呼ばれた形を記録する。 */
function lineworksBinding(respond: () => Response): {
  fetcher: Fetcher;
  calls: Array<{ url: string; init: RequestInit }>;
} {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetcher = {
    fetch: vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
      return respond();
    }),
  } as unknown as Fetcher;
  return { fetcher, calls };
}

describe("getBotAccess", () => {
  const ok = () => json({ access_token: "at-1", expires_at: 1700000000, bot_id: "bid" });

  it("asks ALC_LINEWORKS for a token with the caller's tenant, bot config and scope", async () => {
    const lw = lineworksBinding(ok);
    const f = routeRust({});
    const bot = await getBotAccess(
      createMockEnv({ ALC_LINEWORKS: lw.fetcher }),
      token,
      "bc-1",
      "board.read",
    );
    expect(bot).toEqual({ accessToken: "at-1", botId: "bid" });
    expect(lw.calls).toHaveLength(1);
    expect(lw.calls[0]!.url).toBe("https://alc-lineworks/api/internal/lineworks/token");
    expect(lw.calls[0]!.init.method).toBe("POST");
    expect(lw.calls[0]!.init.headers).toEqual({
      "X-Tenant-ID": "tenant-1",
      "Content-Type": "application/json",
    });
    expect(JSON.parse(String(lw.calls[0]!.init.body))).toEqual({
      bot_config_id: "bc-1",
      scope: "board.read",
    });
    // rust (/secrets 等) は 1 度も呼ばない
    expect(rustCalls(f)).toEqual([]);
  });

  it("defaults scope to bot (Rich Menu)", async () => {
    const lw = lineworksBinding(ok);
    await getBotAccess(createMockEnv({ ALC_LINEWORKS: lw.fetcher }), token, "bc-1");
    expect(JSON.parse(String(lw.calls[0]!.init.body)).scope).toBe("bot");
  });

  it("refuses an unverifiable token without calling the worker", async () => {
    const lw = lineworksBinding(ok);
    await expect(
      getBotAccess(createMockEnv({ ALC_LINEWORKS: lw.fetcher }), "not-a-jwt", "bc1"),
    ).rejects.toThrow("Unauthorized");
    expect(lw.calls).toEqual([]);
  });

  it("refuses a non-admin caller without calling the worker (rust /secrets と同じ線)", async () => {
    const lw = lineworksBinding(ok);
    const userToken = makeJwt(TEST_JWT_SECRET, { tenant_id: "tenant-1", role: "user" });
    await expect(
      getBotAccess(createMockEnv({ ALC_LINEWORKS: lw.fetcher }), userToken, "bc1"),
    ).rejects.toThrow("Forbidden");
    expect(lw.calls).toEqual([]);
  });

  it("throws when ALC_LINEWORKS is not bound (no fallback to rust)", async () => {
    const f = routeRust({});
    await expect(getBotAccess(env, token, "bc1")).rejects.toThrow("LINE WORKS worker not bound");
    expect(rustCalls(f)).toEqual([]);
  });

  it.each([
    [401, { error: "unauthorized", message: "x" }, "Failed to get LINE WORKS token: 401 unauthorized"],
    [404, { error: "bot_config_not_found", message: "x" }, "Failed to get LINE WORKS token: 404 bot_config_not_found"],
    [400, { error: "scope_not_allowed", message: "x" }, "Failed to get LINE WORKS token: 400 scope_not_allowed"],
    [500, { error: "private_key_missing", message: "x" }, "Failed to get LINE WORKS token: 500 private_key_missing"],
    [502, { error: "upstream_error", message: "token: 400 (code invalid_client)" }, "Failed to get LINE WORKS token: 502 upstream_error"],
  ])("maps a %i from the token endpoint to an error with its code only", async (status, body, msg) => {
    const lw = lineworksBinding(() => json(body, status));
    const p = getBotAccess(createMockEnv({ ALC_LINEWORKS: lw.fetcher }), token, "bc1");
    await expect(p).rejects.toThrow(msg);
    // 上流の message (本文) は載せない
    await expect(p).rejects.not.toThrow("invalid_client");
  });

  it("maps a non-JSON failure body to the status alone", async () => {
    const lw = lineworksBinding(() => new Response("Failed to deserialize", { status: 422 }));
    const p = getBotAccess(createMockEnv({ ALC_LINEWORKS: lw.fetcher }), token, "not-a-uuid");
    await expect(p).rejects.toThrow(/^Failed to get LINE WORKS token: 422$/);
  });

  it("rejects a 200 without access_token / bot_id", async () => {
    const lw = lineworksBinding(() => json({ access_token: "at-1" }));
    await expect(
      getBotAccess(createMockEnv({ ALC_LINEWORKS: lw.fetcher }), token, "bc1"),
    ).rejects.toThrow("Failed to get LINE WORKS token: malformed response");
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
