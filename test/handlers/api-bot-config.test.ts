import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import {
  stubOrReal,
  testEnv,
  authRequest,
  authJsonRequest,
  noAuthRequest,
  noAuthJsonRequest,
  restoreFetch,
  waitIfLive,
  isLive,
} from "../helpers/stub-or-real";
import {
  handleBotConfigList,
  handleBotConfigUpsert,
  handleBotConfigDelete,
  handleBotConfigExport,
} from "../../src/handlers/api-bot-config";
import { makeJwt } from "../helpers/live-env";
import { TEST_JWT_SECRET } from "../helpers/mock-env";
import { DEVELOPER_EMAILS } from "../../src/lib/developer";

afterAll(() => restoreFetch());
waitIfLive();

/**
 * 一覧・保存・削除の口の行き先は alc-lineworks-worker の Service Binding (ALC_LINEWORKS)。
 * binding の fetch を global fetch へ流し、各 test が `stubOrReal` / `vi.stubGlobal("fetch")` で応答を決める
 * (呼ばれた url は https://alc-lineworks/api/admin/bot/configs...)。
 */
function lineworksEnv() {
  const base = testEnv();
  return {
    ...base,
    ALC_LINEWORKS: {
      fetch: (url: string, init?: RequestInit) => globalThis.fetch(url, init),
    } as unknown as Fetcher,
  };
}

// ---------- handleBotConfigList ----------

// 一覧・保存・削除の口は ippoan/alc-lineworks-worker へ移り、rust-alc-api から消えた (W2c、Refs ippoan/rust-alc-api#680)。
// live (rust のコンテナが相手、binding 無し) では Cloud Run の口に落ちて 404 になるので、mock だけで回す。export は rust に残る
describe.skipIf(isLive)("handleBotConfigList", () => {
  const env = lineworksEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleBotConfigList(noAuthRequest("/x", "GET"), env);
    expect(res.status).toBe(401);
  });

  it("returns 401 with non-Bearer auth header", async () => {
    const req = new Request("https://auth.test.example/x", {
      headers: { Authorization: "Basic abc" },
    });
    const res = await handleBotConfigList(req, env);
    expect(res.status).toBe(401);
  });

  it("returns mapped configs on success", async () => {
    // Setup: upsert a bot config
    stubOrReal(
      new Response(
        JSON.stringify({
          id: "id1",
          provider: "lineworks",
          name: "ListBot",
          client_id: "list-cid",
          service_account: "list-sa",
          bot_id: "list-bid",
          enabled: true,
          created_at: "2025-01-01",
          updated_at: "2025-01-02",
        }),
        { status: 200 },
      ),
    );
    const upsertRes = await handleBotConfigUpsert(
      authJsonRequest("/x", {
        name: "ListBot",
        clientId: "list-cid",
        clientSecret: "list-secret",
        serviceAccount: "list-sa",
        botId: "list-bid",
        enabled: true,
      }),
      env,
    );
    const upsertData = (await upsertRes.json()) as { id: string };
    const botId = upsertData.id;

    // Act: list
    stubOrReal(
      new Response(
        JSON.stringify({
          configs: [
            {
              id: "id1",
              provider: "lineworks",
              name: "ListBot",
              client_id: "list-cid",
              service_account: "list-sa",
              bot_id: "list-bid",
              enabled: true,
              created_at: "2025-01-01",
              updated_at: "2025-01-02",
            },
          ],
        }),
        { status: 200 },
      ),
    );
    const res = await handleBotConfigList(
      authRequest("/x", { method: "GET" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      configs: Array<Record<string, unknown>>;
    };
    expect(Array.isArray(data.configs)).toBe(true);
    expect(data.configs.length).toBeGreaterThanOrEqual(1);
    const c = data.configs.find((x) => x.name === "ListBot")!;
    expect(c).toBeDefined();
    expect(typeof c.id).toBe("string");
    expect(c.provider).toBe("lineworks");
    expect(c.name).toBe("ListBot");
    expect(c.clientId).toBe("list-cid");
    expect(c.hasClientSecret).toBe(true);
    expect(c.serviceAccount).toBe("list-sa");
    expect(c).not.toHaveProperty("hasPrivateKey");
    expect(c.botId).toBe("list-bid");
    expect(c.enabled).toBe(true);
    expect(typeof c.createdAt).toBe("string");
    expect(typeof c.updatedAt).toBe("string");

    // Cleanup
    stubOrReal(new Response("ok", { status: 200 }));
    await handleBotConfigDelete(
      authJsonRequest("/x", { id: botId || "id1" }),
      env,
    );
  });

  it("handles empty configs array", async () => {
    stubOrReal(
      new Response(JSON.stringify({ configs: [] }), { status: 200 }),
    );
    const res = await handleBotConfigList(
      authRequest("/x", { method: "GET" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { configs: unknown[] };
    expect(Array.isArray(data.configs)).toBe(true);
  });

  it("ALC_LINEWORKS が無ければ fetch せず 404 (fail-closed)", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const res = await handleBotConfigList(authRequest("/x", { method: "GET" }), testEnv());
    expect(res.status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("binding へ identity ヘッダだけで GET する (Authorization は付けない)", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ configs: [] }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await handleBotConfigList(authRequest("/x", { method: "GET" }), env);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("https://alc-lineworks/api/admin/bot/configs");
    expect((init as RequestInit).method).toBe("GET");
    expect((init as RequestInit).headers as Record<string, string>).toHaveProperty("X-Tenant-ID");
    expect(((init as RequestInit).headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it("passes through error status from backend", async () => {
    stubOrReal(new Response("forbidden", { status: 403 }));
    const req = isLive
      ? new Request("https://auth.test.example/x", {
          method: "GET",
          headers: { Authorization: "Bearer invalid-token-value" },
        })
      : authRequest("/x", { method: "GET" });
    const res = await handleBotConfigList(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
    const data = (await res.json()) as { error: string };
    expect(typeof data.error).toBe("string");
  });

});

// ---------- handleBotConfigUpsert ----------

describe.skipIf(isLive)("handleBotConfigUpsert", () => {
  const env = lineworksEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleBotConfigUpsert(
      noAuthJsonRequest("/x", { name: "n" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 when name is missing", async () => {
    const res = await handleBotConfigUpsert(
      authJsonRequest("/x", {
        clientId: "c",
        botId: "b",
        serviceAccount: "s",
      }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 when clientId is missing", async () => {
    const res = await handleBotConfigUpsert(
      authJsonRequest("/x", {
        name: "n",
        botId: "b",
        serviceAccount: "s",
      }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 when botId is missing", async () => {
    const res = await handleBotConfigUpsert(
      authJsonRequest("/x", {
        name: "n",
        clientId: "c",
        serviceAccount: "s",
      }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 when serviceAccount is missing", async () => {
    const res = await handleBotConfigUpsert(
      authJsonRequest("/x", { name: "n", clientId: "c", botId: "b" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns mapped config on success", async () => {
    stubOrReal(
      new Response(
        JSON.stringify({
          id: "id1",
          provider: "lineworks",
          name: "UpsertBot",
          client_id: "upsert-bot-cid",
          service_account: "upsert-sa",
          bot_id: "upsert-bid",
          enabled: true,
        }),
        { status: 200 },
      ),
    );
    const res = await handleBotConfigUpsert(
      authJsonRequest("/x", {
        name: "UpsertBot",
        clientId: "upsert-bot-cid",
        clientSecret: "upsert-bot-secret",
        serviceAccount: "upsert-sa",
        botId: "upsert-bid",
        enabled: true,
      }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as Record<string, unknown>;
    expect(typeof data.id).toBe("string");
    expect(data.name).toBe("UpsertBot");
    expect(data.clientId).toBe("upsert-bot-cid");
    expect(data.hasClientSecret).toBe(true);
    expect(data.serviceAccount).toBe("upsert-sa");
    expect(data).not.toHaveProperty("hasPrivateKey");
    expect(data.botId).toBe("upsert-bid");
    expect(data.enabled).toBe(true);

    // Cleanup
    stubOrReal(new Response("ok", { status: 200 }));
    await handleBotConfigDelete(
      authJsonRequest("/x", { id: data.id || "id1" }),
      env,
    );
  });

  it("sends defaults for optional fields when not provided", async () => {
    const mockFetchFn = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          id: "id1",
          provider: "lineworks",
          name: "DefaultsBot",
          client_id: "def-cid",
          service_account: "def-sa",
          bot_id: "def-bid",
          enabled: true,
        }),
        { status: 200 },
      ),
    );
    if (!isLive) vi.stubGlobal("fetch", mockFetchFn);

    const res = await handleBotConfigUpsert(
      authJsonRequest("/x", {
        name: "DefaultsBot",
        clientId: "def-cid",
        serviceAccount: "def-sa",
        botId: "def-bid",
      }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as Record<string, unknown>;
    expect(data.provider).toBe("lineworks");
    expect(data.enabled).toBe(true);
    expect(typeof data.id).toBe("string");

    // Verify sent body (mock-only)
    if (!isLive) {
      const sentBody = JSON.parse(
        mockFetchFn.mock.calls[0]![1].body as string,
      );
      expect(sentBody.id).toBeNull();
      expect(sentBody.provider).toBe("lineworks");
      expect(sentBody.client_secret).toBeNull();
      expect(sentBody).not.toHaveProperty("private_key");
      expect(sentBody.enabled).toBe(true);
    }

    // Cleanup
    stubOrReal(new Response("ok", { status: 200 }));
    await handleBotConfigDelete(
      authJsonRequest("/x", { id: data.id || "id1" }),
      env,
    );
  });

  it("does not forward privateKey even if an old client still sends it", async () => {
    // Private Key は alc-lineworks が Secrets Store から読む。管理画面から受け取って rust へ転送しない
    const mockFetchFn = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          id: "id1",
          provider: "lineworks",
          name: "StaleClientBot",
          client_id: "stale-cid",
          service_account: "stale-sa",
          bot_id: "stale-bid",
          enabled: true,
        }),
        { status: 200 },
      ),
    );
    if (!isLive) vi.stubGlobal("fetch", mockFetchFn);

    const res = await handleBotConfigUpsert(
      authJsonRequest("/x", {
        name: "StaleClientBot",
        clientId: "stale-cid",
        clientSecret: "stale-secret",
        serviceAccount: "stale-sa",
        privateKey: "stale-pk",
        botId: "stale-bid",
        enabled: true,
      }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as Record<string, unknown>;
    expect(data).not.toHaveProperty("hasPrivateKey");

    if (!isLive) {
      const sentBody = JSON.parse(
        mockFetchFn.mock.calls[0]![1].body as string,
      );
      expect(sentBody).not.toHaveProperty("private_key");
      expect(sentBody.client_secret).toBe("stale-secret");
      expect(sentBody.service_account).toBe("stale-sa");
    }

    // Cleanup
    stubOrReal(new Response("ok", { status: 200 }));
    await handleBotConfigDelete(
      authJsonRequest("/x", { id: data.id || "id1" }),
      env,
    );
  });

  it("passes through error status from backend", async () => {
    stubOrReal(new Response("conflict", { status: 409 }));
    const req = isLive
      ? new Request("https://auth.test.example/x", {
          method: "POST",
          headers: {
            Authorization: "Bearer invalid-token",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            name: "n",
            clientId: "c",
            serviceAccount: "s",
            botId: "b",
          }),
        })
      : authJsonRequest("/x", {
          name: "n",
          clientId: "c",
          serviceAccount: "s",
          botId: "b",
        });
    const res = await handleBotConfigUpsert(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

});

// ---------- handleBotConfigDelete ----------

describe.skipIf(isLive)("handleBotConfigDelete", () => {
  const env = lineworksEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleBotConfigDelete(
      noAuthJsonRequest("/x", { id: "x" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 when id is missing", async () => {
    const res = await handleBotConfigDelete(
      authJsonRequest("/x", {}),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns success on delete", async () => {
    // Setup: create then delete
    stubOrReal(
      new Response(
        JSON.stringify({
          id: "del-id",
          provider: "lineworks",
          name: "DelBot",
          client_id: "del-cid",
          service_account: "del-sa",
          bot_id: "del-bid",
          enabled: true,
        }),
        { status: 200 },
      ),
    );
    const upsertRes = await handleBotConfigUpsert(
      authJsonRequest("/x", {
        name: "DelBot",
        clientId: "del-cid",
        clientSecret: "del-secret",
        serviceAccount: "del-sa",
        botId: "del-bid",
      }),
      env,
    );
    const upsertData = (await upsertRes.json()) as { id: string };
    const deleteId = upsertData.id || "del-id";

    // Act: delete
    stubOrReal(new Response("ok", { status: 200 }));
    const res = await handleBotConfigDelete(
      authJsonRequest("/x", { id: deleteId }),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true });
  });

  it("passes through error status from backend", async () => {
    stubOrReal(new Response("not found", { status: 404 }));
    const req = isLive
      ? new Request("https://auth.test.example/x", {
          method: "POST",
          headers: {
            Authorization: "Bearer invalid-token",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ id: "nonexistent" }),
        })
      : authJsonRequest("/x", { id: "x" });
    const res = await handleBotConfigDelete(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
    const data = (await res.json()) as { error: string };
    expect(typeof data.error).toBe("string");
  });

});

// ---------- handleBotConfigExport ----------

// export も alc-lineworks-worker へ移った (W9、Refs ippoan/rust-alc-api#680)。開発者の判定はここで済ませ、
// 振り分けの表 (admin proxy) で binding へ回す。live (binding 無し) は Cloud Run に落ちるので mock だけで回す
describe.skipIf(isLive)("handleBotConfigExport", () => {
  const TENANT = "11111111-1111-1111-1111-111111111111";
  const EXPORT_URL = `/api/bot-config/export?tenant_id=${TENANT}`;

  function lineworks(res: Response = new Response(JSON.stringify({ version: 1, tenant_id: TENANT }), { status: 200 })) {
    return { fetch: vi.fn(async (_url: string, _init?: RequestInit) => res) };
  }

  function envWith(binding?: ReturnType<typeof lineworks>) {
    const env = testEnv();
    if (binding) (env as unknown as { ALC_LINEWORKS: unknown }).ALC_LINEWORKS = binding;
    return env;
  }

  function devRequest(path = EXPORT_URL, email = DEVELOPER_EMAILS[0]!): Request {
    return new Request(`https://auth.test.example${path}`, {
      headers: { Authorization: `Bearer ${makeJwt(TEST_JWT_SECRET, { email })}` },
    });
  }

  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleBotConfigExport(noAuthRequest(EXPORT_URL, "GET"), envWith(lineworks()));
    expect(res.status).toBe(401);
  });

  it("returns 400 when tenant_id query param is missing or not a UUID", async () => {
    const binding = lineworks();
    let res = await handleBotConfigExport(devRequest("/api/bot-config/export"), envWith(binding));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("tenant_id is required");
    res = await handleBotConfigExport(devRequest("/api/bot-config/export?tenant_id=x/../y"), envWith(binding));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("tenant_id must be a UUID");
    expect(binding.fetch).not.toHaveBeenCalled();
  });

  it("returns 403 for a non-developer and never calls the backend", async () => {
    const binding = lineworks();
    const cloudRun = vi.fn();
    vi.stubGlobal("fetch", cloudRun);
    const res = await handleBotConfigExport(authRequest(EXPORT_URL, { method: "GET" }), envWith(binding));
    expect(res.status).toBe(403);
    expect(binding.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("developer: forwards to alc-lineworks with X-Tenant-ID = the query tenant, and attaches the JSON", async () => {
    const binding = lineworks();
    const res = await handleBotConfigExport(devRequest(), envWith(binding));
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Disposition") || "").toContain(`bot-configs-${TENANT}-`);
    expect(await res.json()).toEqual({ version: 1, tenant_id: TENANT });

    expect(binding.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = binding.fetch.mock.calls[0]!;
    expect(url).toBe(`https://alc-lineworks/api/admin/bot/configs/export?tenant_id=${TENANT}`);
    expect(init?.method).toBe("GET");
    const headers = init?.headers as Record<string, string>;
    expect(headers["X-Tenant-ID"]).toBe(TENANT);
    expect(headers["X-User-Email"]).toBe(DEVELOPER_EMAILS[0]);
    expect(headers.Authorization).toBeUndefined();
  });

  it("developer: passes through error status from the backend", async () => {
    const binding = lineworks(new Response("tenant_not_found", { status: 404 }));
    const res = await handleBotConfigExport(devRequest(), envWith(binding));
    expect(res.status).toBe(404);
    expect(((await res.json()) as { error: string }).error).toBe("tenant_not_found");
  });
});

// 署名の合わない JWT は、どの口も backend を呼ばずに 401 (buildAdminForwardHeaders が null)
describe.skipIf(isLive)("Bot 設定の口: 検証できない JWT は 401", () => {
  const bad = (path: string, method: string, body?: unknown) =>
    new Request(`https://auth.test.example${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${makeJwt("wrong-secret-wrong-secret-wrong!!")}`,
        "Content-Type": "application/json",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });

  it.each<[string, () => Promise<Response>]>([
    ["list", () => handleBotConfigList(bad("/x", "GET"), testEnv())],
    ["upsert", () => handleBotConfigUpsert(bad("/x", "POST", { name: "n", clientId: "c", serviceAccount: "s", botId: "b" }), testEnv())],
    ["delete", () => handleBotConfigDelete(bad("/x", "DELETE", { id: "id1" }), testEnv())],
    ["export", () => handleBotConfigExport(bad("/x?tenant_id=11111111-1111-1111-1111-111111111111", "GET"), testEnv())],
  ])("%s", async (_label, call) => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const res = await call();
    expect(res.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
