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
} from "../../src/handlers/api-bot-config";

afterAll(() => restoreFetch());
waitIfLive();

// ---------- handleBotConfigList ----------

describe("handleBotConfigList", () => {
  const env = testEnv();
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
        privateKey: "list-pk",
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
    expect(c.hasPrivateKey).toBe(true);
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

describe("handleBotConfigUpsert", () => {
  const env = testEnv();
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
        privateKey: "upsert-pk",
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
    expect(data.hasPrivateKey).toBe(true);
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
      expect(sentBody.private_key).toBeNull();
      expect(sentBody.enabled).toBe(true);
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

describe("handleBotConfigDelete", () => {
  const env = testEnv();
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
