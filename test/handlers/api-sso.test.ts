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
  handleSsoList,
  handleSsoUpsert,
  handleSsoDelete,
} from "../../src/handlers/api-sso";

afterAll(() => restoreFetch());
waitIfLive();

// ---------- handleSsoList ----------

describe("handleSsoList", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleSsoList(noAuthRequest("/x", "GET"), env);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "Unauthorized" });
  });

  it("returns 401 with non-Bearer auth header", async () => {
    const req = new Request("https://auth.test.example/x", {
      headers: { Authorization: "Basic abc" },
    });
    const res = await handleSsoList(req, env);
    expect(res.status).toBe(401);
  });

  it("returns mapped configs on success", async () => {
    // Setup: upsert a config
    stubOrReal(
      new Response(
        JSON.stringify({
          provider: "lineworks",
          client_id: "cid",
          external_org_id: "oid",
          enabled: true,
          woff_id: "wid",
          created_at: "2025-01-01",
          updated_at: "2025-01-02",
        }),
        { status: 200 },
      ),
    );
    await handleSsoUpsert(
      authJsonRequest("/x", {
        provider: "lineworks",
        clientId: "cid",
        clientSecret: "secret",
        externalOrgId: "oid",
        woffId: "wid",
        enabled: true,
      }),
      env,
    );

    // Act: list
    stubOrReal(
      new Response(
        JSON.stringify({
          configs: [
            {
              provider: "lineworks",
              client_id: "cid",
              external_org_id: "oid",
              enabled: true,
              woff_id: "wid",
              created_at: "2025-01-01",
              updated_at: "2025-01-02",
            },
          ],
        }),
        { status: 200 },
      ),
    );
    const res = await handleSsoList(
      authRequest("/x", { method: "GET" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      configs: Array<Record<string, unknown>>;
    };
    expect(Array.isArray(data.configs)).toBe(true);
    expect(data.configs.length).toBeGreaterThanOrEqual(1);
    const c = data.configs.find((x) => x.provider === "lineworks")!;
    expect(c).toBeDefined();
    expect(c.provider).toBe("lineworks");
    expect(c.clientId).toBe("cid");
    expect(c.hasClientSecret).toBe(true);
    expect(c.externalOrgId).toBe("oid");
    expect(c.enabled).toBe(true);
    expect(c.woffId).toBe("wid");
    expect(typeof c.createdAt).toBe("string");
    expect(typeof c.updatedAt).toBe("string");

    // Cleanup
    stubOrReal(new Response("ok", { status: 200 }));
    await handleSsoDelete(
      authJsonRequest("/x", { provider: "lineworks" }),
      env,
    );
  });

  it("handles empty configs array", async () => {
    stubOrReal(
      new Response(JSON.stringify({ configs: [] }), { status: 200 }),
    );
    const res = await handleSsoList(
      authRequest("/x", { method: "GET" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { configs: unknown[] };
    expect(Array.isArray(data.configs)).toBe(true);
  });


  it("handles null woff_id as empty string", async () => {
    // Setup: upsert without woffId
    stubOrReal(
      new Response(
        JSON.stringify({
          provider: "lineworks",
          client_id: "null-woff-cid",
          external_org_id: "null-woff-org",
          enabled: true,
          woff_id: null,
          created_at: "2025-01-01",
          updated_at: "2025-01-02",
        }),
        { status: 200 },
      ),
    );
    await handleSsoUpsert(
      authJsonRequest("/x", {
        provider: "lineworks",
        clientId: "null-woff-cid",
        clientSecret: "s",
        externalOrgId: "null-woff-org",
      }),
      env,
    );

    // Act: list
    stubOrReal(
      new Response(
        JSON.stringify({
          configs: [
            {
              provider: "lineworks",
              client_id: "null-woff-cid",
              external_org_id: "null-woff-org",
              enabled: true,
              woff_id: null,
              created_at: "2025-01-01",
              updated_at: "2025-01-02",
            },
          ],
        }),
        { status: 200 },
      ),
    );
    const res = await handleSsoList(
      authRequest("/x", { method: "GET" }),
      env,
    );
    const data = (await res.json()) as {
      configs: Array<{ provider: string; woffId: string }>;
    };
    const c = data.configs.find((x) => x.provider === "lineworks");
    expect(c).toBeDefined();
    expect(c!.woffId).toBe("");

    // Cleanup
    stubOrReal(new Response("ok", { status: 200 }));
    await handleSsoDelete(
      authJsonRequest("/x", { provider: "lineworks" }),
      env,
    );
  });

  it("passes through error status from backend", async () => {
    stubOrReal(new Response("forbidden", { status: 403 }));
    const req = isLive
      ? new Request("https://auth.test.example/x", {
          method: "GET",
          headers: { Authorization: "Bearer invalid-token-value" },
        })
      : authRequest("/x", { method: "GET" });
    const res = await handleSsoList(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
    const data = (await res.json()) as { error: string };
    expect(typeof data.error).toBe("string");
  });

});

// ---------- handleSsoUpsert ----------

describe("handleSsoUpsert", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleSsoUpsert(
      noAuthJsonRequest("/x", { provider: "p" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 when provider is missing", async () => {
    const res = await handleSsoUpsert(
      authJsonRequest("/x", { clientId: "c", externalOrgId: "o" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 when clientId is missing", async () => {
    const res = await handleSsoUpsert(
      authJsonRequest("/x", { provider: "p", externalOrgId: "o" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 when externalOrgId is missing", async () => {
    const res = await handleSsoUpsert(
      authJsonRequest("/x", { provider: "p", clientId: "c" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns mapped config on success", async () => {
    stubOrReal(
      new Response(
        JSON.stringify({
          provider: "lineworks",
          client_id: "upsert-cid",
          external_org_id: "upsert-org",
          enabled: true,
          woff_id: "upsert-woff",
        }),
        { status: 200 },
      ),
    );
    const res = await handleSsoUpsert(
      authJsonRequest("/x", {
        provider: "lineworks",
        clientId: "upsert-cid",
        clientSecret: "upsert-secret",
        externalOrgId: "upsert-org",
        woffId: "upsert-woff",
        enabled: true,
      }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as Record<string, unknown>;
    expect(data.provider).toBe("lineworks");
    expect(data.clientId).toBe("upsert-cid");
    expect(data.hasClientSecret).toBe(true);
    expect(data.externalOrgId).toBe("upsert-org");
    expect(data.woffId).toBe("upsert-woff");
    expect(data.enabled).toBe(true);

    // Cleanup
    stubOrReal(new Response("ok", { status: 200 }));
    await handleSsoDelete(
      authJsonRequest("/x", { provider: "lineworks" }),
      env,
    );
  });

  it("sends null for optional fields when not provided", async () => {
    // clientSecret is required by backend, so we must provide it for live mode
    const mockFetchFn = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            provider: "lineworks",
            client_id: "defaults-cid",
            external_org_id: "defaults-org",
            enabled: true,
            woff_id: null,
          }),
          { status: 200 },
        ),
      );
    if (!isLive) vi.stubGlobal("fetch", mockFetchFn);

    const res = await handleSsoUpsert(
      authJsonRequest("/x", {
        provider: "lineworks",
        clientId: "defaults-cid",
        clientSecret: "defaults-secret",
        externalOrgId: "defaults-org",
      }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as Record<string, unknown>;
    expect(data.provider).toBe("lineworks");
    expect(data.clientId).toBe("defaults-cid");
    expect(data.enabled).toBe(true);
    expect(data.woffId).toBe("");

    // Verify sent body (mock-only)
    if (!isLive) {
      const sentBody = JSON.parse(
        mockFetchFn.mock.calls[0]![1].body as string,
      );
      expect(sentBody.woff_id).toBeNull();
      expect(sentBody.enabled).toBe(true);
    }

    // Cleanup
    stubOrReal(new Response("ok", { status: 200 }));
    await handleSsoDelete(
      authJsonRequest("/x", { provider: "lineworks" }),
      env,
    );
  });

  it("handles null woff_id in response as empty string", async () => {
    stubOrReal(
      new Response(
        JSON.stringify({
          provider: "lineworks",
          client_id: "nullwoff-cid",
          external_org_id: "nullwoff-org",
          enabled: false,
          woff_id: null,
        }),
        { status: 200 },
      ),
    );
    const res = await handleSsoUpsert(
      authJsonRequest("/x", {
        provider: "lineworks",
        clientId: "nullwoff-cid",
        clientSecret: "nullwoff-secret",
        externalOrgId: "nullwoff-org",
        enabled: false,
      }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { woffId: string; enabled: boolean };
    expect(data.woffId).toBe("");
    expect(data.enabled).toBe(false);

    // Cleanup
    stubOrReal(new Response("ok", { status: 200 }));
    await handleSsoDelete(
      authJsonRequest("/x", { provider: "lineworks" }),
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
            provider: "p",
            clientId: "c",
            externalOrgId: "o",
          }),
        })
      : authJsonRequest("/x", {
          provider: "p",
          clientId: "c",
          externalOrgId: "o",
        });
    const res = await handleSsoUpsert(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

});

// ---------- handleSsoDelete ----------

describe("handleSsoDelete", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleSsoDelete(
      noAuthJsonRequest("/x", { provider: "p" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 when provider is missing", async () => {
    const res = await handleSsoDelete(
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
          provider: "lineworks",
          client_id: "del-cid",
          external_org_id: "del-org",
          enabled: true,
          woff_id: null,
        }),
        { status: 200 },
      ),
    );
    await handleSsoUpsert(
      authJsonRequest("/x", {
        provider: "lineworks",
        clientId: "del-cid",
        clientSecret: "del-secret",
        externalOrgId: "del-org",
      }),
      env,
    );

    // Act: delete
    stubOrReal(new Response("ok", { status: 200 }));
    const res = await handleSsoDelete(
      authJsonRequest("/x", { provider: "lineworks" }),
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
          body: JSON.stringify({ provider: "nonexistent" }),
        })
      : authJsonRequest("/x", { provider: "p" });
    const res = await handleSsoDelete(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
    const data = (await res.json()) as { error: string };
    expect(typeof data.error).toBe("string");
  });

});
