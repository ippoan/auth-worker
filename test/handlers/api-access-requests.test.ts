import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import {
  stubOrReal,
  testEnv,
  authJsonRequest,
  noAuthJsonRequest,
  noAuthRequest,
  restoreFetch,
  waitIfLive,
  isLive,
} from "../helpers/stub-or-real";
import {
  handleAccessRequestCreate,
  handleAccessRequestList,
  handleAccessRequestApprove,
  handleAccessRequestDecline,
} from "../../src/handlers/api-access-requests";

afterAll(() => restoreFetch());
waitIfLive();

// ---------- handleAccessRequestCreate ----------

describe("handleAccessRequestCreate", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleAccessRequestCreate(
      noAuthJsonRequest("/x", { orgSlug: "test" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 401 with non-Bearer auth header", async () => {
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      headers: { Authorization: "Basic abc", "Content-Type": "application/json" },
      body: JSON.stringify({ orgSlug: "test" }),
    });
    const res = await handleAccessRequestCreate(req, env);
    expect(res.status).toBe(401);
  });

  it("returns 400 when orgSlug is missing", async () => {
    const res = await handleAccessRequestCreate(
      authJsonRequest("/x", {}),
      env,
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("orgSlug is required");
  });

  it("returns success on create", async () => {
    stubOrReal(
      new Response(
        JSON.stringify({ id: "req-1", status: "pending" }),
        { status: 200 },
      ),
    );
    const res = await handleAccessRequestCreate(
      authJsonRequest("/x", { orgSlug: "test-org" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { id: string };
    expect(typeof data.id).toBe("string");
  });

  it("passes through error from backend", async () => {
    stubOrReal(new Response("conflict", { status: 409 }));
    const req = isLive
      ? new Request("https://auth.test.example/x", {
          method: "POST",
          headers: {
            Authorization: "Bearer invalid-token",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ orgSlug: "test" }),
        })
      : authJsonRequest("/x", { orgSlug: "test" });
    const res = await handleAccessRequestCreate(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
    const data = (await res.json()) as { error: string };
    expect(typeof data.error).toBe("string");
  });
});

// ---------- handleAccessRequestList ----------

describe("handleAccessRequestList", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleAccessRequestList(
      noAuthJsonRequest("/x", {}),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns list on success (no filter)", async () => {
    stubOrReal(
      new Response(JSON.stringify([{ id: "req-1", status: "pending" }]), {
        status: 200,
      }),
    );
    const res = await handleAccessRequestList(
      authJsonRequest("/x", {}),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as unknown[];
    expect(Array.isArray(data)).toBe(true);
  });

  it("returns list on success (with statusFilter)", async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify([]), { status: 200 }),
    );
    if (!isLive) vi.stubGlobal("fetch", mockFetch);

    const res = await handleAccessRequestList(
      authJsonRequest("/x", { statusFilter: "approved" }),
      env,
    );
    expect(res.status).toBe(200);

    // Verify query parameter was set (mock-only)
    if (!isLive) {
      const calledUrl = mockFetch.mock.calls[0]![0] as string;
      expect(calledUrl).toContain("status=approved");
    }
  });

  it("passes through error from backend", async () => {
    stubOrReal(new Response("forbidden", { status: 403 }));
    const req = isLive
      ? new Request("https://auth.test.example/x", {
          method: "POST",
          headers: {
            Authorization: "Bearer invalid-token",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({}),
        })
      : authJsonRequest("/x", {});
    const res = await handleAccessRequestList(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});

// ---------- handleAccessRequestApprove ----------

describe("handleAccessRequestApprove", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleAccessRequestApprove(
      noAuthJsonRequest("/x", { requestId: "r1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 when requestId is missing", async () => {
    const res = await handleAccessRequestApprove(
      authJsonRequest("/x", {}),
      env,
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("requestId is required");
  });

  it("returns success on approve", async () => {
    stubOrReal(new Response("ok", { status: 200 }));
    const res = await handleAccessRequestApprove(
      authJsonRequest("/x", { requestId: "req-1" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { success: boolean };
    expect(data.success).toBe(true);
  });

  it("sends role when provided", async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response("ok", { status: 200 }),
    );
    if (!isLive) vi.stubGlobal("fetch", mockFetch);

    const res = await handleAccessRequestApprove(
      authJsonRequest("/x", { requestId: "req-1", role: "admin" }),
      env,
    );
    expect(res.status).toBe(200);

    // Verify role was sent (mock-only)
    if (!isLive) {
      const sentBody = JSON.parse(mockFetch.mock.calls[0]![1].body as string);
      expect(sentBody.role).toBe("admin");
    }
  });

  it("passes through error from backend", async () => {
    stubOrReal(new Response("not found", { status: 404 }));
    const req = isLive
      ? new Request("https://auth.test.example/x", {
          method: "POST",
          headers: {
            Authorization: "Bearer invalid-token",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ requestId: "r1" }),
        })
      : authJsonRequest("/x", { requestId: "r1" });
    const res = await handleAccessRequestApprove(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
    const data = (await res.json()) as { error: string };
    expect(typeof data.error).toBe("string");
  });
});

// ---------- handleAccessRequestDecline ----------

describe("handleAccessRequestDecline", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleAccessRequestDecline(
      noAuthJsonRequest("/x", { requestId: "r1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 when requestId is missing", async () => {
    const res = await handleAccessRequestDecline(
      authJsonRequest("/x", {}),
      env,
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("requestId is required");
  });

  it("returns success on decline", async () => {
    stubOrReal(new Response("ok", { status: 200 }));
    const res = await handleAccessRequestDecline(
      authJsonRequest("/x", { requestId: "req-1" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { success: boolean };
    expect(data.success).toBe(true);
  });

  it("passes through error from backend", async () => {
    stubOrReal(new Response("forbidden", { status: 403 }));
    const req = isLive
      ? new Request("https://auth.test.example/x", {
          method: "POST",
          headers: {
            Authorization: "Bearer invalid-token",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ requestId: "r1" }),
        })
      : authJsonRequest("/x", { requestId: "r1" });
    const res = await handleAccessRequestDecline(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
    const data = (await res.json()) as { error: string };
    expect(typeof data.error).toBe("string");
  });
});
