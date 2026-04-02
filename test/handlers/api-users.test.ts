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
  handleUsersList,
  handleInvitationsList,
  handleInviteUser,
  handleDeleteInvitation,
  handleDeleteUser,
} from "../../src/handlers/api-users";

afterAll(() => restoreFetch());
waitIfLive();

// ---------- handleUsersList ----------

describe("handleUsersList", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleUsersList(noAuthRequest("/x", "GET"), env);
    expect(res.status).toBe(401);
  });

  it("returns 401 with non-Bearer auth header", async () => {
    const req = new Request("https://auth.test.example/x", {
      headers: { Authorization: "Basic abc" },
    });
    const res = await handleUsersList(req, env);
    expect(res.status).toBe(401);
  });

  it("returns users list on success", async () => {
    stubOrReal(
      new Response(
        JSON.stringify({
          users: [
            {
              id: "u1",
              email: "a@b.com",
              name: "Test",
              role: "admin",
              created_at: "2025-01-01",
            },
          ],
        }),
        { status: 200 },
      ),
    );
    const res = await handleUsersList(
      authRequest("/x", { method: "GET" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      users: Array<Record<string, unknown>>;
    };
    expect(Array.isArray(data.users)).toBe(true);
    expect(data.users.length).toBeGreaterThanOrEqual(1);
    const u = data.users[0]!;
    expect(typeof u.id).toBe("string");
    expect(typeof u.email).toBe("string");
    expect(typeof u.name).toBe("string");
    expect(typeof u.role).toBe("string");
    expect(typeof u.created_at).toBe("string");
  });

  it("passes through error status from backend", async () => {
    stubOrReal(new Response("forbidden", { status: 403 }));
    const req = isLive
      ? new Request("https://auth.test.example/x", {
          method: "GET",
          headers: { Authorization: "Bearer invalid-token-value" },
        })
      : authRequest("/x", { method: "GET" });
    const res = await handleUsersList(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
    const data = (await res.json()) as { error: string };
    expect(typeof data.error).toBe("string");
  });

});

// ---------- handleInvitationsList ----------

describe("handleInvitationsList", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleInvitationsList(noAuthRequest("/x", "GET"), env);
    expect(res.status).toBe(401);
  });

  it("returns invitations list on success", async () => {
    stubOrReal(
      new Response(
        JSON.stringify({
          invitations: [
            {
              id: "i1",
              email: "a@b.com",
              tenant_id: "t1",
              role: "admin",
              created_at: "2025-01-01",
            },
          ],
        }),
        { status: 200 },
      ),
    );
    const res = await handleInvitationsList(
      authRequest("/x", { method: "GET" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      invitations: Array<Record<string, unknown>>;
    };
    expect(Array.isArray(data.invitations)).toBe(true);
    expect(data.invitations.length).toBeGreaterThanOrEqual(1);
  });

  it("passes through error status from backend", async () => {
    stubOrReal(new Response("forbidden", { status: 403 }));
    const req = isLive
      ? new Request("https://auth.test.example/x", {
          method: "GET",
          headers: { Authorization: "Bearer invalid-token-value" },
        })
      : authRequest("/x", { method: "GET" });
    const res = await handleInvitationsList(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

});

// ---------- handleInviteUser ----------

describe("handleInviteUser", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleInviteUser(
      noAuthJsonRequest("/x", { email: "a@b.com" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 when email is missing", async () => {
    const res = await handleInviteUser(
      authJsonRequest("/x", {}),
      env,
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("email is required");
  });

  it("returns invitation on success", async () => {
    const email = isLive
      ? `live-invite-${Date.now()}@example.com`
      : "invite@example.com";

    stubOrReal(
      new Response(
        JSON.stringify({
          id: "i1",
          email: "invite@example.com",
          tenant_id: "t1",
          role: "admin",
          created_at: "2025-01-01",
        }),
        { status: 200 },
      ),
    );
    const res = await handleInviteUser(
      authJsonRequest("/x", { email, role: "admin" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      id: string;
      email: string;
      role: string;
    };
    expect(typeof data.id).toBe("string");
    expect(data.email).toBe(isLive ? email : "invite@example.com");
    expect(data.role).toBe("admin");

    // Cleanup
    stubOrReal(new Response("ok", { status: 200 }));
    await handleDeleteInvitation(
      authJsonRequest("/x", { id: data.id || "i1" }),
      env,
    );
  });

  it("sends default role 'admin' when role is not provided", async () => {
    const email = isLive
      ? `live-default-role-${Date.now()}@example.com`
      : "default-role@example.com";

    const mockFetchFn = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          id: "i1",
          email: "default-role@example.com",
          role: "admin",
        }),
        { status: 200 },
      ),
    );
    if (!isLive) vi.stubGlobal("fetch", mockFetchFn);

    const res = await handleInviteUser(
      authJsonRequest("/x", { email }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { id: string; role: string };
    expect(data.role).toBe("admin");

    // Verify sent body (mock-only)
    if (!isLive) {
      const sentBody = JSON.parse(
        mockFetchFn.mock.calls[0][1].body as string,
      );
      expect(sentBody.role).toBe("admin");
    }

    // Cleanup
    stubOrReal(new Response("ok", { status: 200 }));
    await handleDeleteInvitation(
      authJsonRequest("/x", { id: data.id || "i1" }),
      env,
    );
  });

  it("sends provided role when specified", async () => {
    const email = isLive
      ? `live-viewer-role-${Date.now()}@example.com`
      : "viewer-role@example.com";

    const mockFetchFn = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          id: "i2",
          email: "viewer-role@example.com",
          role: "viewer",
        }),
        { status: 200 },
      ),
    );
    if (!isLive) vi.stubGlobal("fetch", mockFetchFn);

    const res = await handleInviteUser(
      authJsonRequest("/x", { email, role: "viewer" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { id: string; role: string };
    expect(data.role).toBe("viewer");

    // Verify sent body (mock-only)
    if (!isLive) {
      const sentBody = JSON.parse(
        mockFetchFn.mock.calls[0][1].body as string,
      );
      expect(sentBody.role).toBe("viewer");
    }

    // Cleanup
    stubOrReal(new Response("ok", { status: 200 }));
    await handleDeleteInvitation(
      authJsonRequest("/x", { id: data.id || "i2" }),
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
          body: JSON.stringify({ email: "error@example.com" }),
        })
      : authJsonRequest("/x", { email: "a@b.com" });
    const res = await handleInviteUser(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

});

// ---------- handleDeleteInvitation ----------

describe("handleDeleteInvitation", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleDeleteInvitation(
      noAuthJsonRequest("/x", { id: "i1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 when id is missing", async () => {
    const res = await handleDeleteInvitation(
      authJsonRequest("/x", {}),
      env,
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("id is required");
  });

  it("returns success on delete", async () => {
    // Setup: create invitation then delete
    const email = isLive
      ? `live-del-inv-${Date.now()}@example.com`
      : "del-inv@example.com";

    stubOrReal(
      new Response(
        JSON.stringify({
          id: "del-inv-id",
          email: "del-inv@example.com",
          role: "admin",
        }),
        { status: 200 },
      ),
    );
    const invRes = await handleInviteUser(
      authJsonRequest("/x", { email }),
      env,
    );
    const inv = (await invRes.json()) as { id: string };
    const deleteId = inv.id || "del-inv-id";

    // Act: delete
    stubOrReal(new Response("ok", { status: 200 }));
    const res = await handleDeleteInvitation(
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
          body: JSON.stringify({
            id: "00000000-0000-0000-0000-000000000000",
          }),
        })
      : authJsonRequest("/x", { id: "i1" });
    const res = await handleDeleteInvitation(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

});

// ---------- handleDeleteUser ----------

describe("handleDeleteUser", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleDeleteUser(
      noAuthJsonRequest("/x", { id: "u1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 when id is missing", async () => {
    const res = await handleDeleteUser(
      authJsonRequest("/x", {}),
      env,
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("id is required");
  });

  it("returns success on delete", async () => {
    // Use a valid UUID for live mode (non-existent user returns 404, which is acceptable)
    const userId = "00000000-0000-0000-0000-000000000099";
    stubOrReal(new Response("ok", { status: 200 }));
    const res = await handleDeleteUser(
      authJsonRequest("/x", { id: userId }),
      env,
    );
    // mock: 200, live: 200 or 404 (user may not exist)
    if (isLive) {
      expect([200, 404]).toContain(res.status);
      if (res.status === 200) {
        expect(await res.json()).toEqual({ success: true });
      }
    } else {
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ success: true });
    }
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
          body: JSON.stringify({
            id: "00000000-0000-0000-0000-000000000000",
          }),
        })
      : authJsonRequest("/x", { id: "u1" });
    const res = await handleDeleteUser(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

});
