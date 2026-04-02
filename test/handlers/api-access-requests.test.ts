import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

const mockCreateAccessRequest = vi.fn();
const mockListAccessRequests = vi.fn();
const mockApproveAccessRequest = vi.fn();
const mockDeclineAccessRequest = vi.fn();
vi.mock("@connectrpc/connect", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@connectrpc/connect")>();
  return {
    ...actual,
    createClient: vi.fn(() => ({
      createAccessRequest: mockCreateAccessRequest,
      listAccessRequests: mockListAccessRequests,
      approveAccessRequest: mockApproveAccessRequest,
      declineAccessRequest: mockDeclineAccessRequest,
    })),
  };
});
vi.mock("../../src/lib/transport", () => ({
  createTransportWithAuth: vi.fn(),
}));
vi.mock("@yhonda-ohishi-pub-dev/logi-proto", () => ({
  AccessRequestService: {},
}));

import {
  handleAccessRequestCreate,
  handleAccessRequestList,
  handleAccessRequestApprove,
  handleAccessRequestDecline,
} from "../../src/handlers/api-access-requests";

function jsonRequest(url: string, body: unknown, token?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return new Request(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

describe("handleAccessRequestCreate", () => {
  const env = createMockEnv();
  beforeEach(() => vi.clearAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleAccessRequestCreate(
      jsonRequest("https://x.com", { org_slug: "test" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 without org_slug", async () => {
    const res = await handleAccessRequestCreate(
      jsonRequest("https://x.com", {}, "tok"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns created request on success", async () => {
    mockCreateAccessRequest.mockResolvedValueOnce({
      id: "r1",
      status: "pending",
      orgName: "Test Org",
    });
    const res = await handleAccessRequestCreate(
      jsonRequest("https://x.com", { org_slug: "test" }, "tok"),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { id: string; org_name: string };
    expect(data.id).toBe("r1");
    expect(data.org_name).toBe("Test Org");
  });

  it("returns 400 on ConnectError", async () => {
    const { ConnectError } = await import("@connectrpc/connect");
    mockCreateAccessRequest.mockRejectedValueOnce(new ConnectError("dup", 3));
    const res = await handleAccessRequestCreate(
      jsonRequest("https://x.com", { org_slug: "test" }, "tok"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("throws non-ConnectError", async () => {
    mockCreateAccessRequest.mockRejectedValueOnce(new Error("boom"));
    await expect(
      handleAccessRequestCreate(
        jsonRequest("https://x.com", { org_slug: "test" }, "tok"),
        env,
      ),
    ).rejects.toThrow("boom");
  });
});

describe("handleAccessRequestList", () => {
  const env = createMockEnv();
  beforeEach(() => vi.clearAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleAccessRequestList(
      jsonRequest("https://x.com", {}),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns list on success", async () => {
    mockListAccessRequests.mockResolvedValueOnce({
      requests: [
        {
          id: "r1", userId: "u1", email: "a@b.com", displayName: "A",
          avatarUrl: "", provider: "google", status: "pending",
          role: "member", reviewedBy: "", reviewedAt: "", createdAt: "2025-01-01",
        },
      ],
    });
    const res = await handleAccessRequestList(
      jsonRequest("https://x.com", { status_filter: "pending" }, "tok"),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { requests: Array<{ email: string }> };
    expect(data.requests).toHaveLength(1);
    expect(data.requests[0]!.email).toBe("a@b.com");
  });

  it("returns empty array when requests is undefined", async () => {
    mockListAccessRequests.mockResolvedValueOnce({});
    const res = await handleAccessRequestList(
      jsonRequest("https://x.com", {}, "tok"),
      env,
    );
    const data = (await res.json()) as { requests: unknown[] };
    expect(data.requests).toEqual([]);
  });

  it("returns 400 on ConnectError", async () => {
    const { ConnectError } = await import("@connectrpc/connect");
    mockListAccessRequests.mockRejectedValueOnce(new ConnectError("fail", 3));
    const res = await handleAccessRequestList(
      jsonRequest("https://x.com", {}, "tok"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("throws non-ConnectError", async () => {
    mockListAccessRequests.mockRejectedValueOnce(new Error("boom"));
    await expect(
      handleAccessRequestList(jsonRequest("https://x.com", {}, "tok"), env),
    ).rejects.toThrow("boom");
  });
});

describe("handleAccessRequestApprove", () => {
  const env = createMockEnv();
  beforeEach(() => vi.clearAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleAccessRequestApprove(
      jsonRequest("https://x.com", { request_id: "r1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 without request_id", async () => {
    const res = await handleAccessRequestApprove(
      jsonRequest("https://x.com", {}, "tok"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns success on approve", async () => {
    mockApproveAccessRequest.mockResolvedValueOnce({});
    const res = await handleAccessRequestApprove(
      jsonRequest("https://x.com", { request_id: "r1", role: "admin" }, "tok"),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true });
  });

  it("uses default role 'member' when not specified", async () => {
    mockApproveAccessRequest.mockResolvedValueOnce({});
    await handleAccessRequestApprove(
      jsonRequest("https://x.com", { request_id: "r1" }, "tok"),
      env,
    );
    expect(mockApproveAccessRequest).toHaveBeenCalledWith(
      expect.objectContaining({ role: "member" }),
    );
  });

  it("returns 400 on ConnectError", async () => {
    const { ConnectError } = await import("@connectrpc/connect");
    mockApproveAccessRequest.mockRejectedValueOnce(new ConnectError("fail", 3));
    const res = await handleAccessRequestApprove(
      jsonRequest("https://x.com", { request_id: "r1" }, "tok"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("throws non-ConnectError", async () => {
    mockApproveAccessRequest.mockRejectedValueOnce(new Error("boom"));
    await expect(
      handleAccessRequestApprove(
        jsonRequest("https://x.com", { request_id: "r1" }, "tok"),
        env,
      ),
    ).rejects.toThrow("boom");
  });
});

describe("handleAccessRequestDecline", () => {
  const env = createMockEnv();
  beforeEach(() => vi.clearAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleAccessRequestDecline(
      jsonRequest("https://x.com", { request_id: "r1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 without request_id", async () => {
    const res = await handleAccessRequestDecline(
      jsonRequest("https://x.com", {}, "tok"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns success on decline", async () => {
    mockDeclineAccessRequest.mockResolvedValueOnce({});
    const res = await handleAccessRequestDecline(
      jsonRequest("https://x.com", { request_id: "r1" }, "tok"),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true });
  });

  it("returns 400 on ConnectError", async () => {
    const { ConnectError } = await import("@connectrpc/connect");
    mockDeclineAccessRequest.mockRejectedValueOnce(new ConnectError("fail", 3));
    const res = await handleAccessRequestDecline(
      jsonRequest("https://x.com", { request_id: "r1" }, "tok"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("throws non-ConnectError", async () => {
    mockDeclineAccessRequest.mockRejectedValueOnce(new Error("boom"));
    await expect(
      handleAccessRequestDecline(
        jsonRequest("https://x.com", { request_id: "r1" }, "tok"),
        env,
      ),
    ).rejects.toThrow("boom");
  });
});
