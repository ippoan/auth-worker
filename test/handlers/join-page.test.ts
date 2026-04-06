import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

vi.mock("../../src/lib/join-html", () => ({
  renderJoinPage: vi.fn(() => "<html>mock join page</html>"),
  renderJoinNotFoundPage: vi.fn(() => "<html>mock not found</html>"),
}));

import { handleJoinPage } from "../../src/handlers/join-page";
import { renderJoinPage, renderJoinNotFoundPage } from "../../src/lib/join-html";

describe("handleJoinPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 404 with renderJoinNotFoundPage when backend returns 404", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("Not Found", { status: 404 })),
    );
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/join/unknown-org");

    const res = await handleJoinPage(req, env, "unknown-org");

    expect(res.status).toBe(404);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await res.text()).toBe("<html>mock not found</html>");
    expect(renderJoinNotFoundPage).toHaveBeenCalled();
  });

  it("returns 500 when backend returns non-404 error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("Server Error", { status: 500 })),
    );
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/join/some-org");

    const res = await handleJoinPage(req, env, "some-org");

    expect(res.status).toBe(500);
    expect(await res.text()).toBe("Internal Server Error");
  });

  it("returns 404 when backend returns found: false", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ found: false, name: "" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/join/inactive-org");

    const res = await handleJoinPage(req, env, "inactive-org");

    expect(res.status).toBe(404);
    expect(await res.text()).toBe("<html>mock not found</html>");
    expect(renderJoinNotFoundPage).toHaveBeenCalled();
  });

  it("returns 200 with renderJoinPage on success", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ found: true, name: "Test Org" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/join/test-org");

    const res = await handleJoinPage(req, env, "test-org");

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await res.text()).toBe("<html>mock join page</html>");
    expect(renderJoinPage).toHaveBeenCalledWith({
      orgName: "Test Org",
      orgSlug: "test-org",
      googleEnabled: true,
      authWorkerOrigin: "https://auth.test.example",
    });
  });

  it("passes googleEnabled: false when GOOGLE_CLIENT_ID is empty", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ found: true, name: "No Google Org" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const env = createMockEnv({ GOOGLE_CLIENT_ID: "" });
    const req = new Request("https://auth.test.example/join/no-google");

    const res = await handleJoinPage(req, env, "no-google");

    expect(res.status).toBe(200);
    expect(renderJoinPage).toHaveBeenCalledWith(
      expect.objectContaining({ googleEnabled: false }),
    );
  });

  it("returns 500 on fetch exception", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValueOnce(new Error("network error")),
    );
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/join/err-org");

    const res = await handleJoinPage(req, env, "err-org");

    expect(res.status).toBe(500);
    expect(await res.text()).toBe("Internal Server Error");
  });

  it("encodes slug in the backend URL", async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({ found: true, name: "Slug Org" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", mockFetch);
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/join/my%20org");

    await handleJoinPage(req, env, "my org");

    const calledUrl = mockFetch.mock.calls[0]![0] as string;
    expect(calledUrl).toContain("/api/tenants/by-slug/my%20org");
  });
});
