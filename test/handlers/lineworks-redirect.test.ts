import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import {
  stubOrReal,
  testEnv,
  restoreFetch,
  waitIfLive,
  isLive,
} from "../helpers/stub-or-real";
import { handleLineworksRedirect } from "../../src/handlers/lineworks-redirect";

afterAll(() => restoreFetch());
waitIfLive();

describe("handleLineworksRedirect", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 400 when redirect_uri is missing", async () => {
    const req = new Request(
      "https://auth.test.example/oauth/lineworks/redirect?address=tanaka@ohishi",
    );
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid or missing redirect_uri");
  });

  it("returns 400 when redirect_uri origin is not allowed", async () => {
    const req = new Request(
      "https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://evil.example.com/cb&address=tanaka@ohishi",
    );
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid or missing redirect_uri");
  });

  it("returns 400 when address is missing", async () => {
    const req = new Request(
      "https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://app1.test.example/callback",
    );
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Missing address parameter");
  });

  it("returns 400 when address has no domain part (trailing @)", async () => {
    const req = new Request(
      "https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://app1.test.example/callback&address=tanaka@",
    );
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid LINE WORKS address");
  });

  it("proxies to backend and passes through redirect response", async () => {
    stubOrReal(
      new Response(null, {
        status: 307,
        headers: { Location: "https://auth.worksmobile.com/oauth2/v2.0/authorize?client_id=xxx" },
      }),
    );
    const req = new Request(
      "https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://app1.test.example/callback&address=tanaka@ohishi",
    );
    const res = await handleLineworksRedirect(req, env);
    // Backend returns a redirect (307 or 302)
    expect([302, 307]).toContain(res.status);
  });

  it("uses domain-only address without @ sign", async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response(null, {
        status: 307,
        headers: { Location: "https://auth.worksmobile.com/oauth2/v2.0/authorize" },
      }),
    );
    if (!isLive) vi.stubGlobal("fetch", mockFetch);

    const req = new Request(
      "https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://app1.test.example/callback&address=ohishi",
    );
    const res = await handleLineworksRedirect(req, env);
    expect([302, 307]).toContain(res.status);

    // Verify domain extracted correctly (mock-only)
    if (!isLive) {
      const calledUrl = new URL(mockFetch.mock.calls[0]![0] as string);
      expect(calledUrl.searchParams.get("domain")).toBe("ohishi");
    }
  });
});
