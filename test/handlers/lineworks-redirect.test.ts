import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

import { handleLineworksRedirect } from "../../src/handlers/lineworks-redirect";

describe("handleLineworksRedirect", () => {
  const env = createMockEnv();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it("returns 400 for missing redirect_uri", async () => {
    const req = new Request("https://auth.test.example/oauth/lineworks/redirect?address=user@ohishi");
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("redirect_uri");
  });

  it("returns 400 for invalid redirect_uri", async () => {
    const req = new Request("https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://evil.com&address=user@ohishi");
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 for missing address", async () => {
    const req = new Request("https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://app1.test.example/cb");
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("address");
  });

  it("returns 400 for address with @ but empty domain", async () => {
    const req = new Request("https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://app1.test.example/cb&address=user@");
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Invalid");
  });

  it("proxies to ALC API with domain extracted from email-like address", async () => {
    const originalFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(null, {
        status: 307,
        headers: { Location: "https://lineworks.example.com/auth" },
      }),
    ));

    const req = new Request("https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://app1.test.example/cb&address=tanaka@ohishi");
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(307);
    expect(res.headers.get("Location")).toBe("https://lineworks.example.com/auth");

    const fetchCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(fetchCall[0]).toContain("domain=ohishi");
    expect(fetchCall[0]).toContain("redirect_uri=");

    vi.stubGlobal("fetch", originalFetch);
  });

  it("uses address directly as domain when no @ present", async () => {
    const originalFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(null, { status: 307, headers: { Location: "https://lw.example.com" } }),
    ));

    const req = new Request("https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://app1.test.example/cb&address=ohishi");
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(307);

    const fetchCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(fetchCall[0]).toContain("domain=ohishi");

    vi.stubGlobal("fetch", originalFetch);
  });
});
