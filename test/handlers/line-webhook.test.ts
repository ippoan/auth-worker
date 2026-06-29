import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

// #434 lockdown: forwarder は internalAuthToken で OIDC を mint して rust internal へ
// forward する。token mint (Google token endpoint / HS256) は CI で実行できないので mock。
vi.mock("../../src/lib/alc-internal", () => ({
  internalAuthToken: vi.fn(async () => "test-oidc-token"),
}));

import { handleLineWebhook } from "../../src/handlers/line-webhook";

const env = createMockEnv({ ALC_API_ORIGIN: "https://alc-api.test.example" });
const INTERNAL_URL = "https://alc-api.test.example/api/internal/notify/line/webhook";

function lineReq(opts: { signature?: string; contentType?: string; body?: string } = {}): Request {
  const headers: Record<string, string> = {};
  if (opts.signature !== undefined) headers["x-line-signature"] = opts.signature;
  if (opts.contentType !== undefined) headers["content-type"] = opts.contentType;
  return new Request("https://auth.test.example/line/webhook", {
    method: "POST",
    headers,
    body: opts.body ?? JSON.stringify({ events: [] }),
  });
}

afterEach(() => vi.restoreAllMocks());

describe("handleLineWebhook", () => {
  beforeEach(() => vi.unstubAllGlobals());

  it("returns 401 when x-line-signature is missing (no upstream call)", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const res = await handleLineWebhook(lineReq({}), env);

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("missing_signature");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("forwards raw body + signature to rust internal with OIDC and passes status through", async () => {
    const fetchSpy = vi.fn().mockResolvedValueOnce(
      new Response("ok", { status: 200, headers: { "Content-Type": "text/plain" } }),
    );
    vi.stubGlobal("fetch", fetchSpy);

    const res = await handleLineWebhook(
      lineReq({ signature: "sig-abc", contentType: "application/json", body: '{"events":[]}' }),
      env,
    );

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/plain");

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [calledUrl, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(calledUrl).toBe(INTERNAL_URL);
    expect(init.method).toBe("POST");
    const h = init.headers as Record<string, string>;
    expect(h.Authorization).toBe("Bearer test-oidc-token");
    expect(h["x-line-signature"]).toBe("sig-abc");
    expect(h["Content-Type"]).toBe("application/json");
  });

  it("defaults Content-Type to application/json when request has none", async () => {
    // body=null の upstream は content-type を持たない → レスポンス側も application/json fallback
    const fetchSpy = vi.fn().mockResolvedValueOnce(new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);

    // body を付けない Request は content-type を持たない → forward 時に application/json fallback
    const req = new Request("https://auth.test.example/line/webhook", {
      method: "POST",
      headers: { "x-line-signature": "sig" },
    });
    const res = await handleLineWebhook(req, env);

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json");
    const h = (fetchSpy.mock.calls[0] as [string, RequestInit])[1].headers as Record<string, string>;
    expect(h["Content-Type"]).toBe("application/json");
  });

  it("returns 502 when upstream is unreachable", async () => {
    const fetchSpy = vi.fn().mockRejectedValueOnce(new Error("network"));
    vi.stubGlobal("fetch", fetchSpy);

    const res = await handleLineWebhook(lineReq({ signature: "sig" }), env);

    expect(res.status).toBe(502);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("upstream_unreachable");
  });

  it("passes through a non-2xx rust status (e.g. signature mismatch 401)", async () => {
    const fetchSpy = vi.fn().mockResolvedValueOnce(new Response("unauthorized", { status: 401 }));
    vi.stubGlobal("fetch", fetchSpy);

    const res = await handleLineWebhook(lineReq({ signature: "bad-sig" }), env);

    expect(res.status).toBe(401);
  });
});
