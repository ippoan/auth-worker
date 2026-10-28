import { describe, it, expect, vi, afterEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

import { handleLineWebhook } from "../../src/handlers/line-webhook";

// W8b: forwarder は Service Binding ALC_NOTIFY で alc-notify-worker へ raw body と署名を渡す
// (内部用の token は付けない)。
const NOTIFY_URL = "https://alc-notify/api/internal/notify/line/webhook";

function envWith(fetchImpl: (url: string, init: RequestInit) => Promise<Response>) {
  const fetchSpy = vi.fn(fetchImpl);
  const env = createMockEnv({ ALC_NOTIFY: { fetch: fetchSpy } as unknown as Fetcher });
  return { env, fetchSpy };
}

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

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("handleLineWebhook", () => {
  it("returns 401 when x-line-signature is missing (no upstream call)", async () => {
    const { env, fetchSpy } = envWith(async () => new Response("ok"));

    const res = await handleLineWebhook(lineReq({}), env);

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("missing_signature");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("returns 503 when ALC_NOTIFY is not bound (no Cloud Run fallback)", async () => {
    const globalFetch = vi.fn();
    vi.stubGlobal("fetch", globalFetch);

    const res = await handleLineWebhook(lineReq({ signature: "sig" }), createMockEnv());

    expect(res.status).toBe(503);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("notify_worker_not_bound");
    expect(globalFetch).not.toHaveBeenCalled();
  });

  it("forwards raw body + signature to alc-notify via the binding and passes status through", async () => {
    const { env, fetchSpy } = envWith(
      async () => new Response("ok", { status: 200, headers: { "Content-Type": "text/plain" } }),
    );

    const res = await handleLineWebhook(
      lineReq({ signature: "sig-abc", contentType: "application/json", body: '{"events":[]}' }),
      env,
    );

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/plain");

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [calledUrl, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(calledUrl).toBe(NOTIFY_URL);
    expect(init.method).toBe("POST");
    expect(init.redirect).toBe("manual");
    const h = init.headers as Record<string, string>;
    expect(h.Authorization).toBeUndefined();
    expect(h["x-line-signature"]).toBe("sig-abc");
    expect(h["Content-Type"]).toBe("application/json");
    expect(new TextDecoder().decode(init.body as ArrayBuffer)).toBe('{"events":[]}');
  });

  it("defaults Content-Type to application/json when request has none", async () => {
    // body=null の upstream は content-type を持たない → レスポンス側も application/json fallback
    const { env, fetchSpy } = envWith(async () => new Response(null, { status: 200 }));

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

  it("returns 502 when the binding throws", async () => {
    const { env } = envWith(async () => {
      throw new Error("network");
    });

    const res = await handleLineWebhook(lineReq({ signature: "sig" }), env);

    expect(res.status).toBe(502);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("upstream_unreachable");
  });

  it("passes through a non-2xx worker status (e.g. signature mismatch 401)", async () => {
    const { env } = envWith(async () => new Response("", { status: 401 }));

    const res = await handleLineWebhook(lineReq({ signature: "bad-sig" }), env);

    expect(res.status).toBe(401);
  });
});
