import { describe, it, expect, vi, afterEach } from "vitest";

import { LineworksWebhookDO } from "../../src/durable_objects/lineworks-webhook-do";

// W8b: DO の backend (bot-secret の取得・イベントの送信) は Service Binding ALC_NOTIFY で
// alc-notify-worker を呼ぶ (内部用の token は付けない)。

function mockState(initial: Record<string, unknown> = {}) {
  const data = new Map<string, unknown>(Object.entries(initial));
  const storage = {
    get: async (key: string) => data.get(key),
    put: async (key: string, value: unknown) => {
      data.set(key, value);
    },
    delete: async (key: string) => data.delete(key),
    list: async (opts: { prefix?: string } = {}) =>
      new Map([...data].filter(([k]) => k.startsWith(opts.prefix ?? ""))),
    setAlarm: vi.fn(async () => {}),
  };
  return { state: { storage } as unknown as DurableObjectState, data, storage };
}

function makeDO(state: DurableObjectState, binding?: { fetch: ReturnType<typeof vi.fn> }) {
  const env = {
    SSO_ENCRYPTION_KEY: "unused",
    ...(binding ? { ALC_NOTIFY: binding as unknown as Fetcher } : {}),
  };
  return new LineworksWebhookDO(state, env as unknown as ConstructorParameters<typeof LineworksWebhookDO>[1]);
}

function eventReq(botId: string): Request {
  return new Request("https://do/event", {
    method: "POST",
    headers: { "x-bot-id": botId, "x-works-signature": "c2ln" },
    body: "{}",
  });
}

const item = {
  event: { bot_id: "bot-1", event_type: "joined", channel_id: "ch-1" },
  ts: 0,
  attempts: 0,
};

afterEach(() => vi.restoreAllMocks());

describe("LineworksWebhookDO backend (ALC_NOTIFY)", () => {
  it("fetches bot_secret_encrypted from alc-notify via the binding", async () => {
    const fetchSpy = vi.fn(async () => new Response(JSON.stringify({ error: "bot_not_found" }), { status: 404 }));
    const { state } = mockState();
    const res = await makeDO(state, { fetch: fetchSpy }).fetch(eventReq("bot/1"));

    // 取れなければ 401 (署名を確かめられない)
    expect(res.status).toBe(401);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://alc-notify/api/internal/lineworks/bot-secret/bot%2F1");
    expect(init.method).toBe("GET");
    expect(init.redirect).toBe("manual");
    expect(init.headers).toBeUndefined();
  });

  it("does not fetch the secret when ALC_NOTIFY is not bound", async () => {
    const globalFetch = vi.fn();
    vi.stubGlobal("fetch", globalFetch);
    const { state } = mockState();
    const res = await makeDO(state).fetch(eventReq("bot-1"));

    expect(res.status).toBe(401);
    expect(globalFetch).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("posts queued events to alc-notify via the binding and drops them on success", async () => {
    const fetchSpy = vi.fn(async () => new Response('{"ok":true}', { status: 200 }));
    const { state, data } = mockState({ "queue:1": item });
    await makeDO(state, { fetch: fetchSpy }).alarm();

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://alc-notify/api/internal/lineworks/event");
    expect(init.method).toBe("POST");
    expect(init.redirect).toBe("manual");
    expect(init.headers).toEqual({ "Content-Type": "application/json" });
    expect(JSON.parse(init.body as string)).toEqual(item.event);
    expect(data.has("queue:1")).toBe(false);
  });

  it("keeps the event for retry when the worker fails or is not bound", async () => {
    const failing = vi.fn(async () => new Response("", { status: 500 }));
    const first = mockState({ "queue:1": item });
    await makeDO(first.state, { fetch: failing }).alarm();
    expect(first.data.get("queue:1")).toEqual({ ...item, attempts: 1 });
    expect(first.storage.setAlarm).toHaveBeenCalledTimes(1);

    const unbound = mockState({ "queue:1": item });
    await makeDO(unbound.state).alarm();
    expect(unbound.data.get("queue:1")).toEqual({ ...item, attempts: 1 });
  });
});
