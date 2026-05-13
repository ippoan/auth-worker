/**
 * `McpSession` DO unit test (Phase 6 routing + Phase 7 frame mapping).
 *
 * vanilla vitest 環境では `WebSocketPair` / `acceptWebSocket` / `Response(null,
 * { status: 101, webSocket })` が runtime に存在しない (undici Response は
 * 101 を弾く)。test 用に `Response` / `WebSocketPair` を polyfill してから DO
 * を import する。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// --- Response polyfill: allow status 101 + webSocket prop ---
const OriginalResponse = globalThis.Response;
class ResponseWithWS extends OriginalResponse {
  constructor(body?: BodyInit | null, init?: ResponseInit) {
    const { status, ...rest } = init ?? {};
    const safeStatus = status === 101 ? 200 : status;
    super(body ?? null, { ...rest, status: safeStatus });
    if (status !== undefined && status !== safeStatus) {
      Object.defineProperty(this, "status", { value: status, configurable: true });
    }
    const ws = (init as ResponseInit & { webSocket?: unknown })?.webSocket;
    if (ws) {
      Object.defineProperty(this, "webSocket", { value: ws, configurable: true });
    }
  }
}
(globalThis as unknown as { Response: typeof Response }).Response =
  ResponseWithWS as unknown as typeof Response;

interface FakeWebSocket {
  close: ReturnType<typeof vi.fn>;
  send: ReturnType<typeof vi.fn>;
  __id: string;
}

function makeFakeWs(id: string): FakeWebSocket {
  return {
    close: vi.fn(),
    send: vi.fn(),
    __id: id,
  };
}

class WebSocketPairStub {
  0: FakeWebSocket;
  1: FakeWebSocket;
  constructor() {
    this[0] = makeFakeWs("client");
    this[1] = makeFakeWs("server");
  }
}
(globalThis as unknown as { WebSocketPair: unknown }).WebSocketPair = WebSocketPairStub;

function createMockState(initial: FakeWebSocket[] = []): {
  state: DurableObjectState;
  current: FakeWebSocket[];
  acceptCalls: { ws: WebSocket; tags: string[] | undefined }[];
} {
  const current: FakeWebSocket[] = [...initial];
  const acceptCalls: { ws: WebSocket; tags: string[] | undefined }[] = [];
  const state = {
    getWebSockets: (_tag?: string) => current as unknown as WebSocket[],
    acceptWebSocket: (ws: WebSocket, tags?: string[]) => {
      acceptCalls.push({ ws, tags });
      current.push(ws as unknown as FakeWebSocket);
    },
  } as unknown as DurableObjectState;
  return { state, current, acceptCalls };
}

// import after the polyfills
import { McpSession } from "../../src/durable_objects/mcp-session-do";

// --- crypto.randomUUID stub for deterministic ids in tests ---
// `globalThis.crypto` は node 19+ / vitest 環境で存在するが TS 型は narrow なので as cast。
const cryptoRef = (globalThis as unknown as { crypto: Crypto }).crypto;
const originalCryptoRandomUUID = cryptoRef?.randomUUID;

function setStubUUID(id: string): void {
  Object.defineProperty(cryptoRef, "randomUUID", {
    value: () => id,
    configurable: true,
  });
}

function restoreUUID(): void {
  if (originalCryptoRandomUUID) {
    Object.defineProperty(cryptoRef, "randomUUID", {
      value: originalCryptoRandomUUID,
      configurable: true,
    });
  }
}

// --- helpers for base64 (tests use the same decode the binary uses) ---
function b64encode(s: string): string {
  return btoa(s);
}
function b64decode(b64: string): string {
  return atob(b64);
}

/**
 * `do_.fetch(...)` は内部で `await req.arrayBuffer()` を経てから `ws.send()` を呼ぶ。
 * `Promise.resolve()` 数発では超えられないので、send mock の最初の呼び出しを Promise で
 * 待ち合わせる。返り値は送信された JSON 文字列。
 */
function whenSent(ws: FakeWebSocket): Promise<string> {
  return new Promise<string>((resolve) => {
    ws.send.mockImplementation((data: unknown) => {
      resolve(String(data));
    });
  });
}

// =============================================================================
// Phase 6 routing tests (unchanged from previous PR)
// =============================================================================

describe("McpSession.fetch — /__connect", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 426 when Upgrade header is not websocket", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__connect", { method: "GET" });
    const res = await do_.fetch(req);
    expect(res.status).toBe(426);
    expect(await res.text()).toBe("Expected websocket");
  });

  it("accepts a fresh WebSocket (no existing) and returns 101", async () => {
    const { state, acceptCalls } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__connect", {
      method: "GET",
      headers: { Upgrade: "websocket" },
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(101);
    expect(acceptCalls).toHaveLength(1);
    expect(acceptCalls[0]?.tags).toEqual(["client"]);
  });

  it("closes existing WS with code 1000 'replaced' before accepting the new one", async () => {
    const old = makeFakeWs("old");
    const { state, acceptCalls } = createMockState([old]);
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__connect", {
      method: "GET",
      headers: { Upgrade: "websocket" },
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(101);
    expect(old.close).toHaveBeenCalledWith(1000, "replaced");
    expect(acceptCalls).toHaveLength(1);
  });

  it("swallows errors from old.close() and still accepts the new WS", async () => {
    const old = makeFakeWs("old");
    old.close.mockImplementation(() => {
      throw new Error("already closed");
    });
    const { state, acceptCalls } = createMockState([old]);
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__connect", {
      method: "GET",
      headers: { Upgrade: "websocket" },
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(101);
    expect(old.close).toHaveBeenCalled();
    expect(acceptCalls).toHaveLength(1);
  });
});

describe("McpSession.fetch — unknown path", () => {
  it("returns 404", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/whatever", { method: "GET" });
    const res = await do_.fetch(req);
    expect(res.status).toBe(404);
  });
});

// =============================================================================
// Phase 7: handleBridge — frame round-trip
// =============================================================================

describe("McpSession.fetch — /__bridge (Phase 7 frame mapping)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  afterEach(() => {
    restoreUUID();
  });

  it("returns 503 when no active WebSocket", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", { method: "POST" });
    const res = await do_.fetch(req);
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("no_active_relay_session");
  });

  it("sends Frame::Req with uuid + method + path '/' + filtered headers + base64 body", async () => {
    setStubUUID("uuid-1");
    const ws = makeFakeWs("active");
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});
    const sentP = whenSent(ws);

    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer should-be-stripped",
        "CF-Ray": "should-be-stripped",
        "X-Forwarded-For": "should-be-stripped",
        Accept: "application/json, text/event-stream",
      },
      body: '{"hello":"world"}',
    });

    const respPromise = do_.fetch(req);
    const sent = JSON.parse(await sentP);
    expect(sent).toMatchObject({
      kind: "req",
      v: 1,
      id: "uuid-1",
      method: "POST",
      path: "/",
    });
    // body_b64 round-trip
    expect(b64decode(sent.body_b64)).toBe('{"hello":"world"}');
    // header allowlist
    expect(sent.headers).toMatchObject({
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    });
    // hop-by-hop / sensitive headers must be stripped (Authorization は本物の JWT、
    // X-Forwarded-* / CF-* は Cloudflare 由来で binary 側に漏らさない)
    expect(sent.headers).not.toHaveProperty("authorization");
    expect(sent.headers).not.toHaveProperty("cf-ray");
    expect(sent.headers).not.toHaveProperty("x-forwarded-for");
    // Host は意図的に保持 (issue #121): binary 側 rmcp が Host header 必須。
    // 本テスト fixture では undici Request が Host header を構築時に上書き / 落とすが、
    // blocklist には含めないことだけ検証する (上で expect not.toHaveProperty を書かない)。

    // simulate binary side responding
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        kind: "resp",
        v: 1,
        id: "uuid-1",
        status: 200,
        headers: { "content-type": "application/json" },
        body_b64: b64encode('{"ok":true}'),
      }),
    );
    const res = await respPromise;
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json");
    expect(await res.text()).toBe('{"ok":true}');
  });

  it("preserves a non-200 status from the binary response frame", async () => {
    setStubUUID("uuid-status");
    const ws = makeFakeWs("active");
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});
    const sentP = whenSent(ws);

    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", { method: "POST", body: "x" }),
    );
    await sentP;

    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        kind: "resp",
        v: 1,
        id: "uuid-status",
        status: 418,
        headers: {},
        body_b64: b64encode("teapot"),
      }),
    );
    const res = await respPromise;
    expect(res.status).toBe(418);
    expect(await res.text()).toBe("teapot");
  });

  it("returns empty body when body_b64 is empty / missing", async () => {
    setStubUUID("uuid-empty");
    const ws = makeFakeWs("active");
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});
    const sentP = whenSent(ws);

    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", { method: "GET" }),
    );
    await sentP;

    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ kind: "resp", v: 1, id: "uuid-empty", status: 204 }),
    );
    const res = await respPromise;
    expect(res.status).toBe(204);
    expect(await res.text()).toBe("");
  });

  it("returns 502 when ws.send throws synchronously", async () => {
    setStubUUID("uuid-send-fail");
    const ws = makeFakeWs("active");
    ws.send.mockImplementation(() => {
      throw new Error("ws closed mid-flight");
    });
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});

    const res = await do_.fetch(
      new Request("https://do.invalid/__bridge", { method: "POST", body: "x" }),
    );
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe("relay_send_failed");
    expect(body.message).toContain("ws closed mid-flight");
  });

  it("returns 502 when ws.send throws a non-Error value", async () => {
    setStubUUID("uuid-send-fail-2");
    const ws = makeFakeWs("active");
    ws.send.mockImplementation(() => {
      // eslint-disable-next-line @typescript-eslint/no-throw-literal
      throw "string-error";
    });
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});

    const res = await do_.fetch(
      new Request("https://do.invalid/__bridge", { method: "POST", body: "x" }),
    );
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe("relay_send_failed");
    expect(body.message).toBe("string-error");
  });

  it("returns 504 on relay_timeout (vi fake timers)", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: false });
    try {
      setStubUUID("uuid-timeout");
      const ws = makeFakeWs("active");
      const { state } = createMockState([ws]);
      const do_ = new McpSession(state, {});
      const sentP = whenSent(ws);

      const respPromise = do_.fetch(
        new Request("https://do.invalid/__bridge", { method: "POST", body: "x" }),
      );
      // pump microtasks until ws.send fires (req.arrayBuffer に乗っかってる)
      await sentP;
      // setTimeout(REQUEST_TIMEOUT_MS) は fake timer に乗ったので advance で trigger
      await vi.advanceTimersByTimeAsync(30_000);
      const res = await respPromise;
      expect(res.status).toBe(504);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("relay_timeout");
    } finally {
      vi.useRealTimers();
    }
  });

  it("returns 502 when WS closes while the request is in-flight", async () => {
    setStubUUID("uuid-close-mid");
    const ws = makeFakeWs("active");
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});
    const sentP = whenSent(ws);

    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", { method: "POST", body: "x" }),
    );
    await sentP;
    await do_.webSocketClose(ws as unknown as WebSocket, 1006, "abnormal", false);
    const res = await respPromise;
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("relay_session_closed");
  });

  it("returns 502 when the WS errors while the request is in-flight", async () => {
    setStubUUID("uuid-error-mid");
    const ws = makeFakeWs("active");
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});
    const sentP = whenSent(ws);

    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", { method: "POST", body: "x" }),
    );
    await sentP;
    await do_.webSocketError(ws as unknown as WebSocket, new Error("boom"));
    const res = await respPromise;
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("relay_session_error");
  });

  it("drops invalid response header values without crashing", async () => {
    setStubUUID("uuid-bad-header");
    const ws = makeFakeWs("active");
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});
    const sentP = whenSent(ws);

    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", { method: "POST", body: "x" }),
    );
    await sentP;

    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        kind: "resp",
        v: 1,
        id: "uuid-bad-header",
        status: 200,
        headers: {
          "content-type": "application/json",
          // header value with embedded \n is invalid in HTTP and will throw on Headers.set
          "x-bad": "line1\nline2",
        },
        body_b64: b64encode("{}"),
      }),
    );
    const res = await respPromise;
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json");
    expect(res.headers.get("x-bad")).toBeNull();
  });

  it("ignores malformed frames (non-JSON / not-object / wrong kind / wrong id type / unknown id)", async () => {
    const ws = makeFakeWs("active");
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});

    // none of these should throw
    await do_.webSocketMessage(ws as unknown as WebSocket, "not json");
    await do_.webSocketMessage(ws as unknown as WebSocket, "null"); // parse OK but null
    await do_.webSocketMessage(ws as unknown as WebSocket, '"just-a-string"'); // not object
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ kind: "hello", v: 1 }), // hello is fine but ignored
    );
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ kind: "resp", id: 123 }), // wrong id type
    );
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ kind: "resp", v: 1, id: "no-pending-with-this-id", status: 200 }),
    );
    // also accepts ArrayBuffer message variant (TextEncoder returns Uint8Array; we
    // copy into a fresh ArrayBuffer so TS does not see SharedArrayBuffer-backed buffer).
    const u8 = new TextEncoder().encode("not json");
    const ab = new ArrayBuffer(u8.byteLength);
    new Uint8Array(ab).set(u8);
    await do_.webSocketMessage(ws as unknown as WebSocket, ab);
  });
});

describe("McpSession lifecycle hooks (no pending requests)", () => {
  it("webSocketClose with no pending is a no-op", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const ws = makeFakeWs("ws") as unknown as WebSocket;
    await expect(do_.webSocketClose(ws, 1000, "bye", true)).resolves.toBeUndefined();
  });

  it("webSocketError with no pending is a no-op", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const ws = makeFakeWs("ws") as unknown as WebSocket;
    await expect(do_.webSocketError(ws, new Error("oops"))).resolves.toBeUndefined();
  });
});

afterEach(() => {
  vi.clearAllMocks();
  restoreUUID();
});
