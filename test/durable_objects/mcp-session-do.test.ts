/**
 * `McpSession` DO unit test (issue #117 / Phase 6).
 *
 * vanilla vitest 環境では `WebSocketPair` / `acceptWebSocket` / `Response(null,
 * { status: 101, webSocket })` が runtime に存在しない (undici Response は
 * 101 を弾く)。test 用に `Response` / `WebSocketPair` を polyfill してから DO
 * を import する。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// --- Response polyfill: allow status 101 + webSocket prop ---
// 元の Response を継承し、101 のときは super に 200 を渡して `status` getter を上書き、
// `webSocket` プロパティをそのまま生やす。
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
  __id: string;
}

function makeFakeWs(id: string): FakeWebSocket {
  return {
    close: vi.fn(),
    __id: id,
  };
}

// `WebSocketPair` を polyfill: `new WebSocketPair()` で `[client, server]` を返す。
// Cloudflare Workers では index access (`pair[0]`/`pair[1]`) で client/server。
class WebSocketPairStub {
  0: FakeWebSocket;
  1: FakeWebSocket;
  constructor() {
    this[0] = makeFakeWs("client");
    this[1] = makeFakeWs("server");
  }
}
(globalThis as unknown as { WebSocketPair: unknown }).WebSocketPair = WebSocketPairStub;

// `Response` の `webSocket` プロパティを通すために、Response constructor の
// 第 2 引数を拡張側に渡す: native Response は `webSocket` を ResponseInit に
// 認めないため `as any` でバイパスする (テスト目的の only-skeleton check)。

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
      // simulate: accepted server WS joins the active list
      current.push(ws as unknown as FakeWebSocket);
    },
  } as unknown as DurableObjectState;
  return { state, current, acceptCalls };
}

// import after the polyfill
import { McpSession } from "../../src/durable_objects/mcp-session-do";

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

describe("McpSession.fetch — /__bridge", () => {
  it("returns 503 when no active WebSocket", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", { method: "POST" });
    const res = await do_.fetch(req);
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("no_active_relay_session");
  });

  it("returns 501 'phase 7' when WebSocket is active (Phase 6 stub)", async () => {
    const ws = makeFakeWs("active");
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", { method: "POST" });
    const res = await do_.fetch(req);
    expect(res.status).toBe(501);
    const body = (await res.json()) as { error: string; phase: number };
    expect(body.error).toBe("bridge_not_implemented");
    expect(body.phase).toBe(7);
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

describe("McpSession lifecycle hooks (Phase 6 no-op)", () => {
  // Phase 7 で frame handling を入れるまで no-op が壊れないことだけ確認する。
  it("webSocketMessage is no-op (accepts both string and ArrayBuffer)", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const ws = makeFakeWs("ws") as unknown as WebSocket;
    await expect(do_.webSocketMessage(ws, "hi")).resolves.toBeUndefined();
    await expect(do_.webSocketMessage(ws, new ArrayBuffer(4))).resolves.toBeUndefined();
  });

  it("webSocketClose is no-op", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const ws = makeFakeWs("ws") as unknown as WebSocket;
    await expect(do_.webSocketClose(ws, 1000, "bye", true)).resolves.toBeUndefined();
  });

  it("webSocketError is no-op", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const ws = makeFakeWs("ws") as unknown as WebSocket;
    await expect(do_.webSocketError(ws, new Error("oops"))).resolves.toBeUndefined();
  });
});

afterEach(() => {
  vi.clearAllMocks();
});
