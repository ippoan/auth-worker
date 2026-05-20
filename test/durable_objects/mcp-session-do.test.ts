/**
 * `McpSession` DO unit test (Phase 6 routing + Phase 7 frame mapping).
 *
 * vanilla vitest 環境では `WebSocketPair` / `acceptWebSocket` / `Response(null,
 * { status: 101, webSocket })` が runtime に存在しない (undici Response は
 * 101 を弾く)。test 用に `Response` / `WebSocketPair` を polyfill してから DO
 * を import する。
 */

import { describe, it, expect, vi, beforeAll, beforeEach, afterAll, afterEach } from "vitest";

// [tracer #123] DO に追加した `[mcp-relay] ...` 観測 log で test 出力が騒がしく
// なるのを防ぐ。本物の挙動は staging wrangler tail で確認する。
let consoleLogSpy: ReturnType<typeof vi.spyOn> | undefined;
beforeAll(() => {
  consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {});
});
afterAll(() => {
  consoleLogSpy?.mockRestore();
});

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
  /** WebSocket.readyState — DO は OPEN(1) のみ採用するので default は OPEN。 */
  readyState: number;
}

function makeFakeWs(id: string, readyState: number = 1 /* OPEN */): FakeWebSocket {
  return {
    close: vi.fn(),
    send: vi.fn(),
    __id: id,
    readyState,
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
  storageMap: Map<string, unknown>;
  alarmCalls: number[];
} {
  const current: FakeWebSocket[] = [...initial];
  const acceptCalls: { ws: WebSocket; tags: string[] | undefined }[] = [];
  // ADR-006: in-memory storage mock. DO `state.storage.get/put` を `Map` で擬装。
  // 実 DO storage は `Promise<T|undefined>` を返すので async を真似る。
  const storageMap = new Map<string, unknown>();
  const alarmCalls: number[] = [];
  let pendingAlarm: number | null = null;
  const storage = {
    get: async <T>(key: string) => storageMap.get(key) as T | undefined,
    put: async (key: string, value: unknown) => {
      storageMap.set(key, value);
    },
    delete: async (key: string) => {
      storageMap.delete(key);
    },
    // issue #178 (a): alarm API mock。 `setAlarm(when)` を計測し、
    // `getAlarm()` で pending alarm を返す (DO 仕様準拠)。
    setAlarm: async (when: number) => {
      alarmCalls.push(when);
      pendingAlarm = when;
    },
    getAlarm: async () => pendingAlarm,
    deleteAlarm: async () => {
      pendingAlarm = null;
    },
  };
  const state = {
    getWebSockets: (_tag?: string) => current as unknown as WebSocket[],
    acceptWebSocket: (ws: WebSocket, tags?: string[]) => {
      acceptCalls.push({ ws, tags });
      current.push(ws as unknown as FakeWebSocket);
    },
    storage,
  } as unknown as DurableObjectState;
  return { state, current, acceptCalls, storageMap, alarmCalls };
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

  // Phase 2 multiplex (ref-files-mcp#4): handleConnect は existing WS を
  // 即時 close しなくなった (service が accept 時点では未知のため)。同 service
  // の close は webSocketMessage の hello frame 受信時に行う (下の hello テスト群)。
  it("retains existing WS across services and accepts the new one without closing", async () => {
    const old = makeFakeWs("old");
    const { state, acceptCalls } = createMockState([old]);
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__connect", {
      method: "GET",
      headers: { Upgrade: "websocket" },
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(101);
    expect(old.close).not.toHaveBeenCalled();
    expect(acceptCalls).toHaveLength(1);
  });

  it("#178: evicts stale (readyState !== OPEN) WS at accept time", async () => {
    // issue #178 (b): 前 session の WS が CLOSING / CLOSED 状態で残っていると
    // handleBridge の readyState filter で skip はされるが CF runtime の
    // getWebSockets() list には残り続け、 次の accept で並ぶ。 新 session が
    // 来た時点で stale を明示 close + cleanup する。
    const stale = makeFakeWs("stale", 3 /* CLOSED */);
    const live = makeFakeWs("live", 1 /* OPEN */);
    const { state, acceptCalls } = createMockState([stale, live]);
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__connect", {
      method: "GET",
      headers: { Upgrade: "websocket" },
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(101);
    // stale だけが close される (live は維持)
    expect(stale.close).toHaveBeenCalledWith(1000, "stale_on_connect");
    expect(live.close).not.toHaveBeenCalled();
    expect(acceptCalls).toHaveLength(1);
  });

  it("#178: evict tolerates close() throws on stale WS", async () => {
    const stale = makeFakeWs("stale", 3 /* CLOSED */);
    stale.close.mockImplementation(() => {
      throw new Error("already closed");
    });
    const { state } = createMockState([stale]);
    const do_ = new McpSession(state, {});
    // must not throw
    const res = await do_.fetch(
      new Request("https://do.invalid/__connect", {
        method: "GET",
        headers: { Upgrade: "websocket" },
      }),
    );
    expect(res.status).toBe(101);
    expect(stale.close).toHaveBeenCalled();
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
// ADR-004 (multiplex): /__push_event broadcast
// =============================================================================

describe("McpSession.fetch — /__push_event (ADR-004)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 405 when method is not POST", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__push_event", { method: "GET" });
    const res = await do_.fetch(req);
    expect(res.status).toBe(405);
  });

  it("returns 400 when body is invalid JSON", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__push_event", {
      method: "POST",
      body: "not json",
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(400);
  });

  it("broadcasts wrapped frame to all attached client WS and returns counts", async () => {
    const ws1 = makeFakeWs("ws1");
    const ws2 = makeFakeWs("ws2");
    const { state } = createMockState([ws1, ws2]);
    const do_ = new McpSession(state, {});

    const eventBody = {
      event_type: "issue_comment.created",
      delivery_id: "delivery-xyz",
      owner: "ippoan",
      repo: "cc-relay",
      issue_number: 42,
      received_at: "2026-05-15T11:00:00Z",
      payload: { action: "created" },
    };
    const req = new Request("https://do.invalid/__push_event", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(eventBody),
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      delivered?: number;
      dead?: number;
      total?: number;
    };
    expect(json.delivered).toBe(2);
    expect(json.dead).toBe(0);
    expect(json.total).toBe(2);

    expect(ws1.send).toHaveBeenCalledTimes(1);
    expect(ws2.send).toHaveBeenCalledTimes(1);
    const sent = JSON.parse((ws1.send.mock.calls[0]?.[0] as string) ?? "{}") as {
      kind?: string;
      v?: number;
      event_type?: string;
      owner?: string;
      issue_number?: number;
    };
    expect(sent.kind).toBe("event");
    expect(sent.v).toBe(1);
    expect(sent.event_type).toBe("issue_comment.created");
    expect(sent.owner).toBe("ippoan");
    expect(sent.issue_number).toBe(42);
  });

  it("counts dead WS but keeps broadcasting", async () => {
    const ws1 = makeFakeWs("ws1");
    const ws2 = makeFakeWs("ws2");
    ws1.send.mockImplementation(() => {
      throw new Error("dead");
    });
    const { state } = createMockState([ws1, ws2]);
    const do_ = new McpSession(state, {});

    const req = new Request("https://do.invalid/__push_event", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event_type: "issues.opened" }),
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(200);
    const json = (await res.json()) as { delivered?: number; dead?: number };
    expect(json.delivered).toBe(1);
    expect(json.dead).toBe(1);
    expect(ws2.send).toHaveBeenCalledTimes(1);
  });

  it("returns 200 with zero delivered when no WS attached", async () => {
    const { state } = createMockState([]);
    const do_ = new McpSession(state, {});

    const req = new Request("https://do.invalid/__push_event", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event_type: "issues.opened" }),
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      delivered?: number;
      dead?: number;
      total?: number;
    };
    expect(json.delivered).toBe(0);
    expect(json.total).toBe(0);
  });
});

// =============================================================================
// ADR-004 Phase D: /__connect_sse + binary notif frame fan-out
// =============================================================================

describe("McpSession.fetch — /__connect_sse (ADR-004 Phase D)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  afterEach(() => {
    restoreUUID();
  });

  /**
   * SSE body は ReadableStream。Node の Response polyfill (undici) で
   * stream の透過挙動が完全に再現されないため (`reader.read()` が writer
   * 経由の write を pick up しないケースが出る)、テストは「Response の
   * headers と push_event の counter」を中心に検証する。実 stream の中身
   * 検証は staging で `curl -N` で行う。
   */

  it("returns 405 when method is not GET", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__connect_sse", { method: "POST" });
    const res = await do_.fetch(req);
    expect(res.status).toBe(405);
  });

  it("returns 200 + SSE headers + freshly-generated Mcp-Session-Id when none provided", async () => {
    setStubUUID("00000000-0000-0000-0000-000000000abc");
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__connect_sse", { method: "GET" });
    const res = await do_.fetch(req);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/event-stream");
    expect(res.headers.get("Cache-Control")).toBe("no-cache, no-transform");
    expect(res.headers.get("Mcp-Session-Id")).toBe(
      "00000000-0000-0000-0000-000000000abc",
    );
    expect(res.body).not.toBeNull();
    // body の chunk 検証は polyfill の都合で flaky なので、ここでは
    // ReadableStream の存在だけ確認する。
    await res.body!.cancel();
  });

  it("reuses Mcp-Session-Id header when provided and valid", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__connect_sse", {
      method: "GET",
      headers: { "Mcp-Session-Id": "abc-123" },
    });
    const res = await do_.fetch(req);
    expect(res.headers.get("Mcp-Session-Id")).toBe("abc-123");
    await res.body!.cancel();
  });

  it("rejects malformed Mcp-Session-Id by generating a fresh one", async () => {
    setStubUUID("11111111-2222-3333-4444-555555555555");
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__connect_sse", {
      method: "GET",
      headers: { "Mcp-Session-Id": "bad value with spaces!" },
    });
    const res = await do_.fetch(req);
    expect(res.headers.get("Mcp-Session-Id")).toBe(
      "11111111-2222-3333-4444-555555555555",
    );
    await res.body!.cancel();
  });

  it("push_event reports sse_total when channel attached", async () => {
    setStubUUID("sse-id-1");
    const { state } = createMockState();
    const do_ = new McpSession(state, {});

    // open SSE — channel が registry に登録される
    const sseRes = await do_.fetch(
      new Request("https://do.invalid/__connect_sse", { method: "GET" }),
    );
    expect(sseRes.status).toBe(200);

    // push event
    const pushRes = await do_.fetch(
      new Request("https://do.invalid/__push_event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          event_type: "issue_comment.created",
          delivery_id: "d-1",
          owner: "ippoan",
          repo: "cc-relay",
          issue_number: 46,
          payload: { action: "created" },
        }),
      }),
    );
    expect(pushRes.status).toBe(200);
    const counts = (await pushRes.json()) as { sse_total?: number };
    expect(counts.sse_total).toBe(1);

    await sseRes.body!.cancel();
  });

  it("push_event returns sse_total=0 when no SSE channels attached", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const pushRes = await do_.fetch(
      new Request("https://do.invalid/__push_event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event_type: "issues.opened" }),
      }),
    );
    expect(pushRes.status).toBe(200);
    const counts = (await pushRes.json()) as { sse_total?: number };
    expect(counts.sse_total).toBe(0);
  });

  // 書込失敗時の cleanup path: body.cancel() 後に writeSse が write し、
  // 非同期 catch で channel が registry から消える。タイミングは
  // microtask 1〜2 段なので await Promise.resolve() 数回挟んで観測する。
  it("drops SSE channel when writer.write() rejects (body cancelled)", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});

    const sseRes = await do_.fetch(
      new Request("https://do.invalid/__connect_sse", { method: "GET" }),
    );
    // body をすぐ cancel して以後の write が reject する状態にする
    await sseRes.body!.cancel();

    // push_event → writeSse → writer.write() → reject → channel cleanup
    const pushRes = await do_.fetch(
      new Request("https://do.invalid/__push_event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event_type: "issues.opened" }),
      }),
    );
    expect(pushRes.status).toBe(200);
    // この push_event の時点では channel はまだ map にいる (catch は async)
    // 数 tick 待って catch が走ってから 2 回目 push_event で 0 を確認する。
    await new Promise((r) => setTimeout(r, 10));
    const pushRes2 = await do_.fetch(
      new Request("https://do.invalid/__push_event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event_type: "issues.opened" }),
      }),
    );
    const counts2 = (await pushRes2.json()) as { sse_total?: number };
    expect(counts2.sse_total).toBe(0);
  });

  // keepalive setInterval body: fake timers で 1 回 fire させて write が
  // 走ることを確認する (実 write の中身は polyfill 都合で見えなくても、
  // setInterval callback の coverage 取れれば OK)。
  it("keepalive setInterval fires raw SSE comment write", async () => {
    vi.useFakeTimers();
    try {
      const { state } = createMockState();
      const do_ = new McpSession(state, {});
      const sseRes = await do_.fetch(
        new Request("https://do.invalid/__connect_sse", { method: "GET" }),
      );
      // 26s 進めて 1 回 keepalive fire
      await vi.advanceTimersByTimeAsync(26_000);
      // session が依然 attached
      const pushRes = await do_.fetch(
        new Request("https://do.invalid/__push_event", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ event_type: "issues.opened" }),
        }),
      );
      const counts = (await pushRes.json()) as { sse_total?: number };
      expect(counts.sse_total).toBe(1);
      await sseRes.body!.cancel();
    } finally {
      vi.useRealTimers();
    }
  });
});

// =============================================================================
// issue #155: /__notify_tools_list_changed — tools/list_changed broadcast
// =============================================================================

describe("McpSession.fetch — /__notify_tools_list_changed (issue #155)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 405 when method is not POST", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const res = await do_.fetch(
      new Request("https://do.invalid/__notify_tools_list_changed", { method: "GET" }),
    );
    expect(res.status).toBe(405);
  });

  it("returns 200 + sse_total=0 when no SSE channels attached", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const res = await do_.fetch(
      new Request("https://do.invalid/__notify_tools_list_changed", { method: "POST" }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { sse_total: number };
    expect(body.sse_total).toBe(0);
  });

  it("returns 200 + sse_total>=1 when an SSE channel is attached", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});

    const sseRes = await do_.fetch(
      new Request("https://do.invalid/__connect_sse", { method: "GET" }),
    );
    expect(sseRes.status).toBe(200);

    const res = await do_.fetch(
      new Request("https://do.invalid/__notify_tools_list_changed", { method: "POST" }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { sse_total: number };
    expect(body.sse_total).toBe(1);

    await sseRes.body!.cancel();
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

  // ADR-003: WS 未接続時に 503 を返さず inline stub MCP server で応答する。
  // Anthropic Claude.ai connector が "Authorization failed" を誤表示する trap 回避。
  it("inline stub: returns 200 + initialize result when no WS and method=initialize", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-06-18" },
      }),
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      jsonrpc: string;
      id: number;
      result: {
        protocolVersion: string;
        capabilities: { tools: { listChanged: boolean } };
        serverInfo: { name: string; version: string };
      };
    };
    expect(body.jsonrpc).toBe("2.0");
    expect(body.id).toBe(1);
    expect(body.result.protocolVersion).toBe("2025-06-18");
    // issue #155: stub server も listChanged: true を advertise する。
    expect(body.result.capabilities.tools.listChanged).toBe(true);
    expect(body.result.serverInfo.name).toBe("cc-relay-stub");
  });

  it("inline stub: initialize without protocolVersion in params falls back to default", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { result: { protocolVersion: string } };
    expect(body.result.protocolVersion).toBe("2025-06-18");
  });

  it("inline stub: initialize with non-string protocolVersion falls back to default", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: 42 },
      }),
    });
    const res = await do_.fetch(req);
    const body = (await res.json()) as { result: { protocolVersion: string } };
    expect(body.result.protocolVersion).toBe("2025-06-18");
  });

  it("inline stub: tools/list returns cc_relay_ping + ADR-006 server-side tools", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      result: { tools: { name: string; description: string }[] };
    };
    // ADR-006: 5 tools total — ping + subscribe/unsubscribe/list/drain.
    const names = body.result.tools.map((t) => t.name).sort();
    expect(names).toEqual([
      "cc_relay_ping",
      "get_pending_events",
      "list_watched_issues",
      "subscribe_issue_activity",
      "unsubscribe_issue_activity",
    ]);
  });

  it("inline stub: tools/call cc_relay_ping returns pong", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "cc_relay_ping", arguments: {} },
      }),
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      result: { content: { type: string; text: string }[]; isError: boolean };
    };
    expect(body.result.isError).toBe(false);
    expect(body.result.content[0]!.text).toBe("pong");
  });

  it("inline stub: tools/call without params (params undefined) returns -32602 unknown tool", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/call" }),
    });
    const res = await do_.fetch(req);
    const body = (await res.json()) as {
      error: { code: number; message: string };
    };
    expect(body.error.code).toBe(-32602);
    expect(body.error.message).toMatch(/Unknown tool/);
  });

  it("inline stub: tools/call with unknown tool name returns -32602", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: { name: "nonexistent" },
      }),
    });
    const res = await do_.fetch(req);
    const body = (await res.json()) as { error: { code: number } };
    expect(body.error.code).toBe(-32602);
  });

  it("inline stub: ping returns empty result", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: 6, method: "ping" }),
    });
    const res = await do_.fetch(req);
    const body = (await res.json()) as { result: Record<string, unknown> };
    expect(body.result).toEqual({});
  });

  it("inline stub: prompts/list returns empty array", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "prompts/list" }),
    });
    const res = await do_.fetch(req);
    const body = (await res.json()) as { result: { prompts: unknown[] } };
    expect(body.result.prompts).toEqual([]);
  });

  it("inline stub: resources/list returns empty array", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: 8, method: "resources/list" }),
    });
    const res = await do_.fetch(req);
    const body = (await res.json()) as { result: { resources: unknown[] } };
    expect(body.result.resources).toEqual([]);
  });

  it("inline stub: notification (no id) returns 202 with no body", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(202);
    expect(await res.text()).toBe("");
  });

  it("inline stub: notification with id=null also returns 202", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: null, method: "notifications/initialized" }),
    });
    const res = await do_.fetch(req);
    expect(res.status).toBe(202);
  });

  it("inline stub: unknown method returns -32601", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "unknown/method" }),
    });
    const res = await do_.fetch(req);
    const body = (await res.json()) as { error: { code: number; message: string } };
    expect(body.error.code).toBe(-32601);
    expect(body.error.message).toMatch(/Method not found/);
  });

  it("inline stub: missing method (treated as '') returns -32601", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: 10 }),
    });
    const res = await do_.fetch(req);
    const body = (await res.json()) as { error: { code: number } };
    expect(body.error.code).toBe(-32601);
  });

  it("inline stub: malformed JSON body returns -32700 Parse error", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: "{not json",
    });
    const res = await do_.fetch(req);
    const body = (await res.json()) as {
      jsonrpc: string;
      id: null;
      error: { code: number };
    };
    expect(body.error.code).toBe(-32700);
    expect(body.id).toBeNull();
  });

  it("inline stub: array body (object branch true) → no id/method → 202 notification", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify([1, 2, 3]),
    });
    const res = await do_.fetch(req);
    // Array は typeof "object" かつ非 null なので Invalid Request 分岐を抜ける。
    // method / id とも欠けるので notification 扱い (202) になる。MCP 仕様上 batch は
    // 未対応であり、Anthropic からも来ないので本動作で十分。
    expect(res.status).toBe(202);
  });

  it("inline stub: JSON null body returns -32600 Invalid Request", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: "null",
    });
    const res = await do_.fetch(req);
    const body = (await res.json()) as { error: { code: number } };
    expect(body.error.code).toBe(-32600);
  });

  it("inline stub: JSON scalar body returns -32600 Invalid Request", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: "42",
    });
    const res = await do_.fetch(req);
    const body = (await res.json()) as { error: { code: number } };
    expect(body.error.code).toBe(-32600);
  });

  it("inline stub: non-string method (number) treated as '' → -32601", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: 11, method: 123 }),
    });
    const res = await do_.fetch(req);
    const body = (await res.json()) as { error: { code: number } };
    expect(body.error.code).toBe(-32601);
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

  it("#178: ws.send throws → close stale WS + stub fallback (initialize)", async () => {
    // issue #178 (c): relay_send_failed は stale WS 確定として扱う。
    // 当該 WS を close (1011, stale_relay_send_failed) → request 自体は
    // inline stub server の応答 (= 200 + cc-relay-stub serverInfo) に
    // fallback する。 Claude.ai connector は 502 ではなく 200 を受け取る。
    setStubUUID("uuid-send-fail");
    const ws = makeFakeWs("active");
    ws.send.mockImplementation(() => {
      throw new Error("ws closed mid-flight");
    });
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});

    const res = await do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: { protocolVersion: "2025-06-18" },
        }),
      }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      result: { serverInfo: { name: string } };
    };
    expect(body.result.serverInfo.name).toBe("cc-relay-stub");
    // stale WS が close 呼ばれている事を確認 (1011 = internal error)
    expect(ws.close).toHaveBeenCalledWith(1011, "stale_relay_send_failed");
  });

  it("#178: ws.send throws non-Error value → close + stub fallback", async () => {
    setStubUUID("uuid-send-fail-2");
    const ws = makeFakeWs("active");
    ws.send.mockImplementation(() => {
      // eslint-disable-next-line @typescript-eslint/no-throw-literal
      throw "string-error";
    });
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});

    const res = await do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 7,
          method: "tools/list",
        }),
      }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { result: { tools: unknown[] } };
    expect(Array.isArray(body.result.tools)).toBe(true);
    expect(ws.close).toHaveBeenCalledWith(1011, "stale_relay_send_failed");
  });

  it("#178: relay_timeout (10s) → close stale WS + stub fallback", async () => {
    // issue #178 (c): REQUEST_TIMEOUT_MS を 30s → 10s に短縮。 timeout 時は
    // 504 を返さず、stale WS を close + inline stub fallback に流す。
    vi.useFakeTimers({ shouldAdvanceTime: false });
    try {
      setStubUUID("uuid-timeout");
      const ws = makeFakeWs("active");
      const { state } = createMockState([ws]);
      const do_ = new McpSession(state, {});
      const sentP = whenSent(ws);

      const respPromise = do_.fetch(
        new Request("https://do.invalid/__bridge", {
          method: "POST",
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 2,
            method: "initialize",
            params: { protocolVersion: "2025-06-18" },
          }),
        }),
      );
      // pump microtasks until ws.send fires (req.arrayBuffer に乗っかってる)
      await sentP;
      // 10s 進めて timeout (新しい REQUEST_TIMEOUT_MS)
      await vi.advanceTimersByTimeAsync(10_000);
      const res = await respPromise;
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        result: { serverInfo: { name: string } };
      };
      expect(body.result.serverInfo.name).toBe("cc-relay-stub");
      expect(ws.close).toHaveBeenCalledWith(1011, "stale_relay_timeout");
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

  // ---------------------------------------------------------------------------
  // #123: stale (closed) WS race を弾く readyState filter
  // ---------------------------------------------------------------------------

  it("#123: stale WS (readyState=CLOSED) を skip して inline stub に流す", async () => {
    // binary が aggressive reconnect している隙間で active[0] が CLOSED の状態。
    // 旧コードは `ws.send()` で throw → 502 relay_send_failed を返していた。
    // 新コードは readyState !== OPEN の WS を filter し、open=0 なら inline stub。
    const stale = makeFakeWs("stale", 3 /* CLOSED */);
    const { state } = createMockState([stale]);
    const do_ = new McpSession(state, {});

    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-06-18" },
      }),
    });
    const res = await do_.fetch(req);
    // inline stub が応答するので 200 + cc-relay-stub serverInfo になる。
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      result: { serverInfo: { name: string } };
    };
    expect(body.result.serverInfo.name).toBe("cc-relay-stub");
    // stale WS には絶対に send しない (これが 502 を防ぐ核)
    expect(stale.send).not.toHaveBeenCalled();
  });

  it("#123: mix of OPEN + CLOSED — OPEN だけ採用して bridge する", async () => {
    setStubUUID("uuid-mix");
    const stale = makeFakeWs("stale", 3 /* CLOSED */);
    const fresh = makeFakeWs("fresh", 1 /* OPEN */);
    // 配列順: [stale, fresh] — 旧コードは active[0] = stale を掴んで失敗していた。
    const { state } = createMockState([stale, fresh]);
    const do_ = new McpSession(state, {});
    const sentP = whenSent(fresh);

    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", { method: "POST", body: "x" }),
    );
    const sent = JSON.parse(await sentP);
    expect(sent.id).toBe("uuid-mix");
    // stale には触らない
    expect(stale.send).not.toHaveBeenCalled();

    await do_.webSocketMessage(
      fresh as unknown as WebSocket,
      JSON.stringify({ kind: "resp", v: 1, id: "uuid-mix", status: 200 }),
    );
    const res = await respPromise;
    expect(res.status).toBe(200);
  });

  it("#123: multiple OPEN WS — 最新 (末尾) を採用", async () => {
    setStubUUID("uuid-latest");
    const older = makeFakeWs("older", 1 /* OPEN */);
    const newer = makeFakeWs("newer", 1 /* OPEN */);
    const { state } = createMockState([older, newer]);
    const do_ = new McpSession(state, {});
    const sentP = whenSent(newer);

    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", { method: "POST", body: "x" }),
    );
    await sentP;
    expect(newer.send).toHaveBeenCalled();
    expect(older.send).not.toHaveBeenCalled();

    await do_.webSocketMessage(
      newer as unknown as WebSocket,
      JSON.stringify({ kind: "resp", v: 1, id: "uuid-latest", status: 200 }),
    );
    await respPromise;
  });

  it("#123: readyState getter が throw する WS は除外する", async () => {
    // hibernated WS の getter が稀に throw する可能性 (CF 仕様で未保証) への defensive。
    const throwy = {
      close: vi.fn(),
      send: vi.fn(),
      __id: "throwy",
      get readyState(): number {
        throw new Error("hibernated handle");
      },
    } as unknown as FakeWebSocket;
    const { state } = createMockState([throwy]);
    const do_ = new McpSession(state, {});

    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {},
      }),
    });
    const res = await do_.fetch(req);
    // inline stub にフォールバック (throw した WS は OPEN とみなさない)
    expect(res.status).toBe(200);
    expect(throwy.send).not.toHaveBeenCalled();
  });
});

// =============================================================================
// ADR-004 Phase D: binary → DO の `kind:"notif"` frame を SSE に forward
// =============================================================================

describe("McpSession.webSocketMessage — kind:notif fan-out to SSE", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  afterEach(() => {
    restoreUUID();
  });

  it("accepts notif frame with object body without throwing (fan-out to SSE)", async () => {
    setStubUUID("sse-notif-1");
    const ws = makeFakeWs("active");
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});

    // open SSE channel first (so notif has somewhere to fan out)
    const sseRes = await do_.fetch(
      new Request("https://do.invalid/__connect_sse", { method: "GET" }),
    );
    expect(sseRes.status).toBe(200);

    const notifBody = {
      jsonrpc: "2.0",
      method: "notifications/message",
      params: {
        level: "info",
        logger: "cc-relay/issue-events",
        data: {
          event_type: "issue_comment.created",
          owner: "ippoan",
          repo: "cc-relay",
          issue_number: 46,
        },
      },
    };
    // should not throw — stream の中身検証は polyfill の制約で staging に任せる
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ kind: "notif", v: 1, body: notifBody }),
    );

    await sseRes.body!.cancel();
  });

  it("ignores notif frame with non-object body", async () => {
    const ws = makeFakeWs("active");
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});
    // should not throw — covers `typeof body !== "object"` branch
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ kind: "notif", v: 1, body: "not-an-object" }),
    );
    // covers missing body (undefined → typeof !== "object" still true)
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ kind: "notif", v: 1 }),
    );
    // covers `body === null` branch (typeof null === "object" so first
    // clause is false, second clause catches it)
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ kind: "notif", v: 1, body: null }),
    );
  });
});

// =============================================================================
// ADR-006: server-side subscription + event queue (POST /mcp only, no binary)
// =============================================================================

describe("McpSession inline stub — ADR-006 server-side tools", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  /** Send a JSON-RPC body through /__bridge (= inline stub path when no WS). */
  async function rpc(
    do_: McpSession,
    body: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const req = new Request("https://do.invalid/__bridge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const res = await do_.fetch(req);
    return (await res.json()) as Record<string, unknown>;
  }

  function getText(resp: Record<string, unknown>): string {
    const result = resp.result as { content: { text: string }[] };
    return result.content[0]!.text;
  }

  it("tools/list includes the 5 server-side stub tools", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const r = await rpc(do_, { jsonrpc: "2.0", id: 1, method: "tools/list" });
    const tools = (r.result as { tools: { name: string }[] }).tools;
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual([
      "cc_relay_ping",
      "get_pending_events",
      "list_watched_issues",
      "subscribe_issue_activity",
      "unsubscribe_issue_activity",
    ]);
  });

  it("subscribe → list → unsubscribe → list roundtrip persists in DO storage", async () => {
    const { state, storageMap } = createMockState();
    const do_ = new McpSession(state, {});

    // subscribe
    const sub = await rpc(do_, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "subscribe_issue_activity",
        arguments: { owner: "ippoan", repo: "cc-relay", issue_number: 46 },
      },
    });
    expect(getText(sub)).toBe("subscribed: ippoan/cc-relay#46");
    expect(storageMap.get("subs")).toEqual(["ippoan/cc-relay#46"]);

    // subscribe again — idempotent
    const sub2 = await rpc(do_, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "subscribe_issue_activity",
        arguments: { owner: "ippoan", repo: "cc-relay", issue_number: 46 },
      },
    });
    expect(getText(sub2)).toBe("already subscribed: ippoan/cc-relay#46");

    // list
    const list = await rpc(do_, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "list_watched_issues" },
    });
    expect(JSON.parse(getText(list))).toEqual(["ippoan/cc-relay#46"]);

    // unsubscribe
    const unsub = await rpc(do_, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "unsubscribe_issue_activity",
        arguments: { owner: "ippoan", repo: "cc-relay", issue_number: 46 },
      },
    });
    expect(getText(unsub)).toBe("unsubscribed: ippoan/cc-relay#46");
    expect(storageMap.get("subs")).toEqual([]);

    // unsubscribe again — was not subscribed
    const unsub2 = await rpc(do_, {
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: {
        name: "unsubscribe_issue_activity",
        arguments: { owner: "ippoan", repo: "cc-relay", issue_number: 46 },
      },
    });
    expect(getText(unsub2)).toBe("was not subscribed: ippoan/cc-relay#46");
  });

  it("subscribe rejects invalid args (empty owner, empty repo, non-int issue_number, zero)", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const cases: Array<Record<string, unknown>> = [
      { owner: "", repo: "x", issue_number: 1 },
      { owner: "x", repo: "", issue_number: 1 },
      { owner: "x", repo: "y", issue_number: 0 },
      { owner: "x", repo: "y", issue_number: 1.5 }, // non-integer
      { owner: "x", repo: "y" }, // missing issue_number
    ];
    for (const args of cases) {
      const r = await rpc(do_, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "subscribe_issue_activity", arguments: args },
      });
      expect((r.result as { isError: boolean }).isError).toBe(true);
    }
    // unsubscribe with invalid args also returns isError
    const u = await rpc(do_, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "unsubscribe_issue_activity",
        arguments: { owner: "", repo: "y", issue_number: 1 },
      },
    });
    expect((u.result as { isError: boolean }).isError).toBe(true);
  });

  it("push_event with missing owner/repo/issue_number does not queue", async () => {
    const { state, storageMap } = createMockState();
    const do_ = new McpSession(state, {});
    const partial = {
      event_type: "issue_comment.created",
      // owner/repo/issue_number 欠落
      payload: {},
    };
    const r = await do_.fetch(
      new Request("https://do.invalid/__push_event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(partial),
      }),
    );
    expect(r.status).toBe(200);
    const counts = (await r.json()) as { queued?: boolean };
    expect(counts.queued).toBe(false);
    // storage は events key を含まない (or empty array)
    const evs = storageMap.get("events");
    expect(Array.isArray(evs) ? evs.length : 0).toBe(0);
  });

  // parseIssueKey は ternary が args.owner/repo/issue_number の型分岐を
  // 持つ。`{ owner: 123 }` 等の non-string / non-number を渡して
  // ternary の false 側を踏む。
  it("subscribe handles non-string / non-number arg types (ternary false branch)", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const cases: Array<Record<string, unknown>> = [
      { owner: 123, repo: "y", issue_number: 1 }, // owner not string
      { owner: "x", repo: false, issue_number: 1 }, // repo not string
      { owner: "x", repo: "y", issue_number: "1" }, // issue_number not number
    ];
    for (const args of cases) {
      const r = await rpc(do_, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "subscribe_issue_activity", arguments: args },
      });
      expect((r.result as { isError: boolean }).isError).toBe(true);
    }
  });

  // queueEventIfSubscribed の `!owner || !repo || num === null` 短絡分岐 — 各 disjunct で
  // 独立に false が起きる経路をカバー。前テストは「全部欠落」(最初の項で短絡)
  // しか踏んでいないので、中間 / 最後の disjunct を別ケースで起こす。
  it("push_event with only `repo` missing or only `issue_number` missing skips queue", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    // owner OK, repo missing
    const r1 = await do_.fetch(
      new Request("https://do.invalid/__push_event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          event_type: "x",
          owner: "ippoan",
          issue_number: 46,
          payload: {},
        }),
      }),
    );
    expect(((await r1.json()) as { queued?: boolean }).queued).toBe(false);
    // owner OK, repo OK, issue_number missing
    const r2 = await do_.fetch(
      new Request("https://do.invalid/__push_event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          event_type: "x",
          owner: "ippoan",
          repo: "cc-relay",
          payload: {},
        }),
      }),
    );
    expect(((await r2.json()) as { queued?: boolean }).queued).toBe(false);
  });

  it("event queue drops oldest when overflowing MAX_QUEUED_EVENTS", async () => {
    const { state, storageMap } = createMockState();
    const do_ = new McpSession(state, {});
    // pre-seed storage with subs (= subscribe done) AND 500 events (= queue full).
    await state.storage.put("subs", ["ippoan/cc-relay#46"]);
    const seeded: Record<string, unknown>[] = [];
    for (let i = 0; i < 500; i++) {
      seeded.push({
        event_type: "issue_comment.created",
        delivery_id: `d-${i}`,
        owner: "ippoan",
        repo: "cc-relay",
        issue_number: 46,
        payload: {},
      });
    }
    await state.storage.put("events", seeded);
    // push one more — oldest (d-0) should drop.
    await do_.fetch(
      new Request("https://do.invalid/__push_event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          event_type: "issue_comment.created",
          delivery_id: "d-500",
          owner: "ippoan",
          repo: "cc-relay",
          issue_number: 46,
          payload: {},
        }),
      }),
    );
    const after = storageMap.get("events") as Record<string, unknown>[];
    expect(after.length).toBe(500);
    expect(after[0]!.delivery_id).toBe("d-1");
    expect(after[after.length - 1]!.delivery_id).toBe("d-500");
  });

  it("push_event queues event for subscribed issue + get_pending_events drains", async () => {
    const { state, storageMap } = createMockState();
    const do_ = new McpSession(state, {});

    // subscribe to #46 only
    await rpc(do_, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "subscribe_issue_activity",
        arguments: { owner: "ippoan", repo: "cc-relay", issue_number: 46 },
      },
    });

    // push 2 events: one matching #46, one not matching (#99)
    const eventA = {
      event_type: "issue_comment.created",
      delivery_id: "d-1",
      owner: "ippoan",
      repo: "cc-relay",
      issue_number: 46,
      payload: { action: "created", body: "hi" },
    };
    const eventB = {
      event_type: "issues.opened",
      delivery_id: "d-2",
      owner: "ippoan",
      repo: "cc-relay",
      issue_number: 99,
      payload: { action: "opened" },
    };

    const r1 = await do_.fetch(
      new Request("https://do.invalid/__push_event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(eventA),
      }),
    );
    const counts1 = (await r1.json()) as { queued?: boolean; queue_size?: number };
    expect(counts1.queued).toBe(true);
    expect(counts1.queue_size).toBe(1);

    const r2 = await do_.fetch(
      new Request("https://do.invalid/__push_event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(eventB),
      }),
    );
    const counts2 = (await r2.json()) as { queued?: boolean };
    expect(counts2.queued).toBe(false);

    // get_pending_events returns only the subscribed one
    const drain = await rpc(do_, {
      jsonrpc: "2.0",
      id: 10,
      method: "tools/call",
      params: { name: "get_pending_events" },
    });
    const arr = JSON.parse(getText(drain)) as Record<string, unknown>[];
    expect(arr.length).toBe(1);
    expect(arr[0]!.delivery_id).toBe("d-1");
    expect(arr[0]!.issue_number).toBe(46);

    // 2nd drain is empty (queue cleared)
    const drain2 = await rpc(do_, {
      jsonrpc: "2.0",
      id: 11,
      method: "tools/call",
      params: { name: "get_pending_events" },
    });
    expect(JSON.parse(getText(drain2))).toEqual([]);
    expect(storageMap.get("events")).toEqual([]);
  });

  it("initialize includes ADR-006 instructions", async () => {
    const { state } = createMockState();
    const do_ = new McpSession(state, {});
    const r = await rpc(do_, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18" },
    });
    const result = r.result as { instructions: string };
    expect(result.instructions).toContain("subscribe_issue_activity");
    expect(result.instructions).toContain("get_pending_events");
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

// =============================================================================
// Phase 2 multiplex (ref-files-mcp#4 option C):
//   per-service WebSocket attachment + JSON-RPC aggregator (initialize /
//   tools/list / tools/call / notification / fall-through).
//
// Multi-binary fake: extends FakeWebSocket with `serializeAttachment` /
// `deserializeAttachment` so `wsServiceOf` can read the service id back, which
// is the only way the DO distinguishes the WS otherwise.
// =============================================================================

interface FakeMultiplexWs extends FakeWebSocket {
  serializeAttachment: ReturnType<typeof vi.fn>;
  deserializeAttachment: ReturnType<typeof vi.fn>;
}

/** Build a fake WS pre-loaded with a service attachment (so `wsServiceOf`
 *  returns that service straight away — no hello frame needed). Passing
 *  `service = undefined` leaves the attachment null (= v1-compat fallback). */
function makeMultiplexWs(
  id: string,
  service: string | undefined,
  readyState: number = 1,
): FakeMultiplexWs {
  const base = makeFakeWs(id, readyState);
  let attachment: unknown =
    service !== undefined ? { service, binaryVersion: "0.1.0" } : null;
  return Object.assign(base, {
    serializeAttachment: vi.fn((data: unknown) => {
      attachment = data;
    }),
    deserializeAttachment: vi.fn(() => attachment),
  }) as FakeMultiplexWs;
}

/** Capture the next `ws.send(...)` payload and resolve with the parsed Frame.
 *  Used to grab the random UUID the broadcast generated so the test can echo
 *  back a matching `kind:"resp"`. */
function captureSentFrame(ws: FakeWebSocket): Promise<{
  id: string;
  method: string;
  body_b64: string;
}> {
  return new Promise((resolve) => {
    ws.send.mockImplementation((data: unknown) => {
      const f = JSON.parse(String(data)) as {
        id: string;
        method: string;
        body_b64: string;
      };
      resolve(f);
    });
  });
}

/** Helper: respond to a captured Frame::Req with a Frame::Resp JSON envelope. */
async function respondJson(
  do_: McpSession,
  ws: FakeWebSocket,
  reqId: string,
  status: number,
  rpcBody: Record<string, unknown>,
): Promise<void> {
  await do_.webSocketMessage(
    ws as unknown as WebSocket,
    JSON.stringify({
      kind: "resp",
      v: 1,
      id: reqId,
      status,
      headers: { "content-type": "application/json" },
      body_b64: b64encode(JSON.stringify(rpcBody)),
    }),
  );
}

describe("McpSession multiplex — webSocketMessage hello frame (Phase 2)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("records service + binaryVersion attachment on known-service hello", async () => {
    const ws = makeMultiplexWs("fresh", undefined); // attachment unset until hello
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});

    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        kind: "hello",
        v: 1,
        service: "ref-files-mcp-server-rs",
        binary_version: "0.2.0",
      }),
    );

    // issue #178: attachment は keepalive 関連 field (missedPings / lastPongAt /
    // keepaliveSupported) も含むので objectContaining で核となる service /
    // binaryVersion だけ assert する。
    expect(ws.serializeAttachment).toHaveBeenCalledWith(
      expect.objectContaining({
        service: "ref-files-mcp-server-rs",
        binaryVersion: "0.2.0",
        keepaliveSupported: false,
      }),
    );
  });

  it("falls back to v1-compat service when hello.service is unknown", async () => {
    const ws = makeMultiplexWs("fresh", undefined);
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});

    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        kind: "hello",
        v: 1,
        service: "definitely-not-allowlisted",
        binary_version: "0.0.0",
      }),
    );

    expect(ws.serializeAttachment).toHaveBeenCalledWith(
      expect.objectContaining({
        service: "github-mcp-server-rs", // DEFAULT_SERVICE_V1_COMPAT
        binaryVersion: "0.0.0",
      }),
    );
  });

  it("falls back to v1-compat when hello.service is non-string and treats missing binary_version as empty string", async () => {
    const ws = makeMultiplexWs("fresh", undefined);
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});

    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ kind: "hello", v: 1, service: 123 }),
    );

    expect(ws.serializeAttachment).toHaveBeenCalledWith(
      expect.objectContaining({
        service: "github-mcp-server-rs",
        binaryVersion: "",
      }),
    );
  });

  it("closes the previous same-service WS but retains different-service WS", async () => {
    const oldGithub = makeMultiplexWs("old-gh", "github-mcp-server-rs");
    const refFiles = makeMultiplexWs("ref-files", "ref-files-mcp-server-rs");
    const newGithub = makeMultiplexWs("new-gh", undefined);
    const { state } = createMockState([oldGithub, refFiles, newGithub]);
    const do_ = new McpSession(state, {});

    await do_.webSocketMessage(
      newGithub as unknown as WebSocket,
      JSON.stringify({
        kind: "hello",
        v: 1,
        service: "github-mcp-server-rs",
        binary_version: "0.3.0",
      }),
    );

    expect(oldGithub.close).toHaveBeenCalledWith(1000, "replaced");
    expect(refFiles.close).not.toHaveBeenCalled();
    // the newly-arriving WS must NOT close itself
    expect(newGithub.close).not.toHaveBeenCalled();
  });

  it("ignores close() throws on stale peer WS", async () => {
    const oldGithub = makeMultiplexWs("old-gh", "github-mcp-server-rs");
    oldGithub.close.mockImplementation(() => {
      throw new Error("already closed");
    });
    const newGithub = makeMultiplexWs("new-gh", undefined);
    const { state } = createMockState([oldGithub, newGithub]);
    const do_ = new McpSession(state, {});

    // must not throw
    await do_.webSocketMessage(
      newGithub as unknown as WebSocket,
      JSON.stringify({
        kind: "hello",
        v: 1,
        service: "github-mcp-server-rs",
        binary_version: "0.3.0",
      }),
    );
    expect(oldGithub.close).toHaveBeenCalled();
  });

  it("ignores serializeAttachment() throws and tolerates wsServiceOf throws on peer WS", async () => {
    // Both WS lack `serialize/deserializeAttachment`. ws's serializeAttachment
    // throws → outer catch swallows. Inside the same-service replacement loop
    // we call `wsServiceOf(otherPlain)` which also throws (no deserialize
    // method); the inner try/catch returns DEFAULT_SERVICE_V1_COMPAT (=
    // "github-mcp-server-rs"), matching the hello.service → close() fires.
    const otherPlain = makeFakeWs("plain-other");
    const ws = makeFakeWs("plain");
    const { state } = createMockState([otherPlain, ws]);
    const do_ = new McpSession(state, {});

    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        kind: "hello",
        v: 1,
        service: "github-mcp-server-rs",
        binary_version: "0.1.0",
      }),
    );
    expect(otherPlain.close).toHaveBeenCalledWith(1000, "replaced");
  });

  it("ignores unknown frame kind (req / arbitrary) without throwing", async () => {
    const ws = makeFakeWs("ws");
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});

    // covers the `if (kind !== "resp") return;` final fall-through after the
    // hello/notif/resp branches.
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ kind: "req", v: 1 }),
    );
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ kind: "totally-made-up", v: 1 }),
    );
  });
});

describe("McpSession multiplex — handleBridge aggregator (Phase 2)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  afterEach(() => {
    restoreUUID();
  });

  // Setup with 2 attached services. `wsByService.size > 1` so handleBridge
  // takes the `dispatchMultiService` branch.
  function setup() {
    const wsGh = makeMultiplexWs("gh", "github-mcp-server-rs");
    const wsRef = makeMultiplexWs("ref", "ref-files-mcp-server-rs");
    const { state } = createMockState([wsGh, wsRef]);
    const do_ = new McpSession(state, {});
    return { wsGh, wsRef, do_ };
  }

  it("aggregateInitialize: broadcasts to both services and merges serverInfo + protocolVersion", async () => {
    const { wsGh, wsRef, do_ } = setup();
    const capGh = captureSentFrame(wsGh);
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: { protocolVersion: "2025-06-18" },
        }),
      }),
    );
    const fGh = await capGh;
    const fRef = await capRef;
    await respondJson(do_, wsGh, fGh.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "github-mcp-server-rs", version: "1.0.0" },
      },
    });
    await respondJson(do_, wsRef, fRef.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "ref-files-mcp-server-rs", version: "0.1.0" },
      },
    });
    const res = await respPromise;
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      result: {
        protocolVersion: string;
        capabilities: { tools: { listChanged: boolean } };
        serverInfo: { name: string };
      };
    };
    expect(body.result.protocolVersion).toBe("2025-06-18");
    expect(body.result.serverInfo.name).toContain("mcp-relay-multiplex");
    expect(body.result.serverInfo.name).toContain("github-mcp-server-rs");
    expect(body.result.serverInfo.name).toContain("ref-files-mcp-server-rs");
  });

  it("aggregateInitialize: logs proto mismatch and falls back to the first proto", async () => {
    const { wsGh, wsRef, do_ } = setup();
    const capGh = captureSentFrame(wsGh);
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
      }),
    );
    const fGh = await capGh;
    const fRef = await capRef;
    await respondJson(do_, wsGh, fGh.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "gh", version: "1" },
      },
    });
    await respondJson(do_, wsRef, fRef.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-03-01",
        capabilities: { tools: {} },
        serverInfo: { name: "ref", version: "1" },
      },
    });
    const res = await respPromise;
    const body = (await res.json()) as {
      result: { protocolVersion: string };
    };
    expect(["2025-06-18", "2025-03-01"]).toContain(body.result.protocolVersion);
  });

  it("aggregateInitialize: returns -32000 when both binaries respond with garbage JSON", async () => {
    const { wsGh, wsRef, do_ } = setup();
    const capGh = captureSentFrame(wsGh);
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
      }),
    );
    const fGh = await capGh;
    const fRef = await capRef;
    // Reply with body_b64 that decodes to invalid JSON → broadcast returns ok:false.
    await do_.webSocketMessage(
      wsGh as unknown as WebSocket,
      JSON.stringify({
        kind: "resp",
        v: 1,
        id: fGh.id,
        status: 200,
        body_b64: b64encode("{not json"),
      }),
    );
    await do_.webSocketMessage(
      wsRef as unknown as WebSocket,
      JSON.stringify({
        kind: "resp",
        v: 1,
        id: fRef.id,
        status: 200,
        body_b64: b64encode("also not json"),
      }),
    );
    const res = await respPromise;
    const body = (await res.json()) as {
      error: { code: number; message: string };
    };
    expect(body.error.code).toBe(-32000);
    expect(body.error.message).toMatch(/all attached binaries failed initialize/);
  });

  it("aggregateInitialize: empty-body resp (no body_b64) still parses to {} and merges", async () => {
    const { wsGh, wsRef, do_ } = setup();
    const capGh = captureSentFrame(wsGh);
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
      }),
    );
    const fGh = await capGh;
    const fRef = await capRef;
    // No body_b64 → bodyBytes = empty → JSON.parse('') throws → ok:false branch.
    await do_.webSocketMessage(
      wsGh as unknown as WebSocket,
      JSON.stringify({ kind: "resp", v: 1, id: fGh.id, status: 200 }),
    );
    await respondJson(do_, wsRef, fRef.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "ref", version: "1" },
      },
    });
    const res = await respPromise;
    const body = (await res.json()) as {
      result?: { serverInfo?: { name?: string } };
    };
    // ref-files survived → serverInfo name lists just that service
    expect(body.result?.serverInfo?.name).toContain("ref-files-mcp-server-rs");
  });

  it("aggregateToolsList: merges disjoint tools across services and populates routing cache", async () => {
    const { wsGh, wsRef, do_ } = setup();
    const capGh = captureSentFrame(wsGh);
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
      }),
    );
    const fGh = await capGh;
    const fRef = await capRef;
    await respondJson(do_, wsGh, fGh.id, 200, {
      jsonrpc: "2.0",
      id: 2,
      result: {
        tools: [
          { name: "get_pull_request", description: "gh-tool" },
          { name: "list_issues", description: "gh-tool" },
          "not-an-object", // skipped (typeof !== object)
          null, // skipped
          { description: "no-name" }, // skipped (name missing)
          { name: 42 }, // skipped (name not string)
        ],
      },
    });
    await respondJson(do_, wsRef, fRef.id, 200, {
      jsonrpc: "2.0",
      id: 2,
      result: {
        tools: [{ name: "ref_search_files", description: "ref-tool" }],
      },
    });
    // Also exercise the "result.tools not an array" skip branch via a 3rd
    // service... we only have 2 services so we cover that branch indirectly
    // (the okResults loop continues).
    const res = await respPromise;
    const body = (await res.json()) as {
      result: { tools: { name: string }[] };
    };
    const names = body.result.tools.map((t) => t.name).sort();
    expect(names).toEqual(["get_pull_request", "list_issues", "ref_search_files"]);
  });

  it("aggregateToolsList: skips service whose result.tools is not an array", async () => {
    const { wsGh, wsRef, do_ } = setup();
    const capGh = captureSentFrame(wsGh);
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
      }),
    );
    const fGh = await capGh;
    const fRef = await capRef;
    await respondJson(do_, wsGh, fGh.id, 200, {
      jsonrpc: "2.0",
      id: 2,
      result: { tools: "not-an-array" }, // covers Array.isArray false branch
    });
    await respondJson(do_, wsRef, fRef.id, 200, {
      jsonrpc: "2.0",
      id: 2,
      result: { tools: [{ name: "ref_search_files" }] },
    });
    const res = await respPromise;
    const body = (await res.json()) as {
      result: { tools: { name: string }[] };
    };
    expect(body.result.tools.map((t) => t.name)).toEqual(["ref_search_files"]);
  });

  it("aggregateToolsList: fails fast with -32000 on tool name conflict between services", async () => {
    const { wsGh, wsRef, do_ } = setup();
    const capGh = captureSentFrame(wsGh);
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
      }),
    );
    const fGh = await capGh;
    const fRef = await capRef;
    await respondJson(do_, wsGh, fGh.id, 200, {
      jsonrpc: "2.0",
      id: 2,
      result: { tools: [{ name: "ping" }] },
    });
    await respondJson(do_, wsRef, fRef.id, 200, {
      jsonrpc: "2.0",
      id: 2,
      result: { tools: [{ name: "ping" }] },
    });
    const res = await respPromise;
    const body = (await res.json()) as {
      error: { code: number; message: string };
    };
    expect(body.error.code).toBe(-32000);
    expect(body.error.message).toMatch(/tool name conflict between services/);
    expect(body.error.message).toMatch(/'ping'/);
  });

  it("routeToolsCall: returns -32602 when tools/list was never called (cache miss)", async () => {
    const { do_ } = setup();
    const res = await do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 3,
          method: "tools/call",
          params: { name: "get_pull_request" },
        }),
      }),
    );
    const body = (await res.json()) as { error: { code: number; message: string } };
    expect(body.error.code).toBe(-32602);
    expect(body.error.message).toMatch(/unknown tool/);
  });

  it("routeToolsCall: -32602 when params.name is missing / empty", async () => {
    const { do_ } = setup();
    const res = await do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 3,
          method: "tools/call",
          params: {},
        }),
      }),
    );
    const body = (await res.json()) as { error: { code: number; message: string } };
    expect(body.error.code).toBe(-32602);
    expect(body.error.message).toMatch(/missing params.name/);
  });

  it("routeToolsCall: forwards to the correct service after tools/list cache populate", async () => {
    const { wsGh, wsRef, do_ } = setup();
    // populate cache via tools/list
    const cap1Gh = captureSentFrame(wsGh);
    const cap1Ref = captureSentFrame(wsRef);
    const listP = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      }),
    );
    const fGh1 = await cap1Gh;
    const fRef1 = await cap1Ref;
    await respondJson(do_, wsGh, fGh1.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: { tools: [{ name: "get_pull_request" }] },
    });
    await respondJson(do_, wsRef, fRef1.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: { tools: [{ name: "ref_search_files" }] },
    });
    await listP;
    wsGh.send.mockReset();
    wsRef.send.mockReset();

    // now tools/call for ref_search_files → should only go to wsRef.
    const capRef = captureSentFrame(wsRef);
    const callP = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 9,
          method: "tools/call",
          params: { name: "ref_search_files", arguments: { q: "x" } },
        }),
      }),
    );
    const fRef = await capRef;
    expect(wsGh.send).not.toHaveBeenCalled();
    await respondJson(do_, wsRef, fRef.id, 200, {
      jsonrpc: "2.0",
      id: 9,
      result: { content: [{ type: "text", text: "found" }], isError: false },
    });
    const res = await callP;
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      result: { content: { text: string }[] };
    };
    expect(body.result.content[0]!.text).toBe("found");
  });

  it("routeToolsCall: returns -32000 when the cached service is no longer in the attached set", async () => {
    // KNOWN_SERVICES is only {github, ref-files}, so the natural way to drop a
    // service (close its WS) also drops `wsByService.size` to 1, which would
    // bypass the multiplex branch entirely. To still exercise this defensive
    // path, pre-seed `toolToService` with a service id that is NOT in the
    // current `wsByService` (= the WS attached after cache populate switched
    // service identity, the realistic production scenario when KNOWN_SERVICES
    // gains a third entry).
    const { wsGh, wsRef, do_ } = setup();
    (do_ as unknown as { toolToService: Map<string, string> }).toolToService.set(
      "ghost_tool",
      "service-not-currently-attached",
    );
    const res = await do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 9,
          method: "tools/call",
          params: { name: "ghost_tool" },
        }),
      }),
    );
    expect(wsGh.send).not.toHaveBeenCalled();
    expect(wsRef.send).not.toHaveBeenCalled();
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      error: { code: number; message: string };
    };
    expect(body.error.code).toBe(-32000);
    expect(body.error.message).toMatch(/is not currently attached/);
    // cache entry was deleted as a side effect
    expect(
      (do_ as unknown as { toolToService: Map<string, string> }).toolToService.has(
        "ghost_tool",
      ),
    ).toBe(false);
  });

  it("routeToolsCall: surfaces forwardToWs ws.send failure as 502 relay_send_failed", async () => {
    const { wsGh, wsRef, do_ } = setup();
    // populate cache
    const cap1Gh = captureSentFrame(wsGh);
    const cap1Ref = captureSentFrame(wsRef);
    const listP = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      }),
    );
    const fGh1 = await cap1Gh;
    const fRef1 = await cap1Ref;
    await respondJson(do_, wsGh, fGh1.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: { tools: [{ name: "get_pull_request" }] },
    });
    await respondJson(do_, wsRef, fRef1.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: { tools: [{ name: "ref_search_files" }] },
    });
    await listP;
    wsGh.send.mockReset();
    wsRef.send.mockReset();
    // make wsRef.send blow up on the tools/call forward
    wsRef.send.mockImplementation(() => {
      throw new Error("relay dropped");
    });

    const res = await do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 9,
          method: "tools/call",
          params: { name: "ref_search_files" },
        }),
      }),
    );
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: string; message?: string };
    expect(body.error).toBe("relay_send_failed");
    expect(body.message).toContain("relay dropped");
  });

  it("routeToolsCall: relay_timeout returns 504 with no message field", async () => {
    const { wsGh, wsRef, do_ } = setup();
    // populate cache via tools/list with real timers
    const cap1Gh = captureSentFrame(wsGh);
    const cap1Ref = captureSentFrame(wsRef);
    const listP = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      }),
    );
    const fGh1 = await cap1Gh;
    const fRef1 = await cap1Ref;
    await respondJson(do_, wsGh, fGh1.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: { tools: [{ name: "gh_only" }] },
    });
    await respondJson(do_, wsRef, fRef1.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: { tools: [{ name: "ref_only" }] },
    });
    await listP;
    wsGh.send.mockReset();
    wsRef.send.mockReset();

    // now tools/call ref_only and let it time out
    vi.useFakeTimers({ shouldAdvanceTime: false });
    try {
      const capRef = captureSentFrame(wsRef);
      const callP = do_.fetch(
        new Request("https://do.invalid/__bridge", {
          method: "POST",
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 9,
            method: "tools/call",
            params: { name: "ref_only" },
          }),
        }),
      );
      await capRef;
      await vi.advanceTimersByTimeAsync(30_000);
      const res = await callP;
      expect(res.status).toBe(504);
      const body = (await res.json()) as { error: string; message?: string };
      expect(body.error).toBe("relay_timeout");
      // covers the `fwd.message !== undefined` false branch in routeToolsCall
      expect(body.message).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });

  it("dispatchMultiService: notification (id absent) broadcasts to all services and returns 202", async () => {
    const { wsGh, wsRef, do_ } = setup();
    const res = await do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/initialized",
        }),
      }),
    );
    expect(res.status).toBe(202);
    expect(wsGh.send).toHaveBeenCalledTimes(1);
    expect(wsRef.send).toHaveBeenCalledTimes(1);
  });

  it("dispatchMultiService: notification ignores per-service send failures", async () => {
    const { wsGh, wsRef, do_ } = setup();
    wsGh.send.mockImplementation(() => {
      throw new Error("dead");
    });
    const res = await do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/initialized",
        }),
      }),
    );
    expect(res.status).toBe(202);
    expect(wsRef.send).toHaveBeenCalledTimes(1);
  });

  it("dispatchMultiService: unknown method falls through to single-forward on last open WS", async () => {
    const { wsGh, wsRef, do_ } = setup();
    const capRef = captureSentFrame(wsRef); // last open in [wsGh, wsRef]
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 99, method: "prompts/list" }),
      }),
    );
    const fRef = await capRef;
    expect(wsGh.send).not.toHaveBeenCalled();
    await respondJson(do_, wsRef, fRef.id, 200, {
      jsonrpc: "2.0",
      id: 99,
      result: { prompts: [] },
    });
    const res = await respPromise;
    expect(res.status).toBe(200);
  });

  it("dispatchMultiService: non-JSON body falls through to single-forward", async () => {
    const { wsGh, wsRef, do_ } = setup();
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", { method: "POST", body: "not json" }),
    );
    const fRef = await capRef;
    expect(wsGh.send).not.toHaveBeenCalled();
    await respondJson(do_, wsRef, fRef.id, 200, { ok: true });
    await respPromise;
  });

  it("dispatchMultiService: JSON scalar body falls through to single-forward", async () => {
    const { wsGh, wsRef, do_ } = setup();
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", { method: "POST", body: "42" }),
    );
    const fRef = await capRef;
    expect(wsGh.send).not.toHaveBeenCalled();
    await respondJson(do_, wsRef, fRef.id, 200, { ok: true });
    await respPromise;
  });

  it("aggregateInitialize: empty protos set falls back to default protocolVersion", async () => {
    const { wsGh, wsRef, do_ } = setup();
    const capGh = captureSentFrame(wsGh);
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
      }),
    );
    const fGh = await capGh;
    const fRef = await capRef;
    // both ok responses, but NEITHER carries a string protocolVersion
    await respondJson(do_, wsGh, fGh.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: 99, // non-string → filtered out
        capabilities: {},
        serverInfo: { name: "gh", version: "1" },
      },
    });
    await respondJson(do_, wsRef, fRef.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: {
        // protocolVersion absent → undefined → filtered out
        capabilities: {},
        serverInfo: { name: "ref", version: "1" },
      },
    });
    const res = await respPromise;
    const body = (await res.json()) as {
      result: { protocolVersion: string };
    };
    expect(body.result.protocolVersion).toBe("2025-06-18");
  });

  it("aggregateToolsList: skips broken (non-JSON) service responses without breaking the merge", async () => {
    const { wsGh, wsRef, do_ } = setup();
    const capGh = captureSentFrame(wsGh);
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
      }),
    );
    const fGh = await capGh;
    const fRef = await capRef;
    // wsGh returns body that isn't JSON → broadcast returns ok:false → skipped
    await do_.webSocketMessage(
      wsGh as unknown as WebSocket,
      JSON.stringify({
        kind: "resp",
        v: 1,
        id: fGh.id,
        status: 200,
        body_b64: b64encode("not json"),
      }),
    );
    await respondJson(do_, wsRef, fRef.id, 200, {
      jsonrpc: "2.0",
      id: 2,
      result: { tools: [{ name: "ref_search_files" }] },
    });
    const res = await respPromise;
    const body = (await res.json()) as { result: { tools: { name: string }[] } };
    expect(body.result.tools.map((t) => t.name)).toEqual(["ref_search_files"]);
  });

  it("aggregateToolsList: duplicate name within one service is re-merged (prev === r.service branch)", async () => {
    const { wsGh, wsRef, do_ } = setup();
    const capGh = captureSentFrame(wsGh);
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
      }),
    );
    const fGh = await capGh;
    const fRef = await capRef;
    await respondJson(do_, wsGh, fGh.id, 200, {
      jsonrpc: "2.0",
      id: 2,
      result: {
        tools: [
          { name: "dup", description: "first" },
          { name: "dup", description: "second" }, // same service, same name
        ],
      },
    });
    await respondJson(do_, wsRef, fRef.id, 200, {
      jsonrpc: "2.0",
      id: 2,
      result: { tools: [{ name: "ref_only" }] },
    });
    const res = await respPromise;
    const body = (await res.json()) as { result: { tools: { name: string }[] } };
    // no conflict error — the duplicate within the same service is allowed.
    expect(body.result.tools.map((t) => t.name).sort()).toEqual([
      "dup",
      "dup",
      "ref_only",
    ]);
  });

  it("wsServiceOf: attachment with non-allowlisted service falls back to v1-compat", async () => {
    // wsA's deserializeAttachment claims a service id we never put in
    // KNOWN_SERVICES. wsServiceOf must return DEFAULT_SERVICE_V1_COMPAT (=
    // "github-mcp-server-rs"), so paired with a ref-files WS we still see
    // 2 distinct services and enter the multiplex branch.
    const wsA = makeMultiplexWs("a", undefined);
    wsA.deserializeAttachment.mockReturnValue({
      service: "rogue-service",
      binaryVersion: "x",
    });
    const wsRef = makeMultiplexWs("ref", "ref-files-mcp-server-rs");
    const { state } = createMockState([wsA, wsRef]);
    const do_ = new McpSession(state, {});
    const capA = captureSentFrame(wsA);
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
      }),
    );
    const fA = await capA;
    const fRef = await capRef;
    await respondJson(do_, wsA, fA.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        serverInfo: { name: "A", version: "1" },
      },
    });
    await respondJson(do_, wsRef, fRef.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        serverInfo: { name: "ref", version: "1" },
      },
    });
    const res = await respPromise;
    const body = (await res.json()) as {
      result: { serverInfo: { name: string } };
    };
    expect(body.result.serverInfo.name).toContain("github-mcp-server-rs");
    expect(body.result.serverInfo.name).toContain("ref-files-mcp-server-rs");
  });

  it("wsServiceOf: attachment with non-string service field falls back to v1-compat", async () => {
    const wsA = makeMultiplexWs("a", undefined);
    wsA.deserializeAttachment.mockReturnValue({ service: 42 }); // non-string
    const wsRef = makeMultiplexWs("ref", "ref-files-mcp-server-rs");
    const { state } = createMockState([wsA, wsRef]);
    const do_ = new McpSession(state, {});
    const capA = captureSentFrame(wsA);
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
      }),
    );
    const fA = await capA;
    const fRef = await capRef;
    await respondJson(do_, wsA, fA.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        serverInfo: { name: "A", version: "1" },
      },
    });
    await respondJson(do_, wsRef, fRef.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        serverInfo: { name: "ref", version: "1" },
      },
    });
    const res = await respPromise;
    expect(res.status).toBe(200);
  });

  it("dispatchMultiService: non-string `method` field is coerced to '' → falls through to single forward", async () => {
    // covers the `typeof msg.method === "string" ? msg.method : ""` false branch
    const { wsGh, wsRef, do_ } = setup();
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: 42 }),
      }),
    );
    const fRef = await capRef;
    expect(wsGh.send).not.toHaveBeenCalled();
    await respondJson(do_, wsRef, fRef.id, 200, { ok: true });
    await respPromise;
  });

  it("routeToolsCall: missing `params` field (msg.params undefined) returns -32602 missing params.name", async () => {
    // covers the `(msg.params ?? {})` nullish-coalesce activation
    const { do_ } = setup();
    const res = await do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call" }),
      }),
    );
    const body = (await res.json()) as { error: { code: number; message: string } };
    expect(body.error.code).toBe(-32602);
    expect(body.error.message).toMatch(/missing params.name/);
  });

  it("broadcast: drops services whose ws.send throws (forwardToWs returns ok:false)", async () => {
    // covers `if (!fwd.ok) return { ok: false, ... };` inside broadcast IIFE
    const { wsGh, wsRef, do_ } = setup();
    wsGh.send.mockImplementation(() => {
      throw new Error("dead-on-write");
    });
    const capRef = captureSentFrame(wsRef);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
      }),
    );
    const fRef = await capRef;
    await respondJson(do_, wsRef, fRef.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        serverInfo: { name: "ref", version: "1" },
      },
    });
    const res = await respPromise;
    const body = (await res.json()) as {
      result: { serverInfo: { name: string } };
    };
    // wsGh was filtered via the `!fwd.ok` branch; only ref-files survived
    expect(body.result.serverInfo.name).toContain("ref-files-mcp-server-rs");
    expect(body.result.serverInfo.name).not.toContain("github-mcp-server-rs");
  });

  it("broadcast: handles non-Error throws from JSON.parse (String(e) ternary branch)", async () => {
    // JSON.parse only ever throws SyntaxError in practice, but the source
    // ternary `e instanceof Error ? e.message : String(e)` covers a non-Error
    // throw for safety. Force that path by stubbing JSON.parse to throw a
    // string literal when it sees a specific marker text we hand-craft as the
    // service's response body.
    const realParse = JSON.parse.bind(JSON);
    const spy = vi.spyOn(JSON, "parse").mockImplementation((text: string) => {
      if (text === "trigger_non_error_throw") {
        // intentional non-Error throw
        // eslint-disable-next-line @typescript-eslint/no-throw-literal
        throw "non-error-marker";
      }
      return realParse(text);
    });
    try {
      const { wsGh, wsRef, do_ } = setup();
      const capGh = captureSentFrame(wsGh);
      const capRef = captureSentFrame(wsRef);
      const respPromise = do_.fetch(
        new Request("https://do.invalid/__bridge", {
          method: "POST",
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
        }),
      );
      const fGh = await capGh;
      const fRef = await capRef;
      // wsGh: body decodes to the marker → JSON.parse throws non-Error
      await do_.webSocketMessage(
        wsGh as unknown as WebSocket,
        JSON.stringify({
          kind: "resp",
          v: 1,
          id: fGh.id,
          status: 200,
          body_b64: b64encode("trigger_non_error_throw"),
        }),
      );
      // wsRef: legitimate response so the aggregator still returns success
      await respondJson(do_, wsRef, fRef.id, 200, {
        jsonrpc: "2.0",
        id: 1,
        result: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          serverInfo: { name: "ref", version: "1" },
        },
      });
      const res = await respPromise;
      expect(res.status).toBe(200);
    } finally {
      spy.mockRestore();
    }
  });

  it("pickOpenWsByService: same-service duplicates collapse to last (latest wins)", async () => {
    // both with the same service. wsByService.size === 1 so the multiplex
    // branch is *skipped*, exercising the `wsByService.size > 1` false leg.
    const wsA = makeMultiplexWs("a", "github-mcp-server-rs");
    const wsB = makeMultiplexWs("b", "github-mcp-server-rs");
    const { state } = createMockState([wsA, wsB]);
    const do_ = new McpSession(state, {});
    const capB = captureSentFrame(wsB);
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
      }),
    );
    const fB = await capB;
    expect(wsA.send).not.toHaveBeenCalled();
    await respondJson(do_, wsB, fB.id, 200, {
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "gh", version: "1" },
      },
    });
    const res = await respPromise;
    expect(res.status).toBe(200);
  });
});

// ===========================================================================
// issue #178 (a): keepalive ping/pong + alarm() による stale 検出
// ===========================================================================

describe("McpSession keepalive — alarm()-based ping/pong (issue #178)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("handleConnect schedules an alarm (keepalive bootstrap)", async () => {
    const { state, alarmCalls } = createMockState();
    const do_ = new McpSession(state, {});
    const res = await do_.fetch(
      new Request("https://do.invalid/__connect", {
        method: "GET",
        headers: { Upgrade: "websocket" },
      }),
    );
    expect(res.status).toBe(101);
    // scheduleKeepalive() は Promise chain。 microtask flush 後に setAlarm が
    // 呼ばれる。
    await new Promise((r) => setImmediate(r));
    expect(alarmCalls.length).toBeGreaterThanOrEqual(1);
    expect(alarmCalls[0]).toBeGreaterThan(Date.now() - 1_000);
  });

  it("hello with keepalive_supported=true marks attachment for ping", async () => {
    const ws = makeMultiplexWs("ws", undefined);
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});

    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        kind: "hello",
        v: 1,
        service: "github-mcp-server-rs",
        binary_version: "0.3.0",
        keepalive_supported: true,
      }),
    );
    // attachment に keepaliveSupported=true / missedPings=0 / lastPongAt 設定
    const att = (
      ws.serializeAttachment.mock.calls[0] as unknown as [Record<string, unknown>]
    )[0];
    expect(att.keepaliveSupported).toBe(true);
    expect(att.missedPings).toBe(0);
    expect(typeof att.lastPongAt).toBe("number");
  });

  it("alarm() sends a ping frame to keepalive-supported WS", async () => {
    const ws = makeMultiplexWs("ws", "github-mcp-server-rs");
    // hello を済ませて keepaliveSupported=true の attachment にしておく
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        kind: "hello",
        v: 1,
        service: "github-mcp-server-rs",
        binary_version: "0.3.0",
        keepalive_supported: true,
      }),
    );
    ws.send.mockClear();

    await do_.alarm();

    // ping frame が 1 件送られている
    expect(ws.send).toHaveBeenCalledTimes(1);
    const frame = JSON.parse(String(ws.send.mock.calls[0]?.[0])) as {
      kind: string;
      v: number;
      id: string;
    };
    expect(frame.kind).toBe("ping");
    expect(frame.v).toBe(1);
    expect(typeof frame.id).toBe("string");
  });

  it("alarm() does NOT ping keepalive-unsupported WS (backward compat)", async () => {
    // 旧 binary は hello に keepalive_supported を載せない → ping を出さない
    const ws = makeMultiplexWs("ws", "github-mcp-server-rs");
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        kind: "hello",
        v: 1,
        service: "github-mcp-server-rs",
        binary_version: "0.2.0",
        // keepalive_supported は省略 (= false)
      }),
    );
    ws.send.mockClear();
    await do_.alarm();
    expect(ws.send).not.toHaveBeenCalled();
  });

  it("pong frame resets missedPings + updates lastPongAt", async () => {
    const ws = makeMultiplexWs("ws", undefined);
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        kind: "hello",
        v: 1,
        service: "github-mcp-server-rs",
        binary_version: "0.3.0",
        keepalive_supported: true,
      }),
    );
    // 直接 attachment を弄って missedPings=1 にする (alarm 1 回挟んだ状態の simulate)。
    // `vi.fn(...)` Mock を直接 call すると TS 推論が new vs call の union で揺れて
    // TS2348 になるので、 cast 経由で invoke する。
    (ws.serializeAttachment as unknown as (d: unknown) => void)({
      service: "github-mcp-server-rs",
      binaryVersion: "0.3.0",
      keepaliveSupported: true,
      missedPings: 1,
      lastPongAt: Date.now() - 60_000,
    });

    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ kind: "pong", v: 1, id: "some-uuid" }),
    );
    // 最後の serializeAttachment 呼び出しを取得
    const calls = ws.serializeAttachment.mock.calls;
    const lastAtt = calls[calls.length - 1]?.[0] as Record<string, unknown>;
    expect(lastAtt.missedPings).toBe(0);
    expect(typeof lastAtt.lastPongAt).toBe("number");
    expect(lastAtt.lastPongAt as number).toBeGreaterThan(Date.now() - 1_000);
  });

  it("alarm() closes WS after MAX_MISSED_PINGS consecutive pong misses", async () => {
    // KEEPALIVE_MAX_MISSED_PINGS=2、 KEEPALIVE_PONG_TIMEOUT_MS=8000
    const ws = makeMultiplexWs("ws", undefined);
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        kind: "hello",
        v: 1,
        service: "github-mcp-server-rs",
        binary_version: "0.3.0",
        keepalive_supported: true,
      }),
    );
    // lastPongAt をかなり過去にして missedPings=1 にする
    (ws.serializeAttachment as unknown as (d: unknown) => void)({
      service: "github-mcp-server-rs",
      binaryVersion: "0.3.0",
      keepaliveSupported: true,
      missedPings: 1,
      lastPongAt: Date.now() - 60_000,
    });
    // alarm 1 回で missedPings 1→2 (=MAX) → close
    await do_.alarm();
    expect(ws.close).toHaveBeenCalledWith(1011, "keepalive_timeout");
  });

  it("alarm() is a no-op when no WS attached (and does not self-schedule)", async () => {
    const { state, alarmCalls } = createMockState();
    const do_ = new McpSession(state, {});
    await do_.alarm();
    // alarm 内では setAlarm を呼ばない (handleConnect の初回 schedule のみ)
    expect(alarmCalls).toHaveLength(0);
  });

  it("alarm() tolerates ws.send throw + close throw without escaping", async () => {
    const ws = makeMultiplexWs("ws", undefined);
    ws.send.mockImplementation(() => {
      throw new Error("send broken");
    });
    ws.close.mockImplementation(() => {
      throw new Error("close broken");
    });
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        kind: "hello",
        v: 1,
        service: "github-mcp-server-rs",
        binary_version: "0.3.0",
        keepalive_supported: true,
      }),
    );
    // alarm は throw せず通る
    await expect(do_.alarm()).resolves.toBeUndefined();
  });

  it("pong frame on a WS without attachment helpers is tolerated", async () => {
    const ws = makeFakeWs("plain"); // no serialize/deserializeAttachment
    const { state } = createMockState([ws]);
    const do_ = new McpSession(state, {});
    // 一度 hello を入れて (plain WS では attachment 書き込めず silent skip)
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({
        kind: "hello",
        v: 1,
        service: "github-mcp-server-rs",
        binary_version: "0.3.0",
        keepalive_supported: true,
      }),
    );
    // pong も書き込みできずだが throw しない
    await expect(
      do_.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ kind: "pong", v: 1, id: "uuid-pong" }),
      ),
    ).resolves.toBeUndefined();
  });
});

// ===========================================================================
// issue #178 E2E shape: CCoW fresh-container scenario simulation
// ===========================================================================

describe("McpSession recovery — CCoW reuse-DO scenario (issue #178)", () => {
  it("stale prev-session WS detected mid-flight → next call hits stub immediately", async () => {
    // 前 session で attach した binary が container reclaim で死亡:
    //  - WS 自体は CF runtime には残るが、 send は throw (or 応答が来ない)
    //  - readyState は OPEN のまま (CF が CLOSE を観測していない)
    // 新 session で同 DO instance に当たって最初の MCP call を投げると:
    //  1. handleBridge は open[] に WS を見つけて forward
    //  2. send が throw or 応答 timeout → fwd.error が relay_send_failed / relay_timeout
    //  3. DO が WS close + inline stub fallback で 200 を返す
    //  4. 次の call からは open=[] になり inline stub が直接応答 (= 正常運用)
    const staleWs = makeFakeWs("stale-from-prev-session", 1 /* OPEN */);
    staleWs.send.mockImplementation(() => {
      // simulate "binary が死んでて send pipe が broken"
      throw new Error("write to closed pipe");
    });
    const { state, current } = createMockState([staleWs]);
    const do_ = new McpSession(state, {});

    // 1st call: stale WS に当たって stub fallback
    const res1 = await do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: { protocolVersion: "2025-06-18" },
        }),
      }),
    );
    expect(res1.status).toBe(200);
    const body1 = (await res1.json()) as {
      result: { serverInfo: { name: string } };
    };
    expect(body1.result.serverInfo.name).toBe("cc-relay-stub");
    expect(staleWs.close).toHaveBeenCalledWith(1011, "stale_relay_send_failed");

    // close 済 WS の readyState を CLOSED に更新する (CF runtime 挙動 simulate)
    staleWs.readyState = 3;

    // 2nd call: stale 既に close → handleBridge は open=[] で即 stub に流す
    const res2 = await do_.fetch(
      new Request("https://do.invalid/__bridge", {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/list",
        }),
      }),
    );
    expect(res2.status).toBe(200);
    const body2 = (await res2.json()) as { result: { tools: unknown[] } };
    expect(Array.isArray(body2.result.tools)).toBe(true);
    // 2nd call では stale.send 自体が呼ばれていない (= bridge filter で skip)
    expect(staleWs.send).toHaveBeenCalledTimes(1);

    // 3rd call: 新 session の binary が attach する (新 WS が並ぶ)
    const freshWs = makeFakeWs("fresh", 1 /* OPEN */);
    current.push(freshWs);
    const sentP = whenSent(freshWs);
    setStubUUID("uuid-fresh");
    const respPromise = do_.fetch(
      new Request("https://do.invalid/__bridge", { method: "POST", body: "x" }),
    );
    await sentP;
    await do_.webSocketMessage(
      freshWs as unknown as WebSocket,
      JSON.stringify({
        kind: "resp",
        v: 1,
        id: "uuid-fresh",
        status: 200,
        body_b64: b64encode(JSON.stringify({ ok: true })),
        headers: { "content-type": "application/json" },
      }),
    );
    const res3 = await respPromise;
    expect(res3.status).toBe(200);
    // fresh WS には forward した、 stale WS には新たに forward していない
    expect(freshWs.send).toHaveBeenCalled();
    expect(staleWs.send).toHaveBeenCalledTimes(1);
  });
});
