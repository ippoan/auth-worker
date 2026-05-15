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
    expect(body.result.capabilities.tools.listChanged).toBe(false);
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

  it("inline stub: tools/list returns the cc_relay_ping placeholder tool", async () => {
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
    expect(body.result.tools).toHaveLength(1);
    expect(body.result.tools[0]!.name).toBe("cc_relay_ping");
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
    // should not throw
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ kind: "notif", v: 1, body: "not-an-object" }),
    );
    await do_.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ kind: "notif", v: 1 }), // missing body
    );
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
