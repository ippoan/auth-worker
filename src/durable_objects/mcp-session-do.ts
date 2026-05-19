/**
 * MCP relay 用 Durable Object (issue #117 Phase 6 + #119 Phase 7 + ADR-003).
 *
 * 二モード動作:
 *
 * 1. **Relay mode** (Phase 6/7): `github-mcp-server-rs` の `install-mcp.sh` が
 *    `wss://mcp.ippoan.org/u/<github_login>/connect` へ outbound WebSocket を張る。
 *    `POST https://mcp.ippoan.org/u/<github_login>/mcp` は同 DO へルーティングされ、
 *    接続中の binary に WS frame として転送される。
 *
 * 2. **Stub MCP server mode** (ADR-003 fallback): WS 未接続時に 503 を返さず、
 *    最低限の MCP JSON-RPC (initialize / tools/list / tools/call / 各 notification)
 *    を inline で応答する。Anthropic Claude.ai / Claude Code Web connector が
 *    OAuth 完走後に 200 を受け取れるようになり「Authorization with the MCP server
 *    failed」trap を回避する。実 binary が後から接続したら自動で relay mode に切り替わる。
 *
 * 設計判断 (issue #117 plan + #119 plan):
 *
 * - Hibernatable WebSocket (`state.acceptWebSocket()`) を使う。
 * - 同一 user の同時接続は 1 本のみ。新 upgrade で旧 WS は `close(1000, "replaced")`。
 * - DO 内 path は worker public path と衝突しないように `/__connect` /
 *   `/__bridge` の double-underscore prefix を使う。
 * - Frame schema は ippoan/github-mcp-server-rs#27 の binary 側で確定済み:
 *
 *   ```json
 *   {"kind":"req","v":1,"id":"<uuid>","method":"POST","path":"/","headers":{...},"body_b64":"..."}
 *   {"kind":"resp","v":1,"id":"<uuid>","status":200,"headers":{...},"body_b64":"..."}
 *   {"kind":"hello","v":1,"binary_version":"0.1.0","proto":1}
 *   ```
 *
 * - Phase 7 では `path` を `"/"` に固定 (binary 側で StreamableHttpService を
 *   直接呼ぶため)。SSE / `Mcp-Session-Id` 透過は frame v2 で対応 (out of scope)。
 * - in-flight request は `pending: Map<id, resolver>` で待ち合わせ。30s timeout。
 * - WS close / error 時に pending を全て 502 で reject。
 */

/** DO が必要とする env subset。Phase 7 では参照する binding は無い。 */
export interface McpSessionEnv {
  /** Phase 7 では未参照 (Phase 6 plan の名残)。observability 拡張時に参照候補。 */
  MCP_JWT_SECRET?: string;
}

/** `state.acceptWebSocket()` に渡す tag — `getWebSockets("client")` で参照する。
 *
 *  Phase 2 multiplex (issue ref-files-mcp#4 option C): 同 DO に複数 binary が
 *  attach できる。tag は `"client"` のまま (Hibernatable WS API は accept 時
 *  にしか tag を渡せないが、binary を区別する `service` は Hello frame で
 *  後送されるため accept 時点では未知)。service による振り分けは
 *  `ws.serializeAttachment({service})` を Hello 受信時に書き、
 *  `wsServiceOf(ws)` で読む。v1 sender (service 未送出) は
 *  `DEFAULT_SERVICE_V1_COMPAT` ("github-mcp-server-rs") に fallback する。 */
const WS_TAG = "client";

/** Phase 2: v1 sender (Hello frame に `service` を載せない旧 binary) の
 *  service id 既定値。binary 側 `mcp-relay::relay::frame::default_service_v1_compat`
 *  と一致させる。 */
const DEFAULT_SERVICE_V1_COMPAT = "github-mcp-server-rs";

/** 既知 service の allowlist。Hello frame で未知 service を送ってきた binary は
 *  attachment 書き込みを silent reject (= v1 fallback `"github-mcp-server-rs"` で
 *  扱う)。新 service を足すときはここに追加し、`MCP_JWT_AUDIENCE_ALLOWLIST`
 *  env と揃える。 */
const KNOWN_SERVICES: ReadonlySet<string> = new Set([
  "github-mcp-server-rs",
  "ref-files-mcp-server-rs",
]);

/**
 * `WebSocket.readyState` の OPEN 値 (= 1)。`WebSocket.OPEN` static は Workers
 * runtime の型定義に無いケースがあるので literal で持つ。spec:
 * https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/readyState
 */
const WS_READY_STATE_OPEN = 1;

/** Frame schema version (binary 側 #27 と一致させる)。 */
const FRAME_VERSION = 1;

/** 1 request あたりの WS frame round-trip timeout (ms)。 */
const REQUEST_TIMEOUT_MS = 30_000;

/** SSE channel の memory 上での registry entry。Workers DO は hibernation
 *  すると memory が消えるので、SSE は live container 限定 (Claude.ai は
 *  再接続するので OK)。 */
interface SseChannel {
  /** stable client identifier (= `Mcp-Session-Id`)。 */
  sessionId: string;
  /** SSE body の writer (TextEncoder で utf-8 byte 化したものを write)。 */
  writer: WritableStreamDefaultWriter<Uint8Array>;
  /** event-id 採番カウンタ (SSE replay 用、Phase D では再接続時 reset)。 */
  nextEventId: number;
  /** keepalive setInterval ハンドル。close 時に clear するため保持。 */
  keepalive: ReturnType<typeof setInterval>;
}

/** SSE keepalive 間隔 (ms)。Cloudflare の idle timeout (100s) より十分短い。 */
const SSE_KEEPALIVE_INTERVAL_MS = 25_000;

/** binary 側から送られてくる Frame::Resp の構造 (parse 後)。 */
interface RespFrame {
  kind: "resp";
  v: number;
  id: string;
  status: number;
  headers?: Record<string, string>;
  body_b64?: string;
}

interface PendingRequest {
  resolve: (frame: RespFrame) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * auth-worker 側 → binary 側 → Claude Code Web へ送らない頭 (hop-by-hop / 危険系)。
 *
 * `host` は **意図的に保持** (issue #121): binary 側 rmcp `StreamableHttpService` が
 * Host header を必須としている (欠落で 400 "missing Host header" を返す)。Cloudflare
 * 経由なので Host は `mcp(-staging).ippoan.org` のいずれか。binary 側で Host validation
 * が必要なら `with_allowed_hosts` で個別許可する。
 *
 * `authorization` は drop: Bearer JWT は auth-worker 側 gate で消費済み、binary 側に
 * 漏らさない。
 */
const HEADERS_BLOCKLIST = new Set([
  "authorization",
  "content-length",
  "x-forwarded-for",
  "x-forwarded-proto",
  "x-real-ip",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
]);

export class McpSession implements DurableObject {
  state: DurableObjectState;
  env: McpSessionEnv;
  /** in-flight HTTP bridge request の解決待ち。WS 切断時に全て reject される。 */
  private pending: Map<string, PendingRequest> = new Map();
  /** ADR-004 Phase D: 現在 attach 中の SSE channel (= `GET /mcp` で開いた
   *  Streamable HTTP stream)。`/__push_event` と binary 側からの
   *  `kind:"notif"` frame を fan-out する。Hibernation 跨ぎでは保持されない。 */
  private sseChannels: Map<string, SseChannel> = new Map();
  /** Phase 2 multiplex: tool 名 → service id の cache。`tools/list` 集約時に
   *  populate し、`tools/call` 時に lookup する。in-memory only (hibernation で
   *  消える)。lost 時は次回 `tools/list` で再構築されるため retry されれば回復する。
   *  tool 名衝突は fail-fast (`tools/list` aggregator が error を返す)。 */
  private toolToService: Map<string, string> = new Map();

  constructor(state: DurableObjectState, env: McpSessionEnv) {
    this.state = state;
    this.env = env;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/__connect") {
      return this.handleConnect(req);
    }

    if (url.pathname === "/__bridge") {
      return this.handleBridge(req);
    }

    if (url.pathname === "/__push_event") {
      return this.handlePushEvent(req);
    }

    if (url.pathname === "/__connect_sse") {
      return this.handleConnectSse(req);
    }

    return new Response("Not Found", { status: 404 });
  }

  /**
   * ADR-004: GitHub webhook 経由で届いた event を、現在 attach 中の全
   * `client` WebSocket に broadcast する。subscription registry は持たず、
   * binary 側 (`agent-mcp/src/relay.rs`) が `~/.cc-relay/watched-issues.txt`
   * で filter する。
   *
   * Body は raw event JSON (`{v, event_type, delivery_id, owner, repo,
   * issue_number, payload, received_at}`)。WS frame として
   * `{kind:"event", v:1, ...}` の形に wrap してから送る (既存 `req`/`resp`
   * と同じ envelope 系で binary 側 dispatcher の追加が match arm 1 個で済む)。
   */
  private async handlePushEvent(req: Request): Promise<Response> {
    if (req.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }
    let eventBody: Record<string, unknown>;
    try {
      eventBody = (await req.json()) as Record<string, unknown>;
    } catch (e) {
      return jsonResponse(400, { error: "invalid_json", detail: String(e) });
    }
    const wsList = this.state.getWebSockets(WS_TAG);
    const framePayload = JSON.stringify({
      kind: "event",
      v: FRAME_VERSION,
      ...eventBody,
    });
    let delivered = 0;
    let dead = 0;
    for (const ws of wsList) {
      try {
        ws.send(framePayload);
        delivered += 1;
      } catch {
        // 死んでる WS は CF runtime が cleanup するまでスキップ
        dead += 1;
      }
    }
    // ADR-004 Phase D: SSE channel が attached なら、binary 側を介さず DO 自身が
    // `notifications/message` を直接 push する経路も用意する。binary 未起動でも
    // Claude session が event を受け取れる fallback。binary が起動中なら
    // 同じ event が両方の経路で届くが、Claude 側で de-dup (delivery_id) する想定。
    //
    // write は fire-and-forget。`await writer.write()` は TransformStream の
    // backpressure (default HWM=1) で hang し得るので、push_event の応答性を
    // 守るため Promise は捨てる (失敗は .catch で channel cleanup する)。
    const sseFrame = sseFormatNotification("notifications/message", {
      level: "info",
      logger: "cc-relay/issue-events",
      data: eventBody,
    });
    const sseTotal = this.sseChannels.size;
    for (const ch of this.sseChannels.values()) {
      this.writeSse(ch, sseFrame);
    }

    // ADR-006: server-side event queue にも push (subscription filter 経由)。
    // CCoW の `get_pending_events` polling 経路。binary も SSE channel も
    // 無くて queue も空、で初めて event が dead-letter になる。
    const queueResult = await this.queueEventIfSubscribed(eventBody);

    return jsonResponse(200, {
      delivered,
      dead,
      total: wsList.length,
      sse_total: sseTotal,
      queued: queueResult.queued,
      queue_size: queueResult.queue_size,
    });
  }

  /**
   * ADR-004 Phase D: GET /mcp → SSE stream upgrade。bridge handler から
   * 認証済みの request だけが forward されてくる。SSE channel を 1 本開いて
   * `Mcp-Session-Id` header を返し、後段の push_event / notif 経路から
   * `notifications/message` を write する。Claude.ai は EventSource として
   * 読む (`event: message\ndata: <json>\n\n`)。
   *
   * Hibernation 跨ぎは保証しない (memory channel)。クライアントは EventSource
   * の自動 reconnect で復帰する想定。
   */
  private handleConnectSse(req: Request): Response {
    if (req.method !== "GET") {
      return new Response("Method Not Allowed", { status: 405 });
    }
    // 既存 session-id があれば再利用、無ければ採番。
    const incoming = req.headers.get("Mcp-Session-Id");
    const sessionId =
      incoming && /^[a-z0-9-]{1,128}$/i.test(incoming)
        ? incoming
        : crypto.randomUUID();

    const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
    const writer = writable.getWriter();
    // channel object を先に作って `keepalive` を後付け。`as SseChannel` cast
    // で TS の non-optional 制約をパスし、`setInterval` callback が channel
    // 自身を参照キャプチャできるようにする。`if (ch) ...` のような defensive
    // branch は不要 — channel の cleanup は writeSseRaw の `.catch` 内で
    // `clearInterval(channel.keepalive)` を呼ぶ事で timer 自体が停止する。
    const channel = {
      sessionId,
      writer,
      nextEventId: 0,
    } as SseChannel;
    channel.keepalive = setInterval(
      () => this.writeSseRaw(channel, ": keepalive\n\n"),
      SSE_KEEPALIVE_INTERVAL_MS,
    );
    this.sseChannels.set(sessionId, channel);

    // 初回 hello (MCP 慣習に依存しない、診断 + 接続確認用)。
    this.writeSse(channel, sseFormatNotification("notifications/message", {
      level: "info",
      logger: "cc-relay/sse",
      data: { msg: "sse_connected", session_id: sessionId },
    }));

    return new Response(readable, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache, no-transform",
        "Mcp-Session-Id": sessionId,
        "X-Accel-Buffering": "no",
      },
    });
  }

  /**
   * SSE writer に 1 frame 書く。fire-and-forget。`await writer.write()` は
   * TransformStream の backpressure (default HWM=1) で hang し得るので、
   * push_event 応答性のため Promise は捨てる。MCP `notifications/message`
   * 用に `id: N\nevent: message\ndata: <body>\n\n` で wrap する。
   */
  private writeSse(channel: SseChannel, body: string): void {
    channel.nextEventId += 1;
    this.writeSseRaw(
      channel,
      `id: ${channel.nextEventId}\nevent: message\ndata: ${body}\n\n`,
    );
  }

  /** SSE wire への raw write — `: comment\n\n` 形式の keepalive と
   *  `event: message` frame の両方で共通。書込失敗時は channel を
   *  registry から削除して keepalive を止める。 */
  private writeSseRaw(channel: SseChannel, wire: string): void {
    const enc = new TextEncoder();
    channel.writer.write(enc.encode(wire)).catch(() => {
      clearInterval(channel.keepalive);
      this.sseChannels.delete(channel.sessionId);
    });
  }

  private handleConnect(req: Request): Response {
    if (req.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected websocket", { status: 426 });
    }

    // Phase 2 multiplex (option C): 既存 WS は service が同一 (= 旧 connection
    // の置換) のものだけ close する。異 service の binary は維持して
    // 1 DO 内に N services を共存させる。service が未確定 (Hello 前) の
    // attachment は v1 compat default 扱いになる。
    // 注: accept 時点では新 connection の service も未知 (Hello は accept 後)。
    // 既存 v1 全部を一旦保持し、Hello 到着時に同 service の旧 WS を close する
    // (`reconcileServiceAttachment`)。
    const existing = this.state.getWebSockets(WS_TAG);
    console.log(
      `[mcp-relay] handleConnect: existing_ws=${existing.length} (multiplex retains across services until hello)`,
    );

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.state.acceptWebSocket(server, [WS_TAG]);
    return new Response(null, { status: 101, webSocket: client });
  }

  /** Phase 2 multiplex helper: open な WS list から service id 別に最新の
   *  1 本を pick して返す。同 service 内では「末尾 = 最新」採用 (handleConnect
   *  と同じ慣習)。 */
  private pickOpenWsByService(open: WebSocket[]): Map<string, WebSocket> {
    const byService = new Map<string, WebSocket>();
    for (const w of open) {
      byService.set(wsServiceOf(w), w);
    }
    return byService;
  }

  /** Phase 2 multiplex: 1 本の WS に Frame::Req を投げて Resp を await する。
   *  既存 handleBridge を 1-binary でも N-binary でも使えるように切り出し。 */
  private async forwardToWs(
    ws: WebSocket,
    method: string,
    reqHeaders: Record<string, string>,
    bodyBuf: ArrayBuffer,
  ): Promise<{ ok: true; resp: RespFrame } | { ok: false; status: number; error: string }> {
    const id = crypto.randomUUID();
    const reqFrame = {
      kind: "req",
      v: FRAME_VERSION,
      id,
      method,
      path: "/",
      headers: reqHeaders,
      body_b64: arrayBufferToBase64(bodyBuf),
    };
    try {
      ws.send(JSON.stringify(reqFrame));
    } catch (e) {
      return {
        ok: false,
        status: 502,
        error: `relay_send_failed: ${e instanceof Error ? e.message : String(e)}`,
      };
    }
    const respPromise = new Promise<RespFrame>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("relay_timeout"));
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
    });
    try {
      const resp = await respPromise;
      return { ok: true, resp };
    } catch (e) {
      const msg = (e as Error).message;
      return { ok: false, status: msg === "relay_timeout" ? 504 : 502, error: msg };
    }
  }

  private async handleBridge(req: Request): Promise<Response> {
    const active = this.state.getWebSockets(WS_TAG);
    // [#123] stale WS race fix: binary が aggressive reconnect している隙間で
    // auth-worker が古い (close 済) WS を `active[0]` として掴むと
    // `ws.send()` が `Can't call WebSocket send() after close()` を投げ
    // 502 relay_send_failed になる。readyState === OPEN (1) のものだけ採用する。
    //
    // hibernated WS は readyState OPEN を返す (CF 仕様) ので filter には残る。
    // fake mock (test) は readyState 未定義 → undefined !== 1 で除外される。
    const safeReadyState = (w: unknown): number | "throw" => {
      try {
        return (w as WebSocket).readyState;
      } catch {
        return "throw";
      }
    };
    const open = active.filter((w) => safeReadyState(w) === WS_READY_STATE_OPEN);
    console.log(
      `[mcp-relay] handleBridge: ws_count=${active.length} open=${open.length} states=[${active
        .map((w) => String(safeReadyState(w)))
        .join(",")}] pending=${this.pending.size}`,
    );
    if (open.length === 0) {
      // ADR-003: WS relay 未接続 (or 全 stale) 時は inline stub MCP server で応答する。
      // 503 を返すと Anthropic 側 connector が "Authorization failed" を誤表示する
      // ため、最低限の MCP JSON-RPC (initialize / tools/list / tools/call) は本 DO で
      // 自前応答し、connector を「接続済み・stub tool 1 個」状態にする。
      //
      // ADR-006: stub server に subscribe_issue_activity / unsubscribe_issue_activity
      // / list_watched_issues / get_pending_events 4 tool を追加。state は DO
      // storage に持つ (`subs` set + `events` FIFO)。CCoW のように binary を
      // 動かせない環境でも、`POST /mcp` 経由でこの 4 tool だけで「subscribe →
      // webhook 受信 → polling drain」が完結する。
      return this.handleInlineMcp(req);
    }

    // body / headers を取り出して Frame::Req に詰める。aggregator 経路と
    // 単発 forward 経路で共有する。
    const bodyBuf = await req.arrayBuffer();
    const headers: Record<string, string> = {};
    req.headers.forEach((v, k) => {
      const lk = k.toLowerCase();
      if (HEADERS_BLOCKLIST.has(lk)) return;
      if (lk.startsWith("cf-")) return;
      headers[lk] = v;
    });

    // Phase 2 multiplex: service 別の WS 集合を取る。1 service なら従来通り
    // 単発 forward で完了 (既存 v1 binary の挙動を保つ)。2+ service ある時
    // だけ JSON-RPC body を見て initialize / tools/list / tools/call を分岐。
    const wsByService = this.pickOpenWsByService(open);
    if (wsByService.size > 1) {
      const aggResp = await this.dispatchMultiService(wsByService, headers, bodyBuf);
      if (aggResp) return aggResp;
      // dispatchMultiService が null を返した → 集約対象外 method。
      // 既定の最終 WS forward に fall through する (= 1 service 経路と同じ)。
    }

    // 単発 forward: 最新 WS (= open 配列末尾) を 1 本だけ使う。
    const ws = open[open.length - 1] as WebSocket;
    const fwd = await this.forwardToWs(ws, req.method, headers, bodyBuf);
    if (!fwd.ok) {
      return jsonResponse(fwd.status, { error: fwd.error });
    }
    return buildResponseFromRespFrame(fwd.resp);
  }

  /** Phase 2 multiplex: JSON-RPC body を見て初期化系メソッドを全 service に
   *  分配・集約する。集約しない method (notification / 未知 / 単発) は
   *  `null` を返して caller の単発 forward に委ねる。 */
  private async dispatchMultiService(
    wsByService: Map<string, WebSocket>,
    headers: Record<string, string>,
    bodyBuf: ArrayBuffer,
  ): Promise<Response | null> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(bodyBuf));
    } catch {
      return null; // JSON-RPC でない POST は単発 forward
    }
    if (typeof parsed !== "object" || parsed === null) return null;
    const msg = parsed as JsonRpcMessage;
    const method = typeof msg.method === "string" ? msg.method : "";
    const reqId = msg.id;

    // notification (id 無し) は broadcast して 202。
    if (reqId === undefined || reqId === null) {
      for (const ws of wsByService.values()) {
        try {
          ws.send(JSON.stringify({
            kind: "req",
            v: FRAME_VERSION,
            id: crypto.randomUUID(),
            method: "POST",
            path: "/",
            headers,
            body_b64: arrayBufferToBase64(bodyBuf),
          }));
        } catch { /* ignore individual failure */ }
      }
      return new Response(null, { status: 202 });
    }

    switch (method) {
      case "initialize":
        return this.aggregateInitialize(wsByService, headers, bodyBuf, reqId);
      case "tools/list":
        return this.aggregateToolsList(wsByService, headers, bodyBuf, reqId);
      case "tools/call":
        return this.routeToolsCall(wsByService, headers, bodyBuf, msg, reqId);
      default:
        // prompts/list, resources/list, ping 等 — どの binary も同じく返すので
        // 単発 forward (caller) に任せる。
        return null;
    }
  }

  /** `initialize`: 全 service に投げ、capabilities.tools を union、serverInfo は
   *  service 列を join した composite で返す。 */
  private async aggregateInitialize(
    wsByService: Map<string, WebSocket>,
    headers: Record<string, string>,
    bodyBuf: ArrayBuffer,
    reqId: unknown,
  ): Promise<Response> {
    const results = await this.broadcast(wsByService, headers, bodyBuf);
    const okResults = results.filter((r) => r.ok) as Array<{
      ok: true;
      service: string;
      body: Record<string, unknown>;
    }>;
    if (okResults.length === 0) {
      return jsonRpcResponse(reqId, {
        error: { code: -32000, message: "all attached binaries failed initialize" },
      });
    }
    // protocolVersion: 全 binary 同一前提 (Phase 2 spec の制約)。差があれば
    // 先頭の値を採用 + warning log。
    const protos = new Set(
      okResults
        .map((r) => (r.body.result as { protocolVersion?: unknown } | undefined)?.protocolVersion)
        .filter((p) => typeof p === "string"),
    );
    if (protos.size > 1) {
      console.log(`[mcp-relay] aggregate initialize: proto mismatch ${[...protos].join(",")}`);
    }
    const proto = [...protos][0] ?? "2025-06-18";
    return jsonRpcResponse(reqId, {
      result: {
        protocolVersion: proto,
        capabilities: { tools: { listChanged: false } },
        serverInfo: {
          name: `mcp-relay-multiplex(${okResults.map((r) => r.service).join(",")})`,
          version: "0.1.0",
        },
      },
    });
  }

  /** `tools/list`: 全 service の tools を merge。tool 名衝突は fail-fast
   *  (Phase 2 spec: prefix 化は別 issue)。merge 成功時は `toolToService` cache
   *  を populate して後続の `tools/call` の routing に使う。 */
  private async aggregateToolsList(
    wsByService: Map<string, WebSocket>,
    headers: Record<string, string>,
    bodyBuf: ArrayBuffer,
    reqId: unknown,
  ): Promise<Response> {
    const results = await this.broadcast(wsByService, headers, bodyBuf);
    const merged: Array<Record<string, unknown>> = [];
    const seen = new Map<string, string>(); // tool name → service
    for (const r of results) {
      if (!r.ok) continue;
      const tools = (r.body.result as { tools?: unknown } | undefined)?.tools;
      if (!Array.isArray(tools)) continue;
      for (const t of tools) {
        if (typeof t !== "object" || t === null) continue;
        const name = (t as { name?: unknown }).name;
        if (typeof name !== "string") continue;
        const prev = seen.get(name);
        if (prev && prev !== r.service) {
          return jsonRpcResponse(reqId, {
            error: {
              code: -32000,
              message: `tool name conflict between services: '${name}' (${prev} vs ${r.service})`,
            },
          });
        }
        seen.set(name, r.service);
        merged.push(t as Record<string, unknown>);
      }
    }
    // cache 更新
    this.toolToService.clear();
    for (const [name, svc] of seen) this.toolToService.set(name, svc);
    return jsonRpcResponse(reqId, { result: { tools: merged } });
  }

  /** `tools/call`: tool 名から所属 service を引いて該当 WS のみに forward。
   *  cache miss なら fail (caller は tools/list を再実行する想定)。 */
  private async routeToolsCall(
    wsByService: Map<string, WebSocket>,
    headers: Record<string, string>,
    bodyBuf: ArrayBuffer,
    msg: JsonRpcMessage,
    reqId: unknown,
  ): Promise<Response> {
    const params = (msg.params ?? {}) as { name?: unknown };
    const toolName = typeof params.name === "string" ? params.name : "";
    if (!toolName) {
      return jsonRpcResponse(reqId, {
        error: { code: -32602, message: "tools/call missing params.name" },
      });
    }
    const service = this.toolToService.get(toolName);
    if (!service) {
      return jsonRpcResponse(reqId, {
        error: {
          code: -32602,
          message: `unknown tool '${toolName}' — call tools/list to refresh routing cache`,
        },
      });
    }
    const ws = wsByService.get(service);
    if (!ws) {
      // service の WS が落ちた直後など
      this.toolToService.delete(toolName);
      return jsonRpcResponse(reqId, {
        error: {
          code: -32000,
          message: `tool '${toolName}' service '${service}' is not currently attached`,
        },
      });
    }
    const fwd = await this.forwardToWs(ws, "POST", headers, bodyBuf);
    if (!fwd.ok) {
      return jsonResponse(fwd.status, { error: fwd.error });
    }
    return buildResponseFromRespFrame(fwd.resp);
  }

  /** 全 service WS に同じ body を投げ、各 service の JSON-RPC response body を
   *  並列収集する。1 binary でも fail しても他は止めない。 */
  private async broadcast(
    wsByService: Map<string, WebSocket>,
    headers: Record<string, string>,
    bodyBuf: ArrayBuffer,
  ): Promise<Array<
    | { ok: true; service: string; body: Record<string, unknown> }
    | { ok: false; service: string; error: string }
  >> {
    const tasks: Array<Promise<
      | { ok: true; service: string; body: Record<string, unknown> }
      | { ok: false; service: string; error: string }
    >> = [];
    for (const [service, ws] of wsByService) {
      tasks.push((async () => {
        const fwd = await this.forwardToWs(ws, "POST", headers, bodyBuf);
        if (!fwd.ok) return { ok: false as const, service, error: fwd.error };
        const bodyBytes = fwd.resp.body_b64
          ? base64ToArrayBuffer(fwd.resp.body_b64)
          : new ArrayBuffer(0);
        try {
          const parsed = JSON.parse(new TextDecoder().decode(bodyBytes)) as Record<
            string,
            unknown
          >;
          return { ok: true as const, service, body: parsed };
        } catch (e) {
          return {
            ok: false as const,
            service,
            error: `bad json from ${service}: ${e instanceof Error ? e.message : String(e)}`,
          };
        }
      })());
    }
    return Promise.all(tasks);
  }

  /** binary 側からの Frame 受信 — Resp を pending Promise に resolve する。 */
  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const text = typeof message === "string" ? message : new TextDecoder().decode(message);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return; // malformed frame は無視
    }
    if (typeof parsed !== "object" || parsed === null) return;
    const f = parsed as Record<string, unknown>;
    const kind = f["kind"];
    // Phase 2 multiplex: Hello frame の `service` field を attachment に記録。
    // 旧 v1 sender (service field 無し) は DEFAULT_SERVICE_V1_COMPAT 扱いで
    // attachment を書き、handleBridge の routing が常に attachment 参照で済むようにする。
    if (kind === "hello") {
      const rawService = f["service"];
      const service =
        typeof rawService === "string" && KNOWN_SERVICES.has(rawService)
          ? rawService
          : DEFAULT_SERVICE_V1_COMPAT;
      const binaryVersion =
        typeof f["binary_version"] === "string" ? (f["binary_version"] as string) : "";
      try {
        ws.serializeAttachment({ service, binaryVersion });
      } catch {
        // mock WS (test) は serializeAttachment 未定義 — skip
      }
      // 同 service の旧 WS は close (置換)。異 service は維持 (multiplex)。
      for (const other of this.state.getWebSockets(WS_TAG)) {
        if ((other as unknown) === (ws as unknown)) continue;
        if (wsServiceOf(other as WebSocket) === service) {
          try {
            (other as WebSocket).close(1000, "replaced");
          } catch {
            // 既 close は無視
          }
        }
      }
      console.log(
        `[mcp-relay] hello: service=${service} binary_version=${binaryVersion}`,
      );
      return;
    }
    if (kind === "notif") {
      // ADR-004 Phase D: binary 側 (`agent-mcp/src/relay.rs`) が event 受信時に
      // back-pipe してきた MCP `notifications/message`。`body` は JSON-RPC 2.0
      // notification (method = "notifications/message" etc) の object そのまま。
      // attached SSE channel 全部に fan-out する。
      const body = f["body"];
      if (typeof body !== "object" || body === null) return;
      const wire = JSON.stringify(body);
      for (const ch of this.sseChannels.values()) {
        this.writeSse(ch, wire);
      }
      return;
    }
    if (kind !== "resp") {
      // req / unknown は auth-worker 側では何もしない (hello は上で処理済み)
      return;
    }
    const id = f["id"];
    if (typeof id !== "string") return;
    const pending = this.pending.get(id);
    if (!pending) return; // 既に timeout 済 or unknown id
    this.pending.delete(id);
    clearTimeout(pending.timer);
    pending.resolve(f as unknown as RespFrame);
  }

  async webSocketClose(
    _ws: WebSocket,
    code: number,
    reason: string,
    wasClean: boolean,
  ): Promise<void> {
    // [tracer #123] WS が server 側で頻繁に close される根本原因の切り分け。
    // - code=1006 wasClean=false 多発 → CF idle limit / network drop
    // - code=1000 reason="replaced" → handleConnect race (直前の handleConnect log と対)
    // - code=1001 (Going Away) 規則的 → hibernation race
    // - 直前に webSocketError → binary 起因 (writer_task の sink.close())
    // remaining は close 後に残っている WS 数 (新しい WS が attach 済かの判定)。
    const remaining = this.state.getWebSockets(WS_TAG).length;
    console.log(
      `[mcp-relay] webSocketClose code=${code} reason=${JSON.stringify(reason)} wasClean=${wasClean} remaining=${remaining} pending=${this.pending.size}`,
    );
    this.rejectAllPending("relay_session_closed");
  }

  async webSocketError(_ws: WebSocket, err: unknown): Promise<void> {
    // [tracer #123] WS error 経由の close か (= binary 起因疑い) を判定。
    // String() で統一 (Error → "Error: msg")。`err instanceof Error` 三項にすると
    // non-Error テストが必要になり branch coverage に響くため、debug log は冗長で OK。
    console.log(
      `[mcp-relay] webSocketError err=${String(err)} pending=${this.pending.size}`,
    );
    this.rejectAllPending("relay_session_error");
  }

  private rejectAllPending(reason: string): void {
    const err = new Error(reason);
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(err);
    }
    this.pending.clear();
  }

  // ────────────────────────────────────────────────────────────────────────
  // ADR-006: server-side subscription / event queue tools (`POST /mcp` only)
  //
  // CCoW のように binary を起動できない環境向け。state は DO storage:
  //   key "subs"   → string[]   ("owner/repo#N")
  //   key "events" → Array<EventEnvelope> (FIFO、上限 MAX_QUEUED_EVENTS)
  //
  // 4 tool:
  //   - subscribe_issue_activity(owner, repo, issue_number)
  //   - unsubscribe_issue_activity(...)
  //   - list_watched_issues()
  //   - get_pending_events()    — ドレイン (read + clear)
  //
  // webhook 受信時に `handlePushEvent` がここの `events` array に append する
  // (subscription filter 通過時のみ)。CCoW Claude が `get_pending_events` を
  // POST /mcp 経由で呼んでドレインする。`--channels` 不要。
  // ────────────────────────────────────────────────────────────────────────

  /**
   * Inline stub MCP server (ADR-003 + ADR-006)。
   *
   * WS relay 未接続時は本 DO 自身が最小 MCP server として応答する。
   * CCoW で binary を spawn できない constraint があるため、stub に
   * subscribe / unsubscribe / list / get_pending_events を 4 つ追加して、
   * webhook → DO storage → polling drain の経路を `POST /mcp` だけで完結
   * させる。
   */
  private async handleInlineMcp(req: Request): Promise<Response> {
    let body: unknown;
    try {
      body = await req.json();
    } catch {
      return jsonRpcResponse(null, {
        error: { code: -32700, message: "Parse error" },
      });
    }
    if (typeof body !== "object" || body === null) {
      return jsonRpcResponse(null, {
        error: { code: -32600, message: "Invalid Request" },
      });
    }
    const msg = body as JsonRpcMessage;
    const method = typeof msg.method === "string" ? msg.method : "";
    const id = msg.id;

    // JSON-RPC notification (id 不在) — Streamable HTTP §2.1.1: 202 Accepted, no body
    if (id === undefined || id === null) {
      return new Response(null, { status: 202 });
    }

    switch (method) {
      case "initialize": {
        const params = (msg.params ?? {}) as { protocolVersion?: unknown };
        const proto =
          typeof params.protocolVersion === "string"
            ? params.protocolVersion
            : STUB_PROTOCOL_VERSION;
        return jsonRpcResponse(id, {
          result: {
            protocolVersion: proto,
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: STUB_SERVER_NAME, version: STUB_SERVER_VERSION },
            instructions: STUB_SERVER_INSTRUCTIONS,
          },
        });
      }
      case "tools/list":
        return jsonRpcResponse(id, {
          result: { tools: STUB_TOOLS },
        });
      case "tools/call": {
        const params = (msg.params ?? {}) as { name?: unknown; arguments?: unknown };
        const name = typeof params.name === "string" ? params.name : "";
        const args = (params.arguments ?? {}) as Record<string, unknown>;
        switch (name) {
          case "cc_relay_ping":
            return jsonRpcResponse(id, {
              result: { content: [{ type: "text", text: "pong" }], isError: false },
            });
          case "subscribe_issue_activity":
            return await this.toolSubscribe(id, args);
          case "unsubscribe_issue_activity":
            return await this.toolUnsubscribe(id, args);
          case "list_watched_issues":
            return await this.toolListWatched(id);
          case "get_pending_events":
            return await this.toolGetPendingEvents(id);
          default:
            return jsonRpcResponse(id, {
              error: { code: -32602, message: `Unknown tool: ${name}` },
            });
        }
      }
      case "ping":
        return jsonRpcResponse(id, { result: {} });
      case "prompts/list":
        return jsonRpcResponse(id, { result: { prompts: [] } });
      case "resources/list":
        return jsonRpcResponse(id, { result: { resources: [] } });
      default:
        return jsonRpcResponse(id, {
          error: { code: -32601, message: `Method not found: ${method}` },
        });
    }
  }

  /** ADR-006: subscribe_issue_activity tool — DO storage の `subs` set に追加。 */
  private async toolSubscribe(
    id: unknown,
    args: Record<string, unknown>,
  ): Promise<Response> {
    const key = parseIssueKey(args);
    if (typeof key !== "string") {
      return jsonRpcResponse(id, toolError(key.error));
    }
    const subs = await this.loadSubs();
    let added = false;
    if (!subs.includes(key)) {
      subs.push(key);
      subs.sort();
      await this.state.storage.put("subs", subs);
      added = true;
    }
    return jsonRpcResponse(
      id,
      toolOk(added ? `subscribed: ${key}` : `already subscribed: ${key}`),
    );
  }

  /** ADR-006: unsubscribe_issue_activity tool — DO storage の `subs` set から削除。 */
  private async toolUnsubscribe(
    id: unknown,
    args: Record<string, unknown>,
  ): Promise<Response> {
    const key = parseIssueKey(args);
    if (typeof key !== "string") {
      return jsonRpcResponse(id, toolError(key.error));
    }
    const subs = await this.loadSubs();
    const idx = subs.indexOf(key);
    if (idx < 0) {
      return jsonRpcResponse(id, toolOk(`was not subscribed: ${key}`));
    }
    subs.splice(idx, 1);
    await this.state.storage.put("subs", subs);
    return jsonRpcResponse(id, toolOk(`unsubscribed: ${key}`));
  }

  /** ADR-006: list_watched_issues tool — 現在 subscribe 中の set を返す。 */
  private async toolListWatched(id: unknown): Promise<Response> {
    const subs = await this.loadSubs();
    return jsonRpcResponse(id, toolOk(JSON.stringify(subs)));
  }

  /** ADR-006: get_pending_events tool — `events` queue を drain して返す。
   *  返した event は storage から削除する (at-most-once、operator は idempotent
   *  処理を前提)。サイズが大きい場合は将来 cursor-based に拡張する。 */
  private async toolGetPendingEvents(id: unknown): Promise<Response> {
    const events = await this.loadEvents();
    if (events.length > 0) {
      await this.state.storage.put("events", []);
    }
    return jsonRpcResponse(id, toolOk(JSON.stringify(events)));
  }

  /** ADR-006: webhook handler から呼ばれる。subscription filter を通った
   *  event だけ `events` queue に append。queue は FIFO、上限を超えたら oldest
   *  を捨てる (drop-oldest policy)。 */
  async queueEventIfSubscribed(eventBody: Record<string, unknown>): Promise<{
    queued: boolean;
    matched: string | null;
    queue_size: number;
  }> {
    const owner = typeof eventBody.owner === "string" ? eventBody.owner : null;
    const repo = typeof eventBody.repo === "string" ? eventBody.repo : null;
    const num =
      typeof eventBody.issue_number === "number" ? eventBody.issue_number : null;
    if (!owner || !repo || num === null) {
      return { queued: false, matched: null, queue_size: 0 };
    }
    const key = `${owner}/${repo}#${num}`;
    const subs = await this.loadSubs();
    if (!subs.includes(key)) {
      return { queued: false, matched: null, queue_size: 0 };
    }
    const events = await this.loadEvents();
    events.push(eventBody);
    while (events.length > MAX_QUEUED_EVENTS) {
      events.shift();
    }
    await this.state.storage.put("events", events);
    return { queued: true, matched: key, queue_size: events.length };
  }

  private async loadSubs(): Promise<string[]> {
    const v = await this.state.storage.get<string[]>("subs");
    return Array.isArray(v) ? v.slice() : [];
  }

  private async loadEvents(): Promise<Record<string, unknown>[]> {
    const v = await this.state.storage.get<Record<string, unknown>[]>("events");
    return Array.isArray(v) ? v.slice() : [];
  }
}

/** Phase 2 multiplex: WS attachment から service id を読む。`Hello` frame
 *  到着前 (まだ attachment 未書込) or mock WS では DEFAULT_SERVICE_V1_COMPAT
 *  に fallback する。binary 側の `default_service_v1_compat()` と一致。 */
function wsServiceOf(ws: WebSocket): string {
  try {
    const att = ws.deserializeAttachment() as { service?: unknown } | null;
    if (att && typeof att.service === "string" && KNOWN_SERVICES.has(att.service)) {
      return att.service;
    }
  } catch {
    // 未定義 / 未書込 → fallback
  }
  return DEFAULT_SERVICE_V1_COMPAT;
}

/** Phase 2 helper: RespFrame → http::Response 組み立て。invalid header は drop。 */
function buildResponseFromRespFrame(respFrame: RespFrame): Response {
  const respHeaders = new Headers();
  if (respFrame.headers) {
    for (const [k, v] of Object.entries(respFrame.headers)) {
      try {
        respHeaders.set(k, String(v));
      } catch {
        // 不正 header は黙って drop (Workers Response は厳しめ)
      }
    }
  }
  const body = respFrame.body_b64 ? base64ToArrayBuffer(respFrame.body_b64) : null;
  return new Response(body, { status: respFrame.status, headers: respHeaders });
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** ADR-004 Phase D: MCP `notifications/message` JSON-RPC envelope を 1 行で
 *  作る。SSE 上にそのまま流す。binary が back-pipe してくる本番経路と
 *  形式を揃える (binary 側でも同じ shape を吐く)。 */
function sseFormatNotification(method: string, params: unknown): string {
  return JSON.stringify({ jsonrpc: "2.0", method, params });
}


// ────────────────────────────────────────────────────────────────────────────
// Inline stub MCP server (ADR-003)
//
// WS relay が未接続のときに本 DO 自身が最小限の MCP server として応答するための
// JSON-RPC 2.0 ハンドラ群。Streamable HTTP transport の単純 request/response
// 形態 (= POST 1 本に対して 200 + JSON-RPC body 1 本) のみ実装する。SSE / batch
// は未対応 (Anthropic / Claude Code Web は単純応答も受け取れる)。
//
// tools には固定で `cc_relay_ping` を 1 個だけ載せる。空配列だと一部 client が
// 「tool 無しのサーバー = 接続失敗」とみなすため、health-check 用の stub を 1 つ
// 露出させて connector UI を「接続成功・1 tool」状態にする。
// ────────────────────────────────────────────────────────────────────────────

const STUB_PROTOCOL_VERSION = "2025-06-18";
const STUB_SERVER_NAME = "cc-relay-stub";
const STUB_SERVER_VERSION = "0.1.0";

/** ADR-006: server-side event queue 上限。webhook 大量受信時の DO storage
 *  破裂を防ぐ。drop-oldest policy で古い event から捨てる。値は経験則
 *  (1 issue で 1 日あたり ~100 events を見込み、1 週間分くらい)。 */
const MAX_QUEUED_EVENTS = 500;

/** ADR-006: initialize response に乗せる instructions。CCoW Claude が
 *  POST /mcp 経由で見つけるので、subscribe → wait → drain の運用を伝える。 */
const STUB_SERVER_INSTRUCTIONS =
  "Server-side GitHub issue activity broker. Call `subscribe_issue_activity` " +
  "to register interest in an issue, then `get_pending_events` to drain " +
  "webhook events received since the last call. The server filters by " +
  "subscription set and stores events in Durable Object storage; no client " +
  "binary or local file is needed.";

/** ADR-006: stub mode で露出する tools (CCoW 経路)。 */
const STUB_TOOLS = [
  {
    name: "cc_relay_ping",
    description:
      "Health-check tool exposed by the cc-relay stub MCP server when no live relay binary is connected. Returns 'pong'.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
      additionalProperties: false,
    },
  },
  {
    name: "subscribe_issue_activity",
    description:
      "Subscribe to GitHub issue activity (comments, labels, state changes). " +
      "Persists the (owner, repo, issue_number) tuple to server-side Durable " +
      "Object storage. Events arriving via webhook are filtered against the " +
      "subscription set and queued for `get_pending_events`. Idempotent.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string" },
        repo: { type: "string" },
        issue_number: { type: "integer", minimum: 1 },
      },
      required: ["owner", "repo", "issue_number"],
      additionalProperties: false,
    },
  },
  {
    name: "unsubscribe_issue_activity",
    description:
      "Unsubscribe from GitHub issue activity. Removes the (owner, repo, " +
      "issue_number) tuple from server-side subscription set. Future events " +
      "for this issue are dropped at the filter step. Idempotent.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string" },
        repo: { type: "string" },
        issue_number: { type: "integer", minimum: 1 },
      },
      required: ["owner", "repo", "issue_number"],
      additionalProperties: false,
    },
  },
  {
    name: "list_watched_issues",
    description:
      "Return the list of (owner, repo, issue_number) tuples currently " +
      "subscribed via subscribe_issue_activity. JSON array of strings of the " +
      "form 'owner/repo#N'.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
      additionalProperties: false,
    },
  },
  {
    name: "get_pending_events",
    description:
      "Drain webhook events queued since the last call. Returns a JSON " +
      "array of event objects (each with event_type, delivery_id, owner, " +
      "repo, issue_number, received_at, payload). The queue is cleared on " +
      "drain, so subsequent calls return only newly arrived events.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
      additionalProperties: false,
    },
  },
];

interface JsonRpcMessage {
  jsonrpc?: unknown;
  id?: unknown;
  method?: unknown;
  params?: unknown;
}

/** ADR-006: tools/call の引数から `IssueKey` 文字列を抽出。失敗時は
 *  `{error}` を返す (call site が `toolError` で wrap する)。 */
function parseIssueKey(
  args: Record<string, unknown>,
): string | { error: string } {
  const owner = typeof args.owner === "string" ? args.owner : "";
  const repo = typeof args.repo === "string" ? args.repo : "";
  const num =
    typeof args.issue_number === "number" && Number.isInteger(args.issue_number)
      ? args.issue_number
      : null;
  if (!owner) return { error: "missing or non-string 'owner'" };
  if (!repo) return { error: "missing or non-string 'repo'" };
  if (num === null || num <= 0) {
    return { error: "missing or non-positive-integer 'issue_number'" };
  }
  return `${owner}/${repo}#${num}`;
}

/** MCP tool 成功レスポンス wrapper (text content 1 個)。 */
function toolOk(text: string): { result: unknown } {
  return { result: { content: [{ type: "text", text }], isError: false } };
}

/** MCP tool エラーレスポンス wrapper (text content + isError=true)。 */
function toolError(text: string): { result: unknown } {
  return { result: { content: [{ type: "text", text }], isError: true } };
}

function jsonRpcResponse(
  id: unknown,
  body: { result: unknown } | { error: { code: number; message: string } },
): Response {
  return new Response(
    JSON.stringify({ jsonrpc: "2.0", id, ...body }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}

/** Workers runtime の `btoa` で ArrayBuffer → base64 standard alphabet。 */
function arrayBufferToBase64(buf: ArrayBuffer): string {
  if (buf.byteLength === 0) return "";
  const bytes = new Uint8Array(buf);
  // call stack overflow を防ぐため chunk 分割
  const CHUNK = 0x8000;
  let s = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(
      null,
      Array.from(bytes.subarray(i, i + CHUNK)),
    );
  }
  return btoa(s);
}

/**
 * Workers runtime の `atob` で base64 standard → ArrayBuffer。
 * caller (`handleBridge`) が空文字列を渡さない契約 (`respFrame.body_b64 ? ... : null`)。
 */
function base64ToArrayBuffer(b64: string): ArrayBuffer {
  const s = atob(b64);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes.buffer;
}
