/**
 * MCP relay 用 Durable Object (issue #117 Phase 6 + #119 Phase 7).
 *
 * `github-mcp-server-rs` の `install-mcp.sh` が cloudflared Quick Tunnel を立てる
 * 代わりに、binary 側から `wss://mcp.ippoan.org/u/<github_login>/connect` へ
 * outbound WebSocket を張る。Claude Code Web からの
 * `POST https://mcp.ippoan.org/u/<github_login>/mcp` は同じ DO へルーティングされ、
 * 接続中の binary に WS frame として転送される。
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

/** `state.acceptWebSocket()` に渡す tag — `getWebSockets("client")` で参照する */
const WS_TAG = "client";

/** Frame schema version (binary 側 #27 と一致させる)。 */
const FRAME_VERSION = 1;

/** 1 request あたりの WS frame round-trip timeout (ms)。 */
const REQUEST_TIMEOUT_MS = 30_000;

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

    return new Response("Not Found", { status: 404 });
  }

  private handleConnect(req: Request): Response {
    if (req.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected websocket", { status: 426 });
    }

    // 同時 1 本のみ: 既存 WS があれば close してから新規 accept。
    const existing = this.state.getWebSockets(WS_TAG);
    if (existing.length > 0) {
      // [tracer #123] handleConnect race 仮説の検証用。新 upgrade で既存 WS を
      // close するパスが頻発するなら、CF keepalive 等が新 connect を発火させて
      // いる疑い。確定後は削除予定。
      console.log(
        `[mcp-relay] handleConnect: replacing ${existing.length} existing WS (suspect handleConnect race)`,
      );
    }
    for (const old of existing) {
      try {
        old.close(1000, "replaced");
      } catch {
        // 既に閉じてる/エラー時は無視 — Phase 6 と同じ振る舞い
      }
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.state.acceptWebSocket(server, [WS_TAG]);
    return new Response(null, { status: 101, webSocket: client });
  }

  private async handleBridge(req: Request): Promise<Response> {
    const active = this.state.getWebSockets(WS_TAG);
    // [tracer #123] stale WS race の症状特定用。
    // `502 Can't call WebSocket send() after close()` が出る時は ws_count >= 1
    // かつ states に CLOSING(2) / CLOSED(3) が混じっているはず。Hibernated WS の
    // readyState が test 環境と本番で同じ値かも観測。確定後は削除予定。
    // 実 WebSocket は readyState getter を持つので throw しない (fake mock は
    // undefined → "undefined" 出力で OK)。
    console.log(
      `[mcp-relay] handleBridge: ws_count=${active.length} states=[${active
        .map((w) => String((w as WebSocket).readyState))
        .join(",")}] pending=${this.pending.size}`,
    );
    if (active.length === 0) {
      return jsonResponse(503, { error: "no_active_relay_session" });
    }
    const ws = active[0] as WebSocket;

    const id = crypto.randomUUID();

    // body / headers を取り出して Frame::Req に詰める
    const bodyBuf = await req.arrayBuffer();
    const headers: Record<string, string> = {};
    req.headers.forEach((v, k) => {
      const lk = k.toLowerCase();
      if (HEADERS_BLOCKLIST.has(lk)) return;
      if (lk.startsWith("cf-")) return;
      headers[lk] = v;
    });

    const reqFrame = {
      kind: "req",
      v: FRAME_VERSION,
      id,
      method: req.method,
      // binary 側 bridge.rs は StreamableHttpService を直接呼ぶので path は "/" 固定
      path: "/",
      headers,
      body_b64: arrayBufferToBase64(bodyBuf),
    };

    // WS send が即時失敗 (ws closed, etc) なら 502。pending 登録前に試す
    // ことで失敗時の cleanup 分岐 (`if (p)`) を不要にする。
    try {
      ws.send(JSON.stringify(reqFrame));
    } catch (e) {
      return jsonResponse(502, {
        error: "relay_send_failed",
        message: e instanceof Error ? e.message : String(e),
      });
    }

    // send 成功後に pending を登録。Workers DO は single-threaded で
    // webSocketMessage と handleBridge は interleave しないので、ここで race は無い。
    const respPromise = new Promise<RespFrame>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("relay_timeout"));
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
    });

    let respFrame: RespFrame;
    try {
      respFrame = await respPromise;
    } catch (e) {
      // reject は常に new Error(...) なので safely cast
      const msg = (e as Error).message;
      const status = msg === "relay_timeout" ? 504 : 502;
      return jsonResponse(status, { error: msg });
    }

    // Frame::Resp → http::Response 組み立て
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
    const body = respFrame.body_b64
      ? base64ToArrayBuffer(respFrame.body_b64)
      : null;
    return new Response(body, {
      status: respFrame.status,
      headers: respHeaders,
    });
  }

  /** binary 側からの Frame 受信 — Resp を pending Promise に resolve する。 */
  async webSocketMessage(_ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const text = typeof message === "string" ? message : new TextDecoder().decode(message);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return; // malformed frame は無視
    }
    if (typeof parsed !== "object" || parsed === null) return;
    const f = parsed as Record<string, unknown>;
    if (f["kind"] !== "resp") {
      // hello / req は auth-worker 側では何もしない
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
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
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
