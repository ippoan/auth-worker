/**
 * MCP relay 用 Durable Object (issue #117 / Phase 6 skeleton)。
 *
 * `github-mcp-server-rs` の `install-mcp.sh` が cloudflared Quick Tunnel を立てる
 * 代わりに、binary 側から `wss://mcp.ippoan.org/u/<github_login>/connect` へ
 * outbound WebSocket を張る。Claude Code Web からの
 * `POST https://mcp.ippoan.org/u/<github_login>/mcp` は同じ DO へルーティングされ、
 * 接続中の binary に frame として転送される — のだが、本 PR (Phase 6) は
 * **routes + DO skeleton のみ**。frame 変換 (Streamable HTTP ↔ WS frame) は
 * Phase 7 で実装する。
 *
 * 設計判断 (user 確認済み, issue #117 plan):
 *
 * - Hibernatable WebSocket (`state.acceptWebSocket()`) を使う。idle 時は DO が
 *   memory unload されて課金されない。
 * - 同一 user の同時接続は 1 本のみ。新しい upgrade が来たら既存 WS を
 *   `close(1000, "replaced")` してから accept する。
 * - DO 内 path は worker public path と衝突しないように `/__connect` /
 *   `/__bridge` の double-underscore prefix を使う。
 *
 * 関連: ippoan/github-mcp-server-rs#27 (binary 側、Phase 7 と並行実装)。
 */

/**
 * DO が必要とする env subset。Phase 6 では参照する binding は無いが、
 * Phase 7 で `MCP_JWT_SECRET` / observability 系を追加する想定。
 */
export interface McpSessionEnv {
  /** Phase 7 で内部 frame の追加検証に使う候補。Phase 6 では未参照。 */
  MCP_JWT_SECRET?: string;
}

/** `state.acceptWebSocket()` に渡す tag — Phase 7 で `getWebSockets("client")` で参照する */
const WS_TAG = "client";

export class McpSession implements DurableObject {
  state: DurableObjectState;
  env: McpSessionEnv;

  constructor(state: DurableObjectState, env: McpSessionEnv) {
    this.state = state;
    this.env = env;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);

    // binary 側からの WS upgrade (auth-worker の handler 経由で転送されてくる)。
    if (url.pathname === "/__connect") {
      return this.handleConnect(req);
    }

    // Claude Code Web からの HTTP bridge (auth-worker の handler 経由で転送されてくる)。
    // Phase 6 では本当に転送できる準備が無いので 503 / 501 を返す。
    if (url.pathname === "/__bridge") {
      return this.handleBridge();
    }

    return new Response("Not Found", { status: 404 });
  }

  private handleConnect(req: Request): Response {
    if (req.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected websocket", { status: 426 });
    }

    // 同時 1 本のみ: 既存 WS があれば close してから新規 accept。
    for (const old of this.state.getWebSockets(WS_TAG)) {
      try {
        old.close(1000, "replaced");
      } catch {
        // 既に閉じてる/エラー時は無視 (Phase 7 で log を入れる)
      }
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.state.acceptWebSocket(server, [WS_TAG]);
    return new Response(null, { status: 101, webSocket: client });
  }

  private handleBridge(): Response {
    const active = this.state.getWebSockets(WS_TAG);
    if (active.length === 0) {
      return new Response(
        JSON.stringify({ error: "no_active_relay_session" }),
        { status: 503, headers: { "Content-Type": "application/json" } },
      );
    }
    // Phase 7 で実装する。WS frame ↔ Streamable HTTP の双方向マッピングを
    // request_id correlation で行う。
    return new Response(
      JSON.stringify({ error: "bridge_not_implemented", phase: 7 }),
      { status: 501, headers: { "Content-Type": "application/json" } },
    );
  }

  // Phase 6 では受信 frame は破棄。Phase 7 で request/response correlation を実装する。
  async webSocketMessage(_ws: WebSocket, _message: string | ArrayBuffer): Promise<void> {
    /* Phase 7 で実装 */
  }

  async webSocketClose(
    _ws: WebSocket,
    _code: number,
    _reason: string,
    _wasClean: boolean,
  ): Promise<void> {
    /* Phase 7 で pending request の cleanup を実装 */
  }

  async webSocketError(_ws: WebSocket, _err: unknown): Promise<void> {
    /* Phase 7 で error log + pending request の cleanup を実装 */
  }
}
