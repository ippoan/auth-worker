/**
 * IssueRoomDO — per-issue WebSocket room for GitHub issue activity broadcast.
 *
 * ADR-004 (cc-relay/ARCHITECTURE.md): subscription は WebSocket connection
 * 自体。client は `wss://mcp.ippoan.org/issues/<owner>/<repo>/<N>/connect`
 * に WS を open、本 DO がそれを hibernatable な形で保持する。
 *
 * GitHub から `/webhooks/github` に到着した event は (owner, repo, issue#)
 * から本 DO の idFromName(`issue:<owner>/<repo>#<N>`) で解決され、
 * `/__push_event` を経由して attached WS 全部に broadcast される。
 *
 * 設計判断:
 * - **storage を一切使わない**。subscription state = WS connection 自体。
 *   WS close = unsubscribe。空 instance になれば DO は GC 対象になる。
 * - **idFromName key の形式は `issue:<owner>/<repo>#<N>`** (例:
 *   `issue:ippoan/cc-relay#42`)。`McpSession` (キー: github_login) と
 *   namespace が分離されるよう prefix で区別。
 * - Hibernatable WebSocket (`state.acceptWebSocket()`) + tag `"subscriber"`。
 * - public route と衝突しないよう DO 内 path は `/__connect` / `/__push_event`。
 * - push body は raw event JSON (req/resp envelope 不要、本 WS は event
 *   delivery 専用)。
 */

/** DO の env subset。本 DO は env 参照なし。 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface IssueRoomEnv {}

/** `state.acceptWebSocket()` の tag — `getWebSockets("subscriber")` で参照する */
const WS_TAG = "subscriber";

export class IssueRoomDO {
  state: DurableObjectState;
  // env は参照しないが Cloudflare runtime が constructor に渡してくる。
  env: IssueRoomEnv;

  constructor(state: DurableObjectState, env: IssueRoomEnv) {
    this.state = state;
    this.env = env;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/__connect") return this.handleConnect(req);
    if (url.pathname === "/__push_event") return this.handlePushEvent(req);
    if (url.pathname === "/__count") return this.handleCount();
    return new Response("Not Found", { status: 404 });
  }

  /**
   * `/__connect` — WS upgrade。tag だけで識別し github_login 等の
   * metadata は持たない (broadcast に identity は要らない、subscription =
   * WS 自体)。
   */
  private async handleConnect(req: Request): Promise<Response> {
    if (req.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected websocket", { status: 426 });
    }
    const { 0: clientWs, 1: serverWs } = new WebSocketPair();
    this.state.acceptWebSocket(serverWs, [WS_TAG]);
    return new Response(null, {
      status: 101,
      webSocket: clientWs,
    });
  }

  /**
   * `/__push_event` — webhook handler から呼ばれる。body の event JSON を
   * 全 attached WS に broadcast。
   */
  private async handlePushEvent(req: Request): Promise<Response> {
    let bodyText: string;
    try {
      // 一度 text として読んで、send 時にそのまま流す (再 JSON.parse は不要)。
      bodyText = await req.text();
    } catch (e) {
      return jsonResp(400, { error: "invalid_body", detail: String(e) });
    }
    if (!bodyText) {
      return jsonResp(400, { error: "empty_body" });
    }
    const wsList = this.state.getWebSockets(WS_TAG);
    let delivered = 0;
    let dead = 0;
    for (const ws of wsList) {
      try {
        ws.send(bodyText);
        delivered += 1;
      } catch {
        // 死んでる WS はランタイムが回収するまで掃除しない (broadcast 続行)。
        dead += 1;
      }
    }
    return jsonResp(200, { delivered, dead, total: wsList.length });
  }

  /** `/__count` — debug: 現在接続中の subscriber 数を返す。 */
  private handleCount(): Response {
    const wsList = this.state.getWebSockets(WS_TAG);
    return jsonResp(200, { subscribers: wsList.length });
  }

  /**
   * Hibernatable WS callback: client → server message。
   *
   * 本 DO は event delivery only なので client 側からの送信は無視する
   * (将来 keepalive ping を入れる余地はあり)。
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async webSocketMessage(_ws: WebSocket, _message: ArrayBuffer | string): Promise<void> {
    // intentionally empty.
  }

  /** Hibernatable WS callback: close。Cloudflare runtime が WS を pool から除く。 */
  async webSocketClose(
    ws: WebSocket,
    code: number,
    reason: string,
    wasClean: boolean,
  ): Promise<void> {
    console.log(
      JSON.stringify({
        event: "issue_room_ws_close",
        code,
        reason,
        wasClean,
        remaining: this.state.getWebSockets(WS_TAG).length - 1,
      }),
    );
    try {
      ws.close(code, reason);
    } catch {
      // already closed
    }
  }

  async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    console.warn(
      JSON.stringify({
        event: "issue_room_ws_error",
        error: String(error),
      }),
    );
    try {
      ws.close(1011, "server_error");
    } catch {
      // already closed
    }
  }
}

function jsonResp(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
