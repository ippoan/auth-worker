/**
 * GitHub webhook receiver — ADR-004 (multiplex 修正版)。
 *
 * `POST /webhooks/github` (host: `mcp.ippoan.org` / `mcp-staging.ippoan.org`)
 *
 * 1. `X-Hub-Signature-256` を `env.GITHUB_WEBHOOK_SECRET` で HMAC-SHA256 検証。
 * 2. `X-GitHub-Event` が `{issues, issue_comment}` 以外なら 200 で ignore。
 * 3. payload から `(owner, repo, issue_number, event_type, delivery_id)`
 *    を抽出。
 * 4. `idFromName(payload.repository.owner.login)` で **既存** `McpSession`
 *    DO (per `github_login`) を取得、`/__push_event` に raw event JSON を
 *    POST。McpSession DO 内で attached `client` WS 全部に `{kind:"event"}`
 *    frame として broadcast される。binary 側 (`agent-mcp/src/relay.rs`)
 *    が `~/.cc-relay/watched-issues.txt` で filter する。
 * 5. 200 を返す (subscriber 0 でも 200 で構わない、GitHub の retry を防ぐ)。
 *
 * 設計判断:
 * - MCP は通常 1 endpoint。専用 `IssueRoomDO` を作らず、既存 `McpSession`
 *   DO を multiplex する形で event を流す。binary に 2 本目の WS を張らせる
 *   必要が無くなり、auth 経路も 1 つに揃う。
 * - public issue 前提なので signature 検証は **spam 対策** であって
 *   authentication ではない。secret は 1 個共有 (`GITHUB_WEBHOOK_SECRET`)、
 *   全 repo の webhook 設定で同じ値を使う。
 * - routing key は `repository.owner.login`。個人 repo (`ippoan/cc-relay`)
 *   なら owner == github_login で自然に解決。organization repo 対応は
 *   後追い (KV / D1 で github_login mapping を導入)。
 *
 * cross-reference: `cc-relay/ARCHITECTURE.md` ADR-004。
 */

import type { Env } from "../index";

/** GitHub 公式の sig header。lowercase で取れる。 */
const SIG_HEADER = "x-hub-signature-256";
const EVENT_HEADER = "x-github-event";
const DELIVERY_HEADER = "x-github-delivery";

/** 受け付ける event type。 */
const SUPPORTED_EVENTS = new Set<string>(["issues", "issue_comment"]);

interface IssueEventPayload {
  action?: string;
  issue?: {
    number?: number;
  };
  repository?: {
    name?: string;
    owner?: {
      login?: string;
    };
  };
}

export async function handleGithubWebhook(
  request: Request,
  env: Env,
): Promise<Response> {
  if (request.method !== "POST") {
    return jsonResp(405, { error: "method_not_allowed" });
  }
  if (!env.GITHUB_WEBHOOK_SECRET) {
    console.error("github_webhook_secret_not_configured");
    return jsonResp(503, { error: "webhook_not_configured" });
  }
  if (!env.MCP_SESSION_DO) {
    console.error("mcp_session_do_binding_missing");
    return jsonResp(503, { error: "mcp_session_not_configured" });
  }

  const sig = request.headers.get(SIG_HEADER);
  const eventType = request.headers.get(EVENT_HEADER);
  const delivery = request.headers.get(DELIVERY_HEADER) ?? "";
  if (!sig) {
    return jsonResp(401, { error: "missing_signature" });
  }
  if (!eventType) {
    return jsonResp(400, { error: "missing_event_type" });
  }

  // body を 1 度だけ読む (consumable)。検証 + DO への push の両方で使う。
  const rawBody = await request.arrayBuffer();

  const verified = await verifySignature(env.GITHUB_WEBHOOK_SECRET, rawBody, sig);
  if (!verified) {
    console.warn(
      JSON.stringify({ event: "github_webhook_sig_mismatch", delivery, eventType }),
    );
    return jsonResp(401, { error: "signature_mismatch" });
  }

  // 未対応 event は 200 で ignore (GitHub の retry を発生させない)。
  if (!SUPPORTED_EVENTS.has(eventType)) {
    return jsonResp(200, { ok: true, ignored: true, eventType });
  }

  let payload: IssueEventPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(rawBody)) as IssueEventPayload;
  } catch (e) {
    console.warn(
      JSON.stringify({
        event: "github_webhook_parse_failed",
        error: String(e),
        delivery,
      }),
    );
    return jsonResp(400, { error: "invalid_json" });
  }

  const owner = payload.repository?.owner?.login;
  const repo = payload.repository?.name;
  const issueNumber = payload.issue?.number;
  if (!owner || !repo || typeof issueNumber !== "number") {
    return jsonResp(200, {
      ok: true,
      ignored: true,
      reason: "missing_owner_repo_or_issue",
    });
  }

  const action = payload.action ?? "unknown";
  const fullEventType = `${eventType}.${action}`;
  // multiplex on existing McpSession DO (per github_login)。
  // 個人 repo は `owner.login == github_login`。
  const doKey = owner;

  const eventJson = JSON.stringify({
    event_type: fullEventType,
    delivery_id: delivery,
    owner,
    repo,
    issue_number: issueNumber,
    received_at: new Date().toISOString(),
    payload,
  });

  const stub = env.MCP_SESSION_DO.get(env.MCP_SESSION_DO.idFromName(doKey));
  try {
    const doResp = await stub.fetch(
      new Request("https://do.invalid/__push_event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: eventJson,
      }),
    );
    if (!doResp.ok) {
      console.warn(
        JSON.stringify({
          event: "mcp_session_push_failed",
          status: doResp.status,
          doKey,
          delivery,
        }),
      );
    } else {
      const summary = (await doResp.json()) as {
        delivered?: number;
        total?: number;
      };
      console.log(
        JSON.stringify({
          event: "mcp_session_pushed",
          doKey,
          delivery,
          fullEventType,
          delivered: summary.delivered ?? 0,
          total: summary.total ?? 0,
        }),
      );
    }
  } catch (e) {
    console.error(
      JSON.stringify({
        event: "mcp_session_push_error",
        error: String(e),
        doKey,
        delivery,
      }),
    );
    // GitHub には 200 を返す (retry を避ける)。失敗は console log で観測。
  }

  return jsonResp(200, { ok: true });
}

/**
 * HMAC-SHA256 検証 (GitHub webhook spec)。
 * sig は `sha256=<hex>` 形式。constant-time compare。
 */
async function verifySignature(
  secret: string,
  body: ArrayBuffer,
  signatureHeader: string,
): Promise<boolean> {
  const m = /^sha256=([0-9a-f]+)$/i.exec(signatureHeader);
  if (!m || !m[1]) return false;
  const providedHex = m[1].toLowerCase();

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sigBytes = await crypto.subtle.sign("HMAC", key, body);
  const expectedHex = bufToHex(new Uint8Array(sigBytes));

  return constantTimeEqual(providedHex, expectedHex);
}

function bufToHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += (bytes[i] ?? 0).toString(16).padStart(2, "0");
  }
  return s;
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function jsonResp(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
