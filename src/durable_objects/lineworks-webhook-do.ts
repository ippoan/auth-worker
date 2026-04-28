/**
 * LINE WORKS webhook の Durable Object。bot_id ごとに 1 instance が作られる
 * (`idFromName(bot_id)`)。責務:
 *
 * 1. **bot_secret キャッシュ**: `bot_secret_encrypted` を backend から初回 fetch して storage に
 *    永続化。復号後の平文は in-memory のみで保持し、storage には書かない。
 * 2. **HMAC 検証**: 受け取った raw body と `x-works-signature` を bot_secret で検証。
 * 3. **イベント逆処理キュー + 再送**: 検証済イベントを storage キューに enqueue し、alarm() で
 *    backend internal route に exponential-backoff 付きで POST する。
 *
 * これにより auth-worker は LINE WORKS に対して常に 200 を即返せる (検証失敗以外)。
 * backend が一時ダウンしても LINE WORKS のリトライではなく DO の alarm が再送するため、
 * リトライストームが発生しない。
 */

import { decryptBotSecret, signWebhookBody, constantTimeEqual, base64Decode } from "../lib/lineworks-crypto";
import { signInternalJWT } from "../lib/internal-jwt";

interface DOEnv {
  ALC_API_ORIGIN: string;
  JWT_SECRET: string;
  SSO_ENCRYPTION_KEY: string;
}

/** WebhookEvent: rust-alc-api 側 `InternalEventBody` と互換 */
interface WebhookEvent {
  bot_id: string;
  event_type: string;
  channel_id?: string;
  channel_type?: string;
  title?: string;
}

interface QueueItem {
  event: WebhookEvent;
  ts: number;
  attempts: number;
}

const STORAGE_KEY_BOT_SECRET = "bot_secret_encrypted";
const QUEUE_PREFIX = "queue:";
const MAX_ATTEMPTS = 10;
const MAX_BACKOFF_MS = 60_000;

export class LineworksWebhookDO {
  state: DurableObjectState;
  env: DOEnv;
  /** in-memory cache (storage には書かない、復号後の平文) */
  private decryptedSecret: string | null = null;

  constructor(state: DurableObjectState, env: DOEnv) {
    this.state = state;
    this.env = env;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/event") return this.handleEvent(req);
    if (url.pathname === "/refresh") return this.refreshSecret();
    return new Response("Not Found", { status: 404 });
  }

  // ---------- /event ----------

  private async handleEvent(req: Request): Promise<Response> {
    const botId = req.headers.get("x-bot-id");
    const sig = req.headers.get("x-works-signature");
    const rawBody = await req.arrayBuffer();
    if (!botId) return jsonResp(400, { error: "missing_bot_id" });
    if (!sig) return jsonResp(401, { error: "missing_signature" });

    let botSecret: string;
    try {
      botSecret = await this.getBotSecret(botId);
    } catch (e) {
      console.error("lineworks_webhook_get_bot_secret_failed", { botId, error: String(e) });
      return jsonResp(401, { error: "bot_secret_unavailable" });
    }

    if (!(await this.verifySignature(botSecret, rawBody, sig))) {
      // bot_secret 入れ替え時の自己治癒: 1 度だけ refresh して再検証する
      console.warn("lineworks_webhook_signature_mismatch_retrying_with_fresh_secret", { botId });
      await this.invalidateSecret();
      try {
        botSecret = await this.getBotSecret(botId);
      } catch {
        return jsonResp(401, { error: "signature_mismatch" });
      }
      if (!(await this.verifySignature(botSecret, rawBody, sig))) {
        return jsonResp(401, { error: "signature_mismatch" });
      }
    }

    const event = parseEvent(botId, rawBody);
    if (!event) return jsonResp(200, { ok: true, ignored: true });

    const id = `${QUEUE_PREFIX}${ulid()}`;
    const item: QueueItem = { event, ts: Date.now(), attempts: 0 };
    await this.state.storage.put(id, item);
    await this.state.storage.setAlarm(Date.now());
    return jsonResp(200, { ok: true, queued: true });
  }

  private async verifySignature(
    botSecret: string,
    body: ArrayBuffer,
    signatureB64: string,
  ): Promise<boolean> {
    const expected = await signWebhookBody(botSecret, body);
    try {
      return constantTimeEqual(base64Decode(expected), base64Decode(signatureB64));
    } catch {
      return false;
    }
  }

  // ---------- /refresh ----------

  private async refreshSecret(): Promise<Response> {
    await this.invalidateSecret();
    return jsonResp(200, { ok: true });
  }

  private async invalidateSecret(): Promise<void> {
    await this.state.storage.delete(STORAGE_KEY_BOT_SECRET);
    this.decryptedSecret = null;
  }

  // ---------- bot_secret 取得 ----------

  private async getBotSecret(botId: string): Promise<string> {
    if (this.decryptedSecret) return this.decryptedSecret;
    let enc = await this.state.storage.get<string>(STORAGE_KEY_BOT_SECRET);
    if (!enc) {
      enc = await this.fetchBotSecretEncrypted(botId);
      await this.state.storage.put(STORAGE_KEY_BOT_SECRET, enc);
    }
    this.decryptedSecret = await decryptBotSecret(enc, this.env.SSO_ENCRYPTION_KEY);
    return this.decryptedSecret;
  }

  private async fetchBotSecretEncrypted(botId: string): Promise<string> {
    const jwt = await signInternalJWT(this.env);
    const url = `${this.env.ALC_API_ORIGIN}/api/internal/lineworks/bot-secret/${encodeURIComponent(botId)}`;
    const resp = await fetch(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${jwt}` },
    });
    if (!resp.ok) {
      throw new Error(`bot-secret fetch failed: ${resp.status}`);
    }
    const body = (await resp.json()) as { bot_secret_encrypted?: string };
    if (!body.bot_secret_encrypted) {
      throw new Error("bot_secret_encrypted missing in response");
    }
    return body.bot_secret_encrypted;
  }

  // ---------- alarm: キュー drain + 再送 ----------

  async alarm(): Promise<void> {
    const items = await this.state.storage.list<QueueItem>({ prefix: QUEUE_PREFIX });
    if (items.size === 0) return;

    let nextBackoff = 0;
    for (const [key, val] of items) {
      const ok = await this.postToBackend(val);
      if (ok) {
        await this.state.storage.delete(key);
        continue;
      }
      const next: QueueItem = { ...val, attempts: val.attempts + 1 };
      if (next.attempts > MAX_ATTEMPTS) {
        console.error("lineworks_webhook_drop_after_max_attempts", { key, val: next });
        await this.state.storage.delete(key);
        continue;
      }
      await this.state.storage.put(key, next);
      // 1s, 2s, 4s, 8s, 16s, 32s, 60s (cap)
      nextBackoff = Math.min(MAX_BACKOFF_MS, 1000 * 2 ** Math.min(next.attempts - 1, 6));
      // 先頭 1 件で失敗したら、順序保持のため後続をその backoff で再試行する
      break;
    }
    if (nextBackoff > 0) {
      await this.state.storage.setAlarm(Date.now() + nextBackoff);
    }
  }

  private async postToBackend(item: QueueItem): Promise<boolean> {
    const jwt = await signInternalJWT(this.env);
    try {
      const resp = await fetch(`${this.env.ALC_API_ORIGIN}/api/internal/lineworks/event`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify(item.event),
      });
      if (!resp.ok) {
        console.warn("lineworks_webhook_backend_post_failed", {
          status: resp.status,
          attempts: item.attempts,
        });
        return false;
      }
      return true;
    } catch (e) {
      console.warn("lineworks_webhook_backend_post_throw", {
        error: String(e),
        attempts: item.attempts,
      });
      return false;
    }
  }
}

// ---------- helpers ----------

function jsonResp(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

interface RawWebhookEvent {
  type?: unknown;
  source?: {
    channelId?: unknown;
    channelType?: unknown;
    title?: unknown;
  };
}

function parseEvent(botId: string, rawBody: ArrayBuffer): WebhookEvent | null {
  let parsed: RawWebhookEvent;
  try {
    const text = new TextDecoder().decode(rawBody);
    parsed = JSON.parse(text) as RawWebhookEvent;
  } catch {
    return null;
  }
  const eventType = typeof parsed.type === "string" ? parsed.type : null;
  if (!eventType) return null;

  // join/leave 以外は ignore (200 OK 返す)
  if (
    eventType !== "join" &&
    eventType !== "joined" &&
    eventType !== "leave" &&
    eventType !== "left"
  ) {
    return null;
  }

  const src = parsed.source ?? {};
  return {
    bot_id: botId,
    event_type: eventType,
    channel_id: typeof src.channelId === "string" ? src.channelId : undefined,
    channel_type: typeof src.channelType === "string" ? src.channelType : undefined,
    title: typeof src.title === "string" ? src.title : undefined,
  };
}

/**
 * Crockford-ish ULID 軽量実装。Cloudflare Workers でも使えるよう外部依存ゼロ。
 * 厳密な ULID 仕様準拠は不要 (キーの一意性 + 時刻ソート可能性のみ重要)。
 */
function ulid(): string {
  const time = Date.now().toString(36).padStart(10, "0");
  const rand = Array.from(crypto.getRandomValues(new Uint8Array(8)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${time}-${rand}`;
}
