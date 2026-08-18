/**
 * Cloudflare Access 向け OIDC surface (`/oidc/*`) の client レジストリ。
 *
 * ## なぜ DCR ではなく静的設定なのか
 *
 * 既存の MCP surface は DCR (RFC 7591) + public client (`token_endpoint_auth_methods_
 * supported: ["none"]`) で、client_secret を持たない前提で組んである。一方 Access は
 * **client_secret を持つ confidential client** として登録され、しかも「管理画面で 1 回
 * 設定して数年動かす」種類の client なので、動的登録の利点が無い。DCR で発行した
 * public client を Access に流用すると secret 無しで token endpoint を叩ける client が
 * 公開されることになり、逆に危ない。よってこの surface は静的レジストリにする。
 *
 * ## 形式
 *
 * Secrets Store の 1 entry に client の JSON 配列を入れる:
 *
 *   [ { "client_id": "cf-access",
 *       "client_secret": "…",
 *       "redirect_uris": ["https://<team>.cloudflareaccess.com/cdn-cgi/access/callback"],
 *       "name": "cloudflare-access" } ]
 *
 * 複数 client を並べられるので、Access のチーム追加や別サービス (Access 以外の
 * confidential client) もここに足すだけで済む。
 */
import { resolveSecret, type SecretBinding } from "./secret";

export interface OidcClient {
  client_id: string;
  client_secret: string;
  /** 完全一致で照合する。前方一致にすると別 path へ code を渡せてしまうため。 */
  redirect_uris: string[];
  /** 運用上の識別名 (ログ・監査用)。認証には使わない。 */
  name?: string;
}

function isOidcClient(value: unknown): value is OidcClient {
  if (typeof value !== "object" || value === null) return false;
  const c = value as Record<string, unknown>;
  if (typeof c.client_id !== "string" || c.client_id === "") return false;
  if (typeof c.client_secret !== "string" || c.client_secret === "") return false;
  if (!Array.isArray(c.redirect_uris) || c.redirect_uris.length === 0) return false;
  return c.redirect_uris.every((u) => typeof u === "string" && u !== "");
}

/**
 * 生文字列 → client 配列。**1 つでも不正なら全体を `null`** (fail-closed)。
 * 壊れた entry を読み飛ばすと「登録したはずの client だけ無言で 401」という
 * 追いにくい形になるため、設定ミスは surface ごと 503 にして気付かせる。
 */
export function parseOidcClients(raw: string): OidcClient[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  const list = Array.isArray(parsed) ? parsed : [parsed];
  if (list.length === 0) return null;
  const clients: OidcClient[] = [];
  for (const item of list) {
    if (!isOidcClient(item)) return null;
    clients.push(item);
  }
  return clients;
}

/** binding (Secrets Store / plain string) → client 配列。未設定・壊れは `null`。 */
export async function resolveOidcClients(
  binding: SecretBinding,
): Promise<OidcClient[] | null> {
  const raw = await resolveSecret(binding);
  if (!raw) return null;
  return parseOidcClients(raw);
}

/** client_id で引く。未登録は `null`。 */
export function findOidcClient(
  clients: OidcClient[],
  clientId: string,
): OidcClient | null {
  return clients.find((c) => c.client_id === clientId) ?? null;
}

/**
 * redirect_uri が登録済みか (**完全一致**、RFC 6749 §3.1.2.3)。
 * query や fragment を足した変種を許すと、code を意図しない先へ渡せる。
 */
export function isRegisteredRedirectUri(client: OidcClient, redirectUri: string): boolean {
  return client.redirect_uris.includes(redirectUri);
}

/**
 * client_secret の照合。長さで早期 return せず、**常に全長を走査**してから
 * 結果を返す (先に長さで分岐すると、その分岐自体が長さの oracle になる)。
 */
export function verifyClientSecret(client: OidcClient, presented: string): boolean {
  const expected = client.client_secret;
  let diff = expected.length ^ presented.length;
  const len = Math.max(expected.length, presented.length);
  for (let i = 0; i < len; i++) {
    diff |= (expected.charCodeAt(i) || 0) ^ (presented.charCodeAt(i) || 0);
  }
  return diff === 0;
}
