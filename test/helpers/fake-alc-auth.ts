/**
 * alc-auth-worker (`ALC_AUTH`) の機械用資格情報の内部口 4 本をメモリ上の Map で再現する fake
 * (Refs ohishi-exp/rust-leave-worker#1)。`src/lib/machine-credential.ts` のテスト用。
 *
 * 再現する形 (ippoan/alc-auth-worker と同じ):
 *   - 共有 secret の不一致は、どの口でも、当たらない path でも 404 で本文は空
 *   - `POST /internal/machine-credentials` → 201 `{}` / 400 / 404 `tenant_not_found` / 409 `username_taken`
 *   - `GET /internal/machine-credentials?tenant_id=&purpose=` → 200 `{credentials}` (created_at → username の昇順)
 *   - `POST /internal/machine-credentials/<username>/revoke` {tenant_id} → 200 `{revoked:true}` / 404 `not_found`
 *   - `GET /internal/machine-credentials/<username>` → 200 `{tenant_id,purpose,secret_hash,revoked}` / 404 `not_found`
 */

/** テスト固有のダミー値 (本番の値ではない)。 */
export const FAKE_ALC_AUTH_SECRET = "test-internal-shared-secret-for-alc-auth";

export interface FakeMachineCredentialRow {
  username: string;
  tenant_id: string;
  purpose: string;
  label: string;
  secret_hash: string;
  created_at: string;
  revoked: boolean;
}

export interface FakeAlcAuthCall {
  method: string;
  url: string;
  headers: Headers;
  body: string;
}

export interface FakeAlcAuth {
  fetcher: Fetcher;
  /** username → 行 (DB の表の代わり)。テストから直に読み書きしてよい。 */
  rows: Map<string, FakeMachineCredentialRow>;
  /** 受けた要求の記録。 */
  calls: FakeAlcAuthCall[];
}

export interface FakeAlcAuthOptions {
  /** 受ける共有 secret (既定 `FAKE_ALC_AUTH_SECRET`)。 */
  secret?: string;
  /** 在る会社の一覧。渡すと、無い tenant の作成は 404 `tenant_not_found`。省略時はどの tenant も在る扱い。 */
  tenants?: string[];
  /** 返すと、その応答で口の処理を置き換える (5xx・壊れた JSON 等の再現用)。 */
  override?: (req: Request) => Response | undefined;
}

const USERNAME_RE = /^mc_[0-9a-f]{16}$/;
const HASH_RE = /^[0-9a-f]{64}$/;

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

export function createFakeAlcAuth(opts: FakeAlcAuthOptions = {}): FakeAlcAuth {
  const secret = opts.secret ?? FAKE_ALC_AUTH_SECRET;
  const rows = new Map<string, FakeMachineCredentialRow>();
  const calls: FakeAlcAuthCall[] = [];

  async function handle(req: Request, text: string): Promise<Response> {
    if (req.headers.get("X-Internal-Shared-Secret") !== secret) return new Response(null, { status: 404 });
    const url = new URL(req.url);
    const m = /^\/internal\/machine-credentials(?:\/([^/]+)(\/revoke)?)?$/.exec(url.pathname);
    if (!m) return new Response(null, { status: 404 });
    const [, username, revoke] = m;

    if (!username && req.method === "POST") {
      let b: Record<string, unknown>;
      try {
        b = JSON.parse(text) as Record<string, unknown>;
      } catch {
        return json(400, { error: "invalid_body" });
      }
      if (typeof b.username !== "string" || !USERNAME_RE.test(b.username)) return json(400, { error: "invalid_username" });
      if (typeof b.tenant_id !== "string" || !b.tenant_id) return json(400, { error: "invalid_tenant_id" });
      if (typeof b.purpose !== "string" || !b.purpose) return json(400, { error: "invalid_purpose" });
      if (typeof b.label !== "string" || !b.label) return json(400, { error: "invalid_label" });
      if (typeof b.secret_hash !== "string" || !HASH_RE.test(b.secret_hash)) return json(400, { error: "invalid_secret_hash" });
      if (opts.tenants && !opts.tenants.includes(b.tenant_id)) return json(404, { error: "tenant_not_found" });
      if (rows.has(b.username)) return json(409, { error: "username_taken" });
      rows.set(b.username, {
        username: b.username,
        tenant_id: b.tenant_id,
        purpose: b.purpose,
        label: b.label,
        secret_hash: b.secret_hash,
        created_at: new Date().toISOString(),
        revoked: false,
      });
      return json(201, {});
    }

    if (!username && req.method === "GET") {
      const tenant = url.searchParams.get("tenant_id");
      if (!tenant) return json(400, { error: "invalid_tenant_id" });
      const purpose = url.searchParams.get("purpose");
      const credentials = [...rows.values()]
        .filter((r) => r.tenant_id === tenant && (purpose === null || r.purpose === purpose))
        .sort((a, b) => a.created_at.localeCompare(b.created_at) || a.username.localeCompare(b.username))
        .map(({ username: u, purpose: p, label, created_at, revoked }) => ({ username: u, purpose: p, label, created_at, revoked }));
      return json(200, { credentials });
    }

    if (username && revoke && req.method === "POST") {
      if (!USERNAME_RE.test(username)) return json(404, { error: "not_found" });
      let tenant: unknown;
      try {
        tenant = (JSON.parse(text) as { tenant_id?: unknown }).tenant_id;
      } catch {
        return json(400, { error: "invalid_body" });
      }
      const row = rows.get(username);
      if (!row || row.tenant_id !== tenant) return json(404, { error: "not_found" });
      row.revoked = true;
      return json(200, { revoked: true });
    }

    if (username && !revoke && req.method === "GET") {
      if (!USERNAME_RE.test(username)) return json(404, { error: "not_found" });
      const row = rows.get(username);
      if (!row) return json(404, { error: "not_found" });
      return json(200, { tenant_id: row.tenant_id, purpose: row.purpose, secret_hash: row.secret_hash, revoked: row.revoked });
    }

    return new Response(null, { status: 404 });
  }

  const fetcher = {
    fetch: async (input: Request) => {
      const text = input.body ? await input.text() : "";
      calls.push({ method: input.method, url: input.url, headers: input.headers, body: text });
      return opts.override?.(input) ?? handle(input, text);
    },
  } as unknown as Fetcher;

  return { fetcher, rows, calls };
}
