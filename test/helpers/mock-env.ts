import type { Env } from "../../src/index";
import { _clearAllowedOriginsCache } from "../../src/lib/config";
import { AlarmNonceDO } from "../../src/durable_objects/alarm-nonce-do";

/** Minimal in-memory KV mock that satisfies the methods getAllowedOrigins calls.
 *  Also supports `put` (with optional `expirationTtl`) and `delete` for MCP /
 *  device flow tests (Phase 1+).
 *
 *  テストから書込内容を直接検査したいときは `as unknown as MockKV` で cast。
 */
export interface MockKV extends KVNamespace {
  /** 直接読み出し用 (test 内で `kv._data[key]` で内容確認できる) */
  _data: Record<string, string>;
  /** put 呼び出し時に渡された expirationTtl の記録 */
  _ttls: Record<string, number>;
}

export function createMockKV(initial: Record<string, string> = {}): KVNamespace {
  const data: Record<string, string> = { ...initial };
  const ttls: Record<string, number> = {};
  const kv = {
    get: async (key: string) => data[key] ?? null,
    put: async (
      key: string,
      value: string,
      opts?: { expirationTtl?: number; expiration?: number },
    ) => {
      data[key] = value;
      if (opts?.expirationTtl !== undefined) ttls[key] = opts.expirationTtl;
    },
    delete: async (key: string) => {
      delete data[key];
      delete ttls[key];
    },
    list: async (opts?: { prefix?: string; limit?: number }) => {
      const prefix = opts?.prefix ?? "";
      const keys = Object.keys(data)
        .filter((k) => k.startsWith(prefix))
        .sort()
        .slice(0, opts?.limit ?? 1000)
        .map((name) => ({ name }));
      return { keys, list_complete: true, cacheStatus: null };
    },
    _data: data,
    _ttls: ttls,
  };
  return kv as unknown as KVNamespace;
}

/**
 * Minimal Durable Object Namespace stub for tests that don't exercise the DO.
 * Returns a stub whose `fetch()` throws — tests that actually need DO behavior
 * should construct their own mock (see test/handlers/lineworks-webhook.test.ts
 * for a full DO mock pattern).
 *
 * Cloudflare の `@cloudflare/vitest-pool-workers` を使えば実 DO 環境がもらえるが、
 * 本 repo は vanilla vitest なので、createMockKV と同じく `as unknown as ...` で
 * 最小ダミーを返す。
 */
export function createMockDONamespace(): DurableObjectNamespace {
  const stub = {
    fetch: () => {
      throw new Error("mock DO not implemented — use a per-test mock if you exercise the DO");
    },
  };
  return {
    idFromName: (name: string) => ({ name }) as unknown as DurableObjectId,
    idFromString: (s: string) => ({ name: s }) as unknown as DurableObjectId,
    newUniqueId: () => ({ name: "unique" }) as unknown as DurableObjectId,
    get: () => stub as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

/** `createMockAlarmNonceDO` が返す名前空間。中身を test から直接見られる。 */
export interface MockAlarmNonceNamespace extends DurableObjectNamespace<AlarmNonceDO> {
  /** DO の storage の中身 (`devnonce:<nonce>` → JSON、`rate:<key>` → `{minute, n}`) */
  _data: Record<string, unknown>;
  /** 設定された alarm の時刻 (未設定なら null) */
  _alarm: { at: number | null };
  /** `get` に渡された location hint */
  _hints: Array<string | undefined>;
  /** 本物の DO (alarm を直接呼ぶ用) */
  _do: AlarmNonceDO;
}

/**
 * `ALARM_NONCE_DO` の mock。storage だけを記憶上に置き、本物の `AlarmNonceDO` を
 * 直に呼ぶ (RPC の stub = DO そのもの)。全 instance で 1 つを共有する (本番も 1 つ)。
 */
export function createMockAlarmNonceDO(): MockAlarmNonceNamespace {
  const data: Record<string, unknown> = {};
  const alarm = { at: null as number | null };
  const hints: Array<string | undefined> = [];
  const storage = {
    get: async (key: string) => data[key],
    put: async (key: string, value: unknown) => {
      data[key] = value;
    },
    delete: async (keys: string | string[]) => {
      for (const k of Array.isArray(keys) ? keys : [keys]) delete data[k];
      return true;
    },
    list: async (opts: { limit?: number } = {}) =>
      new Map(Object.entries(data).slice(0, opts.limit ?? Infinity)),
    getAlarm: async () => alarm.at,
    setAlarm: async (at: number) => {
      alarm.at = at;
    },
  };
  const instance = new AlarmNonceDO({ storage } as unknown as DurableObjectState, {} as never);
  return {
    idFromName: (name: string) => ({ name }) as unknown as DurableObjectId,
    get: (_id: DurableObjectId, opts?: { locationHint?: string }) => {
      hints.push(opts?.locationHint);
      return instance;
    },
    _data: data,
    _alarm: alarm,
    _hints: hints,
    _do: instance,
  } as unknown as MockAlarmNonceNamespace;
}

/**
 * issue #155 で使う handler 経由の DO 呼び出し検査用 mock。stub.fetch を
 * `vi.fn()` で差し替え、引数の URL / method を assert できるようにする。
 * fetch 結果は `fetchImpl` で制御 (resolve / reject 両方可)。
 *
 * 返り値の `calls` で呼び出された Request 一覧を取り出せる。
 */
export function createSpyDONamespace(
  fetchImpl: (req: Request) => Promise<Response>,
): {
  ns: DurableObjectNamespace;
  calls: Request[];
} {
  const calls: Request[] = [];
  const stub = {
    fetch: async (req: Request) => {
      calls.push(req);
      return await fetchImpl(req);
    },
  };
  const ns = {
    idFromName: (name: string) => ({ name }) as unknown as DurableObjectId,
    idFromString: (s: string) => ({ name: s }) as unknown as DurableObjectId,
    newUniqueId: () => ({ name: "unique" }) as unknown as DurableObjectId,
    get: () => stub as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
  return { ns, calls };
}

const DEFAULT_ALLOWED_ORIGINS =
  "https://app1.test.example,https://app2.test.example,https://auth.test.example";

/**
 * Create a mock Env. The convenience field `allowedOrigins` populates
 * AUTH_CONFIG KV with `origins:prod` = <value>, matching the legacy
 * `ALLOWED_REDIRECT_ORIGINS` env var semantics for existing tests.
 *
 * Pass `AUTH_CONFIG` directly for full control over the KV contents.
 */
export function createMockEnv(
  overrides: Partial<Env> & { allowedOrigins?: string } = {},
): Env {
  // Reset module-level allowlist cache so each test starts fresh.
  _clearAllowedOriginsCache();
  const { allowedOrigins, AUTH_CONFIG, ...rest } = overrides;
  const effectiveAllowed = allowedOrigins ?? DEFAULT_ALLOWED_ORIGINS;
  return {
    GOOGLE_CLIENT_ID: "test-google-client-id",
    GOOGLE_CLIENT_SECRET: "test-google-client-secret",
    OAUTH_STATE_SECRET: "test-oauth-state-secret-32chars!",
    JWT_SECRET: TEST_JWT_SECRET,
    AUTH_WORKER_ORIGIN: "https://auth.test.example",
    VERSION: "test",
    WORKER_ENV: "prod",
    AUTH_CONFIG: AUTH_CONFIG ?? createMockKV({ "origins:prod": effectiveAllowed }),
    SSO_ENCRYPTION_KEY: "test-sso-encryption-key",
    LINEWORKS_WEBHOOK_DO: createMockDONamespace(),
    ALARM_NONCE_DO: createMockAlarmNonceDO(),
    ...rest,
  };
}

/** Default HS256 secret used by createMockEnv. Re-exported so tests that
 *  forge JWT cookies can sign them with the same key. */
export const TEST_JWT_SECRET = "test-jwt-secret-32chars-padding!";
