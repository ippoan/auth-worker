import type { Env } from "../../src/index";
import { _clearAllowedOriginsCache } from "../../src/lib/config";

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
    ALC_API_ORIGIN: "https://alc-api.test.example",
    VERSION: "test",
    WORKER_ENV: "prod",
    AUTH_CONFIG: AUTH_CONFIG ?? createMockKV({ "origins:prod": effectiveAllowed }),
    SSO_ENCRYPTION_KEY: "test-sso-encryption-key",
    LINEWORKS_WEBHOOK_DO: createMockDONamespace(),
    ...rest,
  };
}

/** Default HS256 secret used by createMockEnv. Re-exported so tests that
 *  forge JWT cookies can sign them with the same key. */
export const TEST_JWT_SECRET = "test-jwt-secret-32chars-padding!";
