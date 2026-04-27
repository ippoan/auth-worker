import type { Env } from "../../src/index";
import { _clearAllowedOriginsCache } from "../../src/lib/config";

/** Minimal in-memory KV mock that satisfies the methods getAllowedOrigins calls. */
export function createMockKV(data: Record<string, string> = {}): KVNamespace {
  return {
    get: async (key: string) => data[key] ?? null,
  } as unknown as KVNamespace;
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
    ...rest,
  };
}

/** Default HS256 secret used by createMockEnv. Re-exported so tests that
 *  forge JWT cookies can sign them with the same key. */
export const TEST_JWT_SECRET = "test-jwt-secret-32chars-padding!";
