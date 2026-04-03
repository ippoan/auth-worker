import type { Env } from "../../src/index";

export function createMockEnv(overrides: Partial<Env> = {}): Env {
  return {
    GOOGLE_CLIENT_ID: "test-google-client-id",
    GOOGLE_CLIENT_SECRET: "test-google-client-secret",
    OAUTH_STATE_SECRET: "test-oauth-state-secret-32chars!",
    AUTH_WORKER_ORIGIN: "https://auth.test.example",
    ALLOWED_REDIRECT_ORIGINS:
      "https://app1.test.example,https://app2.test.example,https://auth.test.example",
    ALC_API_ORIGIN: "https://alc-api.test.example",
    ...overrides,
  };
}
