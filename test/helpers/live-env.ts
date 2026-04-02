/**
 * auth-worker container テスト環境
 *
 * ALC_API_URL 設定時 → rust-alc-api に直接 fetch (live)
 * 未設定 → テストスキップ
 *
 * Usage:
 *   docker compose -f docker-compose.test.yml up -d
 *   ALC_API_URL=http://localhost:18081 npm test -- test/live/
 *   docker compose -f docker-compose.test.yml down
 */
import { createHmac } from "node:crypto";

export const ALC_API_URL = process.env.ALC_API_URL || "";
export const isLive = !!ALC_API_URL;

// seed.sql と一致
export const TEST_TENANT_ID = "11111111-1111-1111-1111-111111111111";
export const TEST_USER_ID = "22222222-2222-2222-2222-222222222222";
export const JWT_SECRET = "test-jwt-secret-for-integration";

export const DEL_INVITATION_ID = "dddddddd-0001-0001-0001-dddddddddddd";
export const DEL_USER_ID = "dddddddd-0002-0002-0002-dddddddddddd";

/** HS256 JWT — rust-alc-api の require_jwt ミドルウェアが検証する */
export function makeJwt(): string {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: TEST_USER_ID,
    email: "test@example.com",
    name: "Test Admin",
    tenant_id: TEST_TENANT_ID,
    role: "admin",
    iat: now,
    exp: now + 3600,
  };
  const b64 = (obj: unknown) =>
    Buffer.from(JSON.stringify(obj)).toString("base64url");
  const unsigned = `${b64(header)}.${b64(payload)}`;
  const sig = createHmac("sha256", JWT_SECRET)
    .update(unsigned)
    .digest("base64url");
  return `${unsigned}.${sig}`;
}

/** API が起動するまでポーリング */
export async function waitForApi(maxRetries = 30): Promise<void> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const res = await fetch(`${ALC_API_URL}/api/health`);
      if (res.ok) return;
    } catch {
      // not ready
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`API not ready after ${maxRetries} retries at ${ALC_API_URL}`);
}

/** 認証付き fetch ヘルパー */
export async function apiFetch(
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const token = makeJwt();
  return fetch(`${ALC_API_URL}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...init.headers,
    },
  });
}
