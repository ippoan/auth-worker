/** 型定義 — 実装は jwt-core.mjs (理由はそちらの doc comment 参照) */

export declare function decodeJwtPayload(base64url: string): Record<string, unknown>

export declare function decodeJwtPayloadFromToken(token: string): Record<string, unknown>

export declare function decodeJwtClaims(token: string): {
  username?: string
  provider?: string
  orgSlug?: string
}

export declare function extractTenantIdFromAuth(
  authHeader: string | undefined,
): { authorization?: string; tenantId?: string }
