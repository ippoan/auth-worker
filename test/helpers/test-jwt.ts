/** Generate a fake JWT for testing (not cryptographically valid, but parseable) */
export function createTestJwt(
  payload: Record<string, unknown> = {},
): string {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = btoa(
    JSON.stringify({
      sub: "test-user-id",
      org: "test-org-id",
      org_slug: "test-org",
      exp: Math.floor(Date.now() / 1000) + 3600,
      ...payload,
    }),
  );
  const signature = "test-signature";
  return `${header}.${body}.${signature}`;
}
