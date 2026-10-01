import { describe, it, expect } from "vitest";
import { createAccessToken } from "../../src/lib/access-token";
import { verifyJwt } from "../../src/lib/jwt";

const SECRET = "access-token-test-secret";
const USER = { id: "user-1", email: "op@example.com", name: "Op", tenant_id: "tenant-a", role: "admin" };

describe("createAccessToken の idp claim (Refs ippoan/alc-app#387)", () => {
  it("第 5 引数なし: payload に idp の key が無い (既存 3 経路の token は変わらない)", async () => {
    const token = await createAccessToken(USER, SECRET, "org-a");
    const payload = await verifyJwt(token, SECRET, "prod");
    expect(payload).not.toBeNull();
    expect(payload).not.toHaveProperty("idp");
    expect(Object.keys(payload!).sort()).toEqual(
      ["email", "exp", "iat", "name", "org_slug", "role", "sub", "tenant_id"].sort(),
    );
  });

  it("\"google\" を渡すと idp: \"google\" が載る (ほかの claim は同じ)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const plain = await verifyJwt(await createAccessToken(USER, SECRET, null, now), SECRET, "prod");
    const google = await verifyJwt(
      await createAccessToken(USER, SECRET, null, now, "google"),
      SECRET,
      "prod",
    );
    expect(google!.idp).toBe("google");
    expect(google).toEqual({ ...plain, idp: "google" });
  });
});
