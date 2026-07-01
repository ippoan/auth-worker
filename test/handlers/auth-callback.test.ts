import { describe, it, expect } from "vitest";
import { handleAuthCallback } from "../../src/handlers/auth-callback";

describe("handleAuthCallback", () => {
  it("returns 200 HTML that lands on fixed /top", async () => {
    const res = handleAuthCallback();
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    const body = await res.text();
    expect(body).toContain('window.location.replace("/top")');
  });

  it("does not read or plant the fragment token (no cookie write, no token read)", async () => {
    const res = handleAuthCallback();
    const body = await res.text();
    // セキュリティ: fragment token を読まない / cookie に書かない (session fixation / XSS 回避)。
    expect(body).not.toContain("document.cookie");
    expect(body).not.toContain("logi_auth_token");
    expect(body).not.toContain("params.get");
    expect(body).not.toContain("location.hash");
  });

  it("does not reflect any user input (static script, fixed dest)", async () => {
    const res = handleAuthCallback();
    const body = await res.text();
    // 遷移先は固定 /top。?to= 等の反射なし (open-redirect / XSS 回避)。
    expect(body).not.toContain("searchParams");
    expect(body).not.toContain("var dest");
  });
});
