import { describe, it, expect } from "vitest";
import {
  buildTestPdf,
  handlePrintTestPdf,
  handlePrintTestPage,
} from "../../src/handlers/print-test";
import { createMockKV } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import type { Env } from "../../src/index";

const SECRET = "print-test-secret";
const ENV = "staging";
const ISSUER = "https://auth.ippoan.org";

function makeEnv(overrides: Record<string, unknown> = {}): Env {
  return {
    AUTH_CONFIG: createMockKV(),
    JWT_SECRET: SECRET,
    WORKER_ENV: ENV,
    ...overrides,
  } as unknown as Env;
}

async function opCookie(claims: Record<string, unknown> = {}): Promise<Record<string, string>> {
  const token = await signTestJwt(
    { tenant_id: "tenant-1", email: "op@example.com", env: ENV, ...claims },
    SECRET,
  );
  return { Cookie: `logi_auth_token=${token}` };
}

function getReq(path: string, headers: Record<string, string> = {}): Request {
  return new Request(`${ISSUER}${path}`, { method: "GET", headers });
}

describe("buildTestPdf", () => {
  it("produces a structurally valid PDF with correct xref offsets", () => {
    const now = new Date("2026-07-14T03:00:00Z");
    const bytes = buildTestPdf(now, "auth.ippoan.org");
    const text = new TextDecoder().decode(bytes);

    expect(text.startsWith("%PDF-1.4\n")).toBe(true);
    expect(text.endsWith("%%EOF\n")).toBe(true);
    expect(text).toContain("ALC PRINT TEST");
    expect(text).toContain("2026-07-14T03:00:00.000Z");
    expect(text).toContain("auth.ippoan.org");

    // xref のオフセットが実際のオブジェクト位置と一致する (壊れた PDF を
    // 配らないための構造検証)
    const xrefAt = Number(text.match(/startxref\n(\d+)\n/)?.[1]);
    expect(text.slice(xrefAt, xrefAt + 4)).toBe("xref");
    const entries = [...text.matchAll(/^(\d{10}) 00000 n /gm)].map((m) => Number(m[1]));
    expect(entries).toHaveLength(5);
    entries.forEach((off, i) => {
      expect(text.slice(off, off + String(i + 1).length + 6)).toBe(`${i + 1} 0 obj`);
    });

    // /Length が content stream の実バイト数と一致する
    const len = Number(text.match(/\/Length (\d+) /)?.[1]);
    const stream = text.match(/stream\n([\s\S]*?)\nendstream/)?.[1] ?? "";
    expect(stream.length).toBe(len);
  });

  it("escapes PDF string delimiters in host", () => {
    const bytes = buildTestPdf(new Date(0), "evil(host)\\x");
    const text = new TextDecoder().decode(bytes);
    expect(text).toContain("evil\\(host\\)\\\\x");
  });
});

describe("handlePrintTestPdf", () => {
  it("serves the PDF publicly with no-store", () => {
    const res = handlePrintTestPdf(getReq("/print/test.pdf"));
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("application/pdf");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });
});

describe("handlePrintTestPage", () => {
  it("redirects to /login when not authenticated", async () => {
    const res = await handlePrintTestPage(getReq("/device/print-test"), makeEnv());
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location") ?? "";
    expect(loc).toContain("/login");
    expect(loc).toContain(encodeURIComponent("/device/print-test"));
  });

  it("shows session error page (not a redirect) when cookie is invalid", async () => {
    const res = await handlePrintTestPage(
      getReq("/device/print-test", { Cookie: "logi_auth_token=broken" }),
      makeEnv(),
    );
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("セッションを確認できません");
  });

  it("renders the WebSerial page for a valid session", async () => {
    const res = await handlePrintTestPage(
      getReq("/device/print-test", await opCookie()),
      makeEnv(),
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("プリントテスト");
    expect(html).toContain("/print/test.pdf");
    expect(html).toContain("PRINTER ADDR");
    expect(html).toContain("op@example.com");
  });

  it("rejects a session without tenant_id", async () => {
    const res = await handlePrintTestPage(
      getReq("/device/print-test", await opCookie({ tenant_id: "", org: "" })),
      makeEnv(),
    );
    expect(res.status).toBe(403);
  });
});
