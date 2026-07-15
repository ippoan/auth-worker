import { describe, it, expect } from "vitest";
import { buildTestPdf, handlePrintTestPdf } from "../../src/handlers/print-test";

const ISSUER = "https://auth.ippoan.org";

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
