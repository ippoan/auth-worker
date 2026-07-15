/**
 * 印刷ブリッジ (AtomS3 + Atomic PoE Base、ippoan/alc-app-s3#38) のテスト支援。
 *
 *   GET /print/test.pdf — テスト用 PDF (公開)。デバイスの HTTP クライアントは
 *     認証ヘッダを付けないため認証無し。内容は生成時刻入りの 1 ページ PDF
 *     (PDF ダイレクトプリント対応プリンターの検証も兼ねる、#37)。
 *
 * WebSerial のテスト印刷 UI は `/device/setup` (device-setup.ts) の
 * 「テスト印刷」ボタンに統合済み。旧 `/device/print-test` ページは撤去した。
 */

/**
 * 生成時刻・ホスト入りの最小 1 ページ PDF を組み立てる。
 * xref のバイトオフセットを正しく計算した正規の PDF (プリンターの PDF
 * ダイレクトプリントでそのまま印字できることを狙う)。ASCII のみで構成する
 * (バイト長 = 文字列長 の前提で offset を計算するため)。
 */
export function buildTestPdf(now: Date, host: string): Uint8Array {
  // PDF 文字列リテラルのエスケープ (ASCII 前提)
  const esc = (s: string) => s.replace(/[\\()]/g, (c) => `\\${c}`);
  const lines = [
    { size: 24, y: 780, text: "ALC PRINT TEST" },
    { size: 12, y: 745, text: `Generated: ${now.toISOString()}` },
    { size: 12, y: 725, text: `Source: ${host}` },
    { size: 12, y: 705, text: "alc-app-s3 #38 print bridge (AtomS3 + PoE)" },
    { size: 10, y: 60, text: "If you can read this, PDF direct printing works." },
  ];
  const content = lines
    .map((l) => `BT /F1 ${l.size} Tf 72 ${l.y} Td (${esc(l.text)}) Tj ET`)
    .join("\n");

  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] " +
      "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    `<< /Length ${content.length} >>\nstream\n${content}\nendstream`,
  ];

  let body = "%PDF-1.4\n";
  const offsets: number[] = [];
  objects.forEach((obj, i) => {
    offsets.push(body.length);
    body += `${i + 1} 0 obj\n${obj}\nendobj\n`;
  });
  const xrefAt = body.length;
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) {
    body += `${String(off).padStart(10, "0")} 00000 n \n`;
  }
  body +=
    `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\n` +
    `startxref\n${xrefAt}\n%%EOF\n`;
  return new TextEncoder().encode(body);
}

/** GET /print/test.pdf — テスト用 PDF (公開・認証無し)。 */
export function handlePrintTestPdf(request: Request): Response {
  const host = new URL(request.url).host;
  return new Response(buildTestPdf(new Date(), host), {
    headers: {
      "Content-Type": "application/pdf",
      // 毎回生成時刻が変わるためキャッシュさせない
      "Cache-Control": "no-store",
      "Content-Disposition": 'inline; filename="alc-print-test.pdf"',
    },
  });
}
