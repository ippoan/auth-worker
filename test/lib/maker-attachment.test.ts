// 認定申請の添付資料 (外観図・構造図・システム図)。写真・図は架空。
import { describe, it, expect, vi } from "vitest";
import { attachmentCsp, buildAttachment, parsePhotos } from "../../src/lib/maker-attachment";
import { TENKO_FORMS_RAW, type ProductConfig } from "../../src/lib/maker-certification";

const CFG: ProductConfig = { product: "一歩庵点呼", version: "v2" };
const FIG = (name: string) => `<h1>{機器の名称}　${name}</h1><div class="sub">製作事業者：{製作事業者名}</div><svg></svg>`;

function fetcher(photos: string | Response = '{"photos":[]}', figure: Response | null = null) {
  return vi.fn(async (url: string) => {
    if (url.endsWith("product/photos/index.json")) return typeof photos === "string" ? new Response(photos) : photos;
    if (figure) return figure;
    return new Response(FIG(url.includes("structure") ? "構造図" : "システム図"));
  }) as unknown as typeof fetch;
}

describe("写真の一覧", () => {
  it("英数字・-・_・. の画像のファイルだけ読み、見出しと日付を取る", () => {
    expect(
      parsePhotos({
        photos: [
          { file: "2026-11-10-set.jpg", caption: "点呼端末一式", date: "2026-11-10" },
          { file: "a.PNG" },
          { file: "../x.jpg", caption: "外へ出る" },
          { file: ".hidden.jpg" },
          { file: "x.svg" },
          { file: 1 },
          null,
        ],
      }),
    ).toEqual([
      { file: "2026-11-10-set.jpg", caption: "点呼端末一式", date: "2026-11-10" },
      { file: "a.PNG", caption: "", date: null },
    ]);
    expect(() => parsePhotos({})).toThrow("photos が要ります");
    expect(() => parsePhotos(null)).toThrow("photos が要ります");
  });
});

describe("添付資料の HTML", () => {
  it("写真が無ければ「写真未登録」、構造図・システム図の名称と製作事業者を置き換える (HTML は逃がす)", async () => {
    const f = fetcher();
    const html = await buildAttachment(CFG, "架空<製作所>", "n0nce", f);
    expect(html).toContain("一歩庵点呼 v2　外観図");
    expect(html).toContain('<div class="empty">写真未登録</div>');
    expect(html).toContain("一歩庵点呼 v2　構造図");
    expect(html).toContain("一歩庵点呼 v2　システム図");
    expect(html).toContain("製作事業者：架空&lt;製作所&gt;");
    expect(html).not.toContain("{機器の名称}");
    expect(html.match(/<div class="page">/g)).toHaveLength(3);
    expect(html).toContain('<script nonce="n0nce">');
    expect(vi.mocked(f).mock.calls.map((c) => c[0])).toEqual([
      `${TENKO_FORMS_RAW}product/photos/index.json`,
      `${TENKO_FORMS_RAW}product/figures/structure.html`,
      `${TENKO_FORMS_RAW}product/figures/system.html`,
    ]);
    expect(await buildAttachment(CFG, null, "n", fetcher())).toContain("製作事業者：</div>");
  });

  it("写真を raw の URL で並べ、見出しと撮影日を付ける", async () => {
    const photos = JSON.stringify({ photos: [{ file: "a.jpg", caption: "制御装置 <CoreS3>", date: "2026-11-10" }, { file: "b.png", caption: "体温計" }] });
    const html = await buildAttachment(CFG, "x", "n", fetcher(photos));
    expect(html).toContain(`<img src="${TENKO_FORMS_RAW}product/photos/a.jpg" alt="制御装置 &lt;CoreS3&gt;">`);
    expect(html).toContain("<figcaption>制御装置 &lt;CoreS3&gt;<span>（2026-11-10 撮影）</span></figcaption>");
    expect(html).toContain("<figcaption>体温計</figcaption>");
    expect(html).not.toContain("写真未登録");
  });

  it("取れない・読めないときは理由を添えて例外", async () => {
    await expect(buildAttachment(CFG, "x", "n", fetcher(new Response("", { status: 404 })))).rejects.toThrow(
      "product/photos/index.json を取得できませんでした (404)",
    );
    await expect(buildAttachment(CFG, "x", "n", fetcher("{"))).rejects.toThrow("JSON として読めません");
    await expect(buildAttachment(CFG, "x", "n", fetcher('{"x":1}'))).rejects.toThrow("photos が要ります");
    await expect(buildAttachment(CFG, "x", "n", fetcher(undefined, new Response("", { status: 503 })))).rejects.toThrow(
      "product/figures/structure.html を取得できませんでした (503)",
    );
  });

  it("CSP は nonce の付いた script・raw の画像・Google Fonts だけ", () => {
    const csp = attachmentCsp("abc");
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'nonce-abc'");
    expect(csp).toContain("img-src https://raw.githubusercontent.com");
    expect(csp).not.toContain("unsafe-eval");
  });
});
