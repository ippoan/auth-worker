/**
 * 認定申請の添付資料 (様式2 の注 2「外観図、構造図、システム図を示した資料」) を A4 横 3 ページの HTML に組む。
 * ブラウザの印刷で PDF に保存して添付する (開発者専用ページ `/maker/certification/attachment`)。
 *
 * - 1 ページ目 外観図: ippoan/tenko-forms の `product/photos/index.json` の写真を並べ、見出しを付ける (無ければ「写真未登録」)
 * - 2 ページ目 構造図・3 ページ目 システム図: `product/figures/structure.html`・`system.html` (1 ページぶんの部品) をそのまま入れる
 *
 * 部品の `{機器の名称}`・`{製作事業者名}` は版の付いた名称と申請者の名称に置き換える (public repo に申請者を書かないため)。
 * 部品の中の script は動かさない (応答の CSP が nonce の付いた script だけを通す)。
 */
import { escapeHtml } from "./html";
import { TENKO_FORMS_RAW, deviceName, type ProductConfig } from "./maker-certification";

export const PHOTOS_PATH = "product/photos/";
export const FIGURES = [
  ["structure", "構造図"],
  ["system", "システム図"],
] as const;

export interface Photo {
  file: string;
  caption: string;
  date: string | null;
}

/** 写真の一覧を読む。ファイル名が英数字・`-`・`_`・`.` で画像の拡張子のものだけ */
export function parsePhotos(body: unknown): Photo[] {
  const list = (body as { photos?: unknown } | null)?.photos;
  if (!Array.isArray(list)) throw new Error("写真の一覧の形が想定と違います (photos が要ります)");
  return list.flatMap((p) => {
    const { file, caption, date } = (p ?? {}) as Record<string, unknown>;
    if (typeof file !== "string" || !/^[\w.-]+\.(jpe?g|png|webp)$/i.test(file) || file.startsWith(".")) return [];
    return [{ file, caption: typeof caption === "string" ? caption : "", date: typeof date === "string" ? date : null }];
  });
}

async function fetchText(path: string, fetcher: typeof fetch): Promise<string> {
  const res = await fetcher(`${TENKO_FORMS_RAW}${path}`, { cf: { cacheTtl: 0 } } as RequestInit);
  if (!res.ok) throw new Error(`${path} を取得できませんでした (${res.status})`);
  return res.text();
}

function photosPage(cfg: ProductConfig, photos: Photo[]): string {
  const body = photos.length
    ? `<div class="photos">${photos
        .map(
          (p) =>
            `<figure><img src="${escapeHtml(`${TENKO_FORMS_RAW}${PHOTOS_PATH}${p.file}`)}" alt="${escapeHtml(p.caption)}">` +
            `<figcaption>${escapeHtml(p.caption)}${p.date ? `<span>（${escapeHtml(p.date)} 撮影）</span>` : ""}</figcaption></figure>`,
        )
        .join("")}</div>`
    : `<div class="empty">写真未登録</div>`;
  return `<h1>${escapeHtml(deviceName(cfg))}　外観図</h1><div class="sub">点呼端末一式の実機の写真</div>${body}`;
}

/** 添付資料の HTML。`nonce` は印刷ボタンの script に付ける (CSP と同じ値) */
export async function buildAttachment(
  cfg: ProductConfig,
  makerName: string | null,
  nonce: string,
  fetcher: typeof fetch = fetch,
): Promise<string> {
  const [photosJson, ...figures] = await Promise.all([
    fetchText(`${PHOTOS_PATH}index.json`, fetcher),
    ...FIGURES.map(([id]) => fetchText(`product/figures/${id}.html`, fetcher)),
  ]);
  let photos: Photo[];
  try {
    photos = parsePhotos(JSON.parse(photosJson));
  } catch (e) {
    throw e instanceof SyntaxError ? new Error("写真の一覧が JSON として読めません") : e;
  }
  const fill = (html: string) =>
    html.replaceAll("{機器の名称}", escapeHtml(deviceName(cfg))).replaceAll("{製作事業者名}", escapeHtml(makerName ?? ""));
  const pages = [photosPage(cfg, photos), ...figures.map(fill)];
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(deviceName(cfg))} 添付資料 (外観図・構造図・システム図)</title>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;700&display=block" rel="stylesheet">
<style>
@page { size: A4 landscape; margin: 12mm; }
body { font-family: 'Noto Sans JP', sans-serif; margin: 0; color: #111; }
.page { page-break-after: always; }
.page:last-child { page-break-after: auto; }
h1 { font-size: 16pt; margin: 0 0 2mm; }
.sub { font-size: 9pt; color: #444; margin-bottom: 3mm; }
svg { display:block; height: 145mm; width: auto; margin: 0 auto; }
svg text { font-family: 'Noto Sans JP', sans-serif; }
.note { font-size: 8.5pt; color: #333; margin-top: 2mm; line-height: 1.5; }
.photos { display: grid; grid-template-columns: repeat(auto-fit, minmax(80mm, 1fr)); gap: 4mm; }
figure { margin: 0; break-inside: avoid; }
figure img { width: 100%; max-height: 120mm; object-fit: contain; border: 1px solid #ccc; }
figcaption { font-size: 10pt; font-weight: 700; margin-top: 1mm; }
figcaption span { font-weight: 400; color: #555; font-size: 9pt; }
.empty { border: 1px dashed #999; height: 120mm; display: flex; align-items: center; justify-content: center; font-size: 20pt; color: #888; }
.toolbar { position: sticky; top: 0; background: #f1f5f9; padding: 8px 12px; font-size: 14px; display: flex; gap: 12px; align-items: center; }
.toolbar button { background: #2563eb; color: #fff; border: 0; border-radius: 6px; padding: 6px 14px; font-size: 14px; cursor: pointer; }
@media screen { .page { max-width: 277mm; margin: 12px auto; padding: 12mm; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,.15); } body { background: #e2e8f0; } }
@media print { .toolbar { display: none; } }
</style></head><body>
<div class="toolbar"><button type="button" id="print">印刷 / PDF に保存</button><span>印刷の画面で「PDF に保存」・用紙 A4 横を選びます</span></div>
${pages.map((p) => `<div class="page">\n${p}\n</div>`).join("\n")}
<script nonce="${nonce}">document.getElementById("print").addEventListener("click", () => window.print());</script>
</body></html>`;
}

/** 添付資料の応答の CSP。画像は tenko-forms の raw、字体は Google Fonts、script は nonce の付いたものだけ */
export function attachmentCsp(nonce: string): string {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    "style-src 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src https://raw.githubusercontent.com",
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");
}
