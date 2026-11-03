// 一歩庵点呼の認定申請の様式への差し込み。様式は位置だけ本物に合わせた合成の docx で、値は架空。
import { describe, it, expect, vi } from "vitest";
import { strFromU8, strToU8, unzipSync, zipSync } from "fflate";
import { DocxBody, fillDocx } from "../../src/lib/docx-fill";
import {
  MAKER_FORMS,
  applicantStreet,
  TENKO_FORMS_RAW,
  PRODUCT_PATH,
  buildMakerForm,
  certifiedLabel,
  deviceName,
  emptyApplicant,
  fetchProduct,
  fillSelfCheck,
  fillYoshiki1,
  fillYoshiki2,
  fillYoshiki5,
  fillYoshiki7,
  loadApplicant,
  parseApplicant,
  reiwaDate,
  saveApplicant,
  selfCheckKey,
  type Applicant,
  type ProductConfig,
} from "../../src/lib/maker-certification";
import { createMockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"';
type Child = string | string[][][];

/** 段落 (文字列。'|' で run を分ける。'' は run の無い段落) と表 (行 → 列 → 段落) を並べた document.xml */
function documentXml(children: Child[]): string {
  const p = (t: string) =>
    t
      ? `<w:p>${t
          .split("|")
          .map((x) => `<w:r><w:t>${x}</w:t></w:r>`)
          .join("")}</w:p>`
      : '<w:p><w:pPr><w:rPr><w:sz w:val="21"/></w:rPr></w:pPr></w:p>';
  const body = children.map((c) =>
    typeof c === "string"
      ? p(c)
      : `<w:tbl>${c.map((row) => `<w:tr>${row.map((cell) => `<w:tc>${cell.map(p).join("")}</w:tc>`).join("")}</w:tr>`).join("")}</w:tbl>`,
  );
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document ${W}><w:body>${body.join("")}</w:body></w:document>`;
}
const docx = (children: Child[]) => zipSync({ "word/document.xml": strToU8(documentXml(children)) });
const bodyOf = (b: Uint8Array) => new DocxBody(strFromU8(unzipSync(b)["word/document.xml"]!));
const run = (children: Child[], f: (b: DocxBody) => void) => bodyOf(fillDocx(docx(children), f));
const text = (b: DocxBody, i: number) => DocxBody.text(b.child(i));
/** 段落の行 (<w:br/> で分けた文) */
const lines = (b: DocxBody, i: number) => {
  const out = [""];
  const walk = (n: { childNodes?: ArrayLike<{ localName?: string | null; textContent?: string | null; childNodes?: unknown }> }) => {
    for (const c of Array.from(n.childNodes ?? [])) {
      if (c.localName === "br") out.push("");
      else if (c.localName === "t") out[out.length - 1] += c.textContent ?? "";
      else walk(c as never);
    }
  };
  walk(b.child(i) as never);
  return out;
};
const cell = (b: DocxBody, t: number, r: number, c: number, p = 0) => DocxBody.text(b.cellPara(b.table(t), r, c, p));

const A: Applicant = {
  name: "架空製作所",
  kana: "カクウセイサクショ",
  postal_code: "000-0000",
  prefecture: "架空県",
  city: "架空市",
  street: "9-9",
  building: null,
  contact_name: "架空 次郎",
  contact_dept: "開発部",
  contact_phone: "000-1111-2222",
  contact_fax: "000-1111-3333",
  contact_email: "dev@example.com",
};
const CFG: ProductConfig = {
  product: "一歩庵点呼",
  version: "v2",
  product_url: "https://example.com/tenko",
  certification: { pre: "前-0001", post: "後-0002" },
  history: [
    { version: "v2", date: "2027-04-01", summary: "体温計を足す", impact: "なし" },
    { version: "v1", date: null, summary: "初版", impact: null },
  ],
  self_check: {
    pre: { 一: { ok: "適", detail: "点呼の画面で確認する", evidence: "取扱説明書 p.3" }, ア: { ok: "適" } },
    post: {},
  },
  discontinue: { date: "2028-03-31", reason: "後継機へ移るため" },
};

describe("値の道具", () => {
  it("名称・認定番号・日付", () => {
    expect(deviceName(CFG)).toBe("一歩庵点呼 v2");
    expect(deviceName(CFG, "v1")).toBe("一歩庵点呼 v1");
    expect(certifiedLabel(CFG, "v1")).toBe("一歩庵点呼 v1（認定番号 業務前 前-0001・業務後 後-0002）");
    expect(certifiedLabel({ ...CFG, certification: { pre: null, post: "後-1" } })).toBe("一歩庵点呼 v2（認定番号 業務後 後-1）");
    expect(certifiedLabel({ product: "x", version: "v1" })).toBe("x v1");
    expect(reiwaDate("2026-11-03")).toBe("令和8年11月3日");
    expect(reiwaDate("2018-01-01")).toBe("令和　　年　　月　　日");
    expect(reiwaDate(null)).toBe("令和　　年　　月　　日");
  });

  it("申請者の本文は知らない欄を捨て、空白を落とし、型や長さが外れたら null", () => {
    expect(parseApplicant({ name: " 架空 ", kana: "", extra: 1, address: null })).toEqual({ ...emptyApplicant(), name: "架空" });
    expect(parseApplicant({ name: 1 })).toBeNull();
    expect(parseApplicant({ name: "あ".repeat(501) })).toBeNull();
    expect(parseApplicant(null)).toBeNull();
    expect(parseApplicant("x")).toBeNull();
  });

  it("都道府県から建物名までをつなぐ", () => {
    expect(applicantStreet(A)).toBe("架空県架空市9-9");
    expect(applicantStreet({ ...A, building: "架空ビル 2F" })).toBe("架空県架空市9-9　架空ビル 2F");
    expect(applicantStreet(emptyApplicant())).toBeNull();
  });

  it("自己チェック表の項目の key", () => {
    expect(selfCheckKey(" 二十三 ")).toBe("二十三");
    expect(selfCheckKey("（ア）事業者用の取扱説明書等")).toBe("ア");
  });
});

describe("申請者の KV", () => {
  it("環境ごとの key に保存し、無い・壊れた値は空にする", async () => {
    const kv = createMockKV();
    const env = { AUTH_CONFIG: kv, WORKER_ENV: "staging" } as unknown as Env;
    expect(await loadApplicant(env)).toEqual(emptyApplicant());
    await saveApplicant(env, A);
    expect(await kv.get("maker-certification:applicant:staging")).toBe(JSON.stringify(A));
    expect(await loadApplicant(env)).toEqual(A);
    expect(await loadApplicant({ AUTH_CONFIG: kv, WORKER_ENV: "" } as unknown as Env)).toEqual(emptyApplicant());
    await kv.put("maker-certification:applicant:staging", "{");
    expect(await loadApplicant(env)).toEqual(emptyApplicant());
    await kv.put("maker-certification:applicant:staging", '{"name":1}');
    expect(await loadApplicant(env)).toEqual(emptyApplicant());
  });
});

const YOSHIKI1: Child[] = [
  "（様式１）　　|令和|　|　|年　　月　　日", "", "国土交通省", "安全政策課長　殿", "申請者|　|住所", "氏名又は名称", "", "", "申請書", "", "本文", "", "記", "", "１．",
  [
    [["申請者"], ["（フリガナ）"]],
    [[""], ["", ""]],
    [["住　所"], ["〒", ""]],
    [["連絡先"], ["担当者名"]],
    [[""], ["所属・役職"]],
    [[""], ["電話番号"]],
    [[""], ["メールアドレス"]],
  ],
  "", "２．",
  [
    [["機器の種類"], ["業務前自動点呼機器　・　業務後自動点呼機器"]],
    [["名称"], [""]],
    [["添付"], ["（　　）１．", "（　　）２．", "（　　）３．", "（　　）４．", "（　　）５.", "（　　）６．", "（　　）７."]],
  ],
];

describe("様式1・様式2", () => {
  it("様式1: 日付・申請者・機器の種類・名称・添付 1〜6", () => {
    const b = run(YOSHIKI1, (d) => fillYoshiki1(d, A, CFG, "2026-11-03"));
    expect(text(b, 0)).toBe("（様式１）　　令和8年11月3日");
    expect(lines(b, 4)).toEqual(["申請者　住所　〒000-0000", "架空県架空市9-9"]);
    expect(cell(b, 0, 0, 1)).toBe("（フリガナ）カクウセイサクショ");
    expect(cell(b, 0, 1, 1)).toBe("架空製作所");
    expect([cell(b, 0, 2, 1), cell(b, 0, 2, 1, 1)]).toEqual(["〒000-0000", "架空県架空市9-9"]);
    expect(cell(b, 0, 6, 1)).toBe("メールアドレス　dev@example.com");
    expect(cell(b, 1, 0, 1)).toBe("○業務前自動点呼機器　・　○業務後自動点呼機器");
    expect(cell(b, 1, 1, 1)).toBe("一歩庵点呼 v2");
    expect(cell(b, 1, 2, 1, 5)).toBe("（○）６．");
    expect(cell(b, 1, 2, 1, 6)).toBe("（　　）７.");
    // run の無い段落に足した run は段落の既定の書式を写す
    expect(b.xml()).toMatch(/<w:r><w:rPr><w:sz w:val="21"\/><\/w:rPr><w:t xml:space="preserve">一歩庵点呼 v2</);
  });

  it("様式1: 冒頭の住所は郵便番号だけ・住所だけでも書け、無ければ元のまま", () => {
    const postal = run(YOSHIKI1, (d) => fillYoshiki1(d, { ...emptyApplicant(), postal_code: "000-0000" }, CFG, ""));
    expect(lines(postal, 4)).toEqual(["申請者　住所　〒000-0000"]);
    const street = run(YOSHIKI1, (d) => fillYoshiki1(d, { ...emptyApplicant(), city: "架空市" }, CFG, ""));
    expect(lines(street, 4)).toEqual(["申請者　住所", "架空市"]);
    const bad = [...YOSHIKI1];
    bad[4] = "申請者";
    expect(() => run(bad, (d) => fillYoshiki1(d, A, CFG, ""))).toThrow("「住所」の位置が合いません");
  });

  it("様式1: 値が無ければ元のまま、〒付きの郵便番号は〒を重ねない", () => {
    const empty = run(YOSHIKI1, (d) => fillYoshiki1(d, emptyApplicant(), CFG, ""));
    expect([text(empty, 0), cell(empty, 0, 0, 1), cell(empty, 0, 1, 1), cell(empty, 0, 2, 1)]).toEqual([
      "（様式１）　　令和　　年　　月　　日",
      "（フリガナ）",
      "",
      "〒",
    ]);
    const zip = run(YOSHIKI1, (d) => fillYoshiki1(d, { ...A, postal_code: "〒111-1111" }, CFG, ""));
    expect(cell(zip, 0, 2, 1)).toBe("〒111-1111");
  });

  it("様式2: 名称・①に ○・製作事業者・URL", () => {
    const Y2: Child[] = ["（様式２）", "概要", "", [
      [["名称"], [""]],
      [["対象者"], ["①運転者のみ　②運転者及び特定運行保安員", "③"]],
      [["場所"], ["①営業所又は車庫に限る", "②"]],
      [["製作事業者名"], [""]],
      [["URL"], [""]],
    ]];
    const b = run(Y2, (d) => fillYoshiki2(d, A, CFG));
    expect([cell(b, 0, 0, 1), cell(b, 0, 1, 1), cell(b, 0, 2, 1), cell(b, 0, 3, 1), cell(b, 0, 4, 1)]).toEqual([
      "一歩庵点呼 v2",
      "○①運転者のみ　②運転者及び特定運行保安員",
      "○①営業所又は車庫に限る",
      "架空製作所",
      "https://example.com/tenko",
    ]);
    const empty = run(Y2, (d) => fillYoshiki2(d, emptyApplicant(), { product: "x", version: "v1" }));
    expect([cell(empty, 0, 3, 1), cell(empty, 0, 4, 1)]).toEqual(["", ""]);
  });
});

describe("様式3 自己チェック表", () => {
  const Y3: Child[] = [[
    [["業務前自動点呼の要件に係る自己チェック表"]],
    [["項目"], ["内容"], ["適否"], ["詳細"], ["根拠資料（必須）"]],
    [["一"], ["…"], [""], [""], ["資料番号①"]],
    [["二"], ["…"], [""], [""], ["資料番号②"]],
    [["（ア）取扱説明書等"], ["…"], [""], [""], ["資料番号㉔"]],
    [[]],
  ]];

  it("答えのある項目だけ、適否・詳細・根拠資料を書く", () => {
    let n = 0;
    const b = run(Y3, (d) => {
      n = fillSelfCheck(d, CFG.self_check?.pre);
    });
    expect(n).toBe(2);
    expect([cell(b, 0, 2, 2), cell(b, 0, 2, 3), cell(b, 0, 2, 4)]).toEqual(["適", "点呼の画面で確認する", "資料番号①　取扱説明書 p.3"]);
    expect([cell(b, 0, 3, 2), cell(b, 0, 3, 4)]).toEqual(["", "資料番号②"]);
    expect([cell(b, 0, 4, 2), cell(b, 0, 4, 3), cell(b, 0, 4, 4)]).toEqual(["適", "", "資料番号㉔"]);
  });

  it("答えが無ければ何も書かない。表の題が違えば止める", () => {
    let n = -1;
    run(Y3, (d) => {
      n = fillSelfCheck(d, undefined);
    });
    expect(n).toBe(0);
    expect(() => run([[[["別の表"]]]], (d) => fillSelfCheck(d, {}))).toThrow("「自己チェック表」の位置が合いません");
  });
});

const HEAD: Child[] = ["（様式５）", "", "令和|　|　|年　　月　　日", "", "申請書", "", "", "国土交通省", "課長　殿", "", "住所", "氏名又は名称", "", "", "本文", "", "記"];

describe("様式5・様式7", () => {
  const Y5: Child[] = [...HEAD, [
    [["名称"], ["", "", ""]],
    [["内容"], ["", "", ""]],
    [["時期"], [""]],
    [["影響"], ["", "", ""]],
    [["連絡先"], ["担当者名"]],
    [[""], ["所属・役職"]],
    [[""], ["電話番号"], ["ＦＡＸ"]],
    [[""], ["メールアドレス"]],
  ]];

  it("様式5: 認定済みの版の名称と認定番号・変更の内容・時期・影響・連絡先 (FAX も)", () => {
    const b = run(Y5, (d) => fillYoshiki5(d, A, CFG, "2027-03-01"));
    expect([text(b, 2), lines(b, 10), text(b, 11)]).toEqual(["令和9年3月1日", ["住所　〒000-0000", "架空県架空市9-9"], "氏名又は名称　架空製作所"]);
    expect(cell(b, 0, 0, 1)).toBe("一歩庵点呼 v1（認定番号 業務前 前-0001・業務後 後-0002）");
    expect(cell(b, 0, 1, 1)).toBe("一歩庵点呼 v1 → 一歩庵点呼 v2：体温計を足す");
    expect([cell(b, 0, 2, 1), cell(b, 0, 3, 1)]).toEqual(["令和9年4月1日", "なし"]);
    expect([cell(b, 0, 6, 1), cell(b, 0, 6, 2)]).toEqual(["電話番号　000-1111-2222", "ＦＡＸ　000-1111-3333"]);
  });

  it("様式5: 時期・影響・内容が空でも作れる。履歴が 1 件なら作らない", () => {
    const cfg = { ...CFG, history: [{ version: "v2" }, { version: "v1" }] };
    const b = run(Y5, (d) => fillYoshiki5(d, emptyApplicant(), cfg, ""));
    expect([cell(b, 0, 1, 1), cell(b, 0, 2, 1), cell(b, 0, 3, 1)]).toEqual(["一歩庵点呼 v1 → 一歩庵点呼 v2：", "", ""]);
    expect(() => run(Y5, (d) => fillYoshiki5(d, A, { ...CFG, history: [CFG.history![1]!] }, ""))).toThrow("版の履歴が 1 件だけ");
    expect(() => run(Y5, (d) => fillYoshiki5(d, A, { product: "x", version: "v1" }, ""))).toThrow("版の履歴が 1 件だけ");
  });

  it("様式7: 名称と認定番号・廃止時期・理由・連絡先", () => {
    const Y7: Child[] = [...HEAD, [
      [["名称"], ["", ""]],
      [["廃止時期"], [""]],
      [["廃止理由"], [""]],
      [["連絡先"], ["担当者名"]],
      [[""], ["所属・役職"]],
      [[""], ["電話番号"]],
      [[""], ["メールアドレス"]],
    ]];
    const b = run(Y7, (d) => fillYoshiki7(d, A, CFG, "2028-01-10"));
    expect([cell(b, 0, 0, 1), cell(b, 0, 1, 1), cell(b, 0, 2, 1), cell(b, 0, 3, 1)]).toEqual([
      "一歩庵点呼 v2（認定番号 業務前 前-0001・業務後 後-0002）",
      "令和10年3月31日",
      "後継機へ移るため",
      "担当者名　架空 次郎",
    ]);
    const empty = run(Y7, (d) => fillYoshiki7(d, A, { product: "x", version: "v1" }, ""));
    expect([cell(empty, 0, 1, 1), cell(empty, 0, 2, 1)]).toEqual(["", ""]);
  });
});

describe("DocxBody の見つからない位置", () => {
  it("本文・要素・表・升目・版のずれは例外", () => {
    expect(() => new DocxBody(`<w:document ${W}/>`)).toThrow("本文が見つかりません");
    const b = new DocxBody(documentXml(["a", [[["x"]]]]));
    expect(() => b.child(9)).toThrow("9 番目の要素");
    expect(() => b.table(1)).toThrow("2 番目の表");
    expect(() => b.cellPara(b.table(0), 3, 0)).toThrow("4 行 1 列");
    expect(() => b.cellPara(b.table(0), 0, 5)).toThrow("1 行 6 列");
    expect(() => b.setText(b.child(0), (n) => n, "住所")).toThrow("「住所」の位置が合いません");
    expect(() => fillDocx(zipSync({ "a.xml": strToU8("<a/>") }), () => {})).toThrow("本文が見つかりません");
  });

  it("字下げを左の字下げだけにし、いちばん長い行が本文の幅に収まるところまで寄せる", () => {
    const para = (pPr: string) =>
      `<w:document ${W}><w:body><w:p>${pPr}<w:r><w:t>住所</w:t></w:r></w:p><w:sectPr><w:pgSz w:w="11900"/><w:pgMar w:left="1134" w:right="1134"/></w:sectPr></w:body></w:document>`;
    const ind = (b: DocxBody) => b.xml().match(/<w:ind [^>]*\/>/)?.[0];
    // 本文の幅 9632。10.5pt の全角は 210 → 20 文字 = 4200 なら 5250 から 5432 へは出ないので 5250 のまま
    const short = new DocxBody(para('<w:pPr><w:ind w:firstLineChars="2500" w:firstLine="5250"/></w:pPr>'));
    short.fitIndent(short.child(0), ["あ".repeat(20)]);
    expect(ind(short)).toBe('<w:ind w:left="5250"/>');
    // 30 文字 = 6300 → 9632 - 6300 = 3332 へ寄せる。半角は半分
    const long = new DocxBody(para('<w:pPr><w:ind w:left="5041" w:firstLine="720"/><w:rPr><w:sz w:val="24"/></w:rPr></w:pPr>'));
    long.fitIndent(long.child(0), ["あ".repeat(20) + "a".repeat(10)]);
    expect(ind(long)).toBe(`<w:ind w:left="${9632 - (20 * 240 + 10 * 120)}"/>`);
    // 幅を超えるなら 0。字下げの無い段落には足す。pPr の無い段落は何もしない。用紙の大きさが無ければ A4 の既定
    const none = new DocxBody(para("<w:pPr/>"));
    none.fitIndent(none.child(0), ["あ".repeat(60)]);
    expect(ind(none)).toBe('<w:ind w:left="0"/>');
    const bare = new DocxBody(`<w:document ${W}><w:body><w:p><w:r><w:t>x</w:t></w:r></w:p></w:body></w:document>`);
    bare.fitIndent(bare.child(0), ["x"]);
    expect(bare.xml()).not.toContain("w:ind");
    expect(bare.textWidth()).toBe(9638);
  });

  it("段落を複数行にする", () => {
    const b = new DocxBody(documentXml(["住所|　|"]));
    b.setLines(b.child(0), ["住所　〒1", "架空県"], "住所");
    expect(b.xml()).toContain('<w:t xml:space="preserve">住所　〒1</w:t><w:br/><w:t xml:space="preserve">架空県</w:t>');
  });

  it("書式の無い空の段落にも run を足せる", () => {
    const b = new DocxBody(`<w:document ${W}><w:body><w:p/></w:body></w:document>`);
    b.setText(b.child(0), () => "新しい文");
    expect(b.xml()).toContain('<w:p><w:r><w:t xml:space="preserve">新しい文</w:t></w:r></w:p>');
  });
});

describe("製品の設定と様式の取得", () => {
  const manifest = { forms: { "nintei-yoshiki1-shinsei": { latest: "forms/nintei-yoshiki1-shinsei/2026-11-03.docx" } } };
  const ok = (body: unknown) => new Response(typeof body === "string" ? body : JSON.stringify(body));
  function fetcher(over: { product?: Response; manifest?: Response; file?: Response } = {}) {
    return vi.fn(async (url: string) =>
      url.endsWith(PRODUCT_PATH)
        ? over.product ?? ok(CFG)
        : url.endsWith("manifest.json")
          ? over.manifest ?? ok(manifest)
          : over.file ?? new Response(docx(YOSHIKI1) as BodyInit),
    ) as unknown as typeof fetch;
  }

  it("製品の設定を読む (形が合わない・取れないときは例外)", async () => {
    expect(await fetchProduct(fetcher())).toEqual(CFG);
    await expect(fetchProduct(fetcher({ product: new Response("", { status: 404 }) }))).rejects.toThrow("(404)");
    await expect(fetchProduct(fetcher({ product: ok({ product: "x" }) }))).rejects.toThrow("形が想定と違います");
    await expect(fetchProduct(fetcher({ product: ok("null") }))).rejects.toThrow("形が想定と違います");
  });

  it("最新版の様式に書き、版付きのファイル名を返す", async () => {
    const f = fetcher();
    const y1 = MAKER_FORMS.find((m) => m.id === "nintei-yoshiki1-shinsei")!;
    const { bytes, filename } = await buildMakerForm(y1, A, CFG, "2026-11-03", f);
    expect(filename).toBe("nintei-yoshiki1-shinsei_v2_2026-11-03_記入済み.docx");
    expect(cell(bodyOf(bytes), 1, 1, 1)).toBe("一歩庵点呼 v2");
    expect(vi.mocked(f).mock.calls.map((c) => c[0])).toEqual([
      `${TENKO_FORMS_RAW}manifest.json`,
      `${TENKO_FORMS_RAW}forms/nintei-yoshiki1-shinsei/2026-11-03.docx`,
    ]);
    const odd = ok({ forms: { "nintei-yoshiki1-shinsei": { latest: "forms/x/current.docx" } } });
    expect((await buildMakerForm(y1, A, CFG, "", fetcher({ manifest: odd }))).filename).toBe("nintei-yoshiki1-shinsei_v2_latest_記入済み.docx");
  });

  it("一覧・様式が取れない、一覧に無いときは例外", async () => {
    const y1 = MAKER_FORMS[0]!;
    await expect(buildMakerForm(y1, A, CFG, "", fetcher({ manifest: new Response("", { status: 503 }) }))).rejects.toThrow("一覧を取得できませんでした (503)");
    await expect(buildMakerForm(y1, A, CFG, "", fetcher({ manifest: ok({}) }))).rejects.toThrow("一覧にありません");
    await expect(buildMakerForm(y1, A, CFG, "", fetcher({ file: new Response("", { status: 404 }) }))).rejects.toThrow("様式を取得できませんでした (404)");
  });

  it("様式の一覧の差し込みはどれも動く", () => {
    const byId = Object.fromEntries(MAKER_FORMS.map((m) => [m.id, m]));
    const Y3: Child[] = [[[["自己チェック表"]]]];
    const Y2: Child[] = ["", "", "", [[[""], [""]], [[""], ["①運転者のみ"]], [[""], ["①営業所又は車庫に限る"]], [[""], [""]], [[""], [""]]]];
    expect(() => fillDocx(docx(Y2), (b) => byId["nintei-yoshiki2-gaiyo"]!.fill(b, A, CFG, ""))).not.toThrow();
    expect(() => fillDocx(docx(Y3), (b) => byId["nintei-yoshiki3-1-gyomumae-check"]!.fill(b, A, CFG, ""))).not.toThrow();
    expect(() => fillDocx(docx(Y3), (b) => byId["nintei-yoshiki3-2-gyomugo-check"]!.fill(b, A, CFG, ""))).not.toThrow();
  });
});
