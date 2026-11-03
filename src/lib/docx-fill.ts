/**
 * docx (Word) の本文 (word/document.xml) の決まった位置に文を書く小さな道具。
 *
 * Workers には DOMParser が無いので @xmldom/xmldom で読む。差し込み用の目印が無い様式を、
 * 本文の何番目の要素 (段落・表) か・表の何行何列の何番目の段落かで指す。書く前に位置の文字を
 * 確かめ、合わなければ書かずに例外にする (様式の版のずれ)。
 *
 * alc-app の `web/app/utils/tenko-forms.ts` の `DocxBody` (ブラウザの DOMParser 版) と同じ考え方。
 */
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import { strFromU8, strToU8, unzipSync, zipSync } from "fflate";

const W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";

/** 子の要素 (文字や注釈を除く) */
function elementChildren(el: Element): Element[] {
  const out: Element[] = [];
  for (let n = el.firstChild; n; n = n.nextSibling) if (n.nodeType === 1) out.push(n as Element);
  return out;
}

/** 子孫の要素を localName で引く (接頭辞に頼らない) */
function descendants(el: Element | Document, local: string): Element[] {
  return Array.from(el.getElementsByTagName("*")).filter((e) => e.localName === local);
}

export class DocxBody {
  readonly doc: Document;
  readonly body: Element;

  constructor(xml: string) {
    this.doc = new DOMParser().parseFromString(xml, "text/xml") as unknown as Document;
    const body = descendants(this.doc, "body")[0];
    if (!body) throw new Error("様式の本文が見つかりません");
    this.body = body;
  }

  /** 本文の直下の i 番目の要素 (段落・表) */
  child(i: number): Element {
    const el = elementChildren(this.body)[i];
    if (!el) throw new Error(`様式の本文に ${i} 番目の要素がありません`);
    return el;
  }

  /** 本文の直下の表のうち n 番目 */
  table(n: number): Element {
    const t = elementChildren(this.body).filter((e) => e.localName === "tbl")[n];
    if (!t) throw new Error(`様式に ${n + 1} 番目の表がありません`);
    return t;
  }

  rows(tbl: Element): Element[] {
    return elementChildren(tbl).filter((e) => e.localName === "tr");
  }

  /** 表の r 行 c 列の p 番目の段落 */
  cellPara(tbl: Element, r: number, c: number, p = 0): Element {
    const row = this.rows(tbl)[r];
    const cell = row && elementChildren(row).filter((e) => e.localName === "tc")[c];
    const para = cell && elementChildren(cell).filter((e) => e.localName === "p")[p];
    if (!para) throw new Error(`様式の表の ${r + 1} 行 ${c + 1} 列が見つかりません`);
    return para;
  }

  static text(p: Element): string {
    return descendants(p, "t")
      .map((t) => t.textContent ?? "")
      .join("");
  }

  /**
   * 段落の文を `f(今の文)` に置き換える。先頭の文の run に全部を書き、ほかの run の文は空にする。
   * 文の run が無ければ、段落の既定の書式で run を足す。`expect` があれば、今の文がそれを
   * 含まないとき書かずに例外にする。
   */
  setText(p: Element, f: (now: string) => string, expect?: string): void {
    const now = DocxBody.text(p);
    if (expect !== undefined && !now.includes(expect)) {
      throw new Error(`様式の版が想定と違います (「${expect}」の位置が合いません)`);
    }
    const next = f(now);
    const ts = descendants(p, "t");
    let first = ts[0];
    if (!first) {
      const r = this.doc.createElementNS(W_NS, "w:r");
      const pPr = descendants(p, "pPr")[0];
      const rPr = pPr && descendants(pPr, "rPr")[0];
      if (rPr) r.appendChild(rPr.cloneNode(true));
      first = this.doc.createElementNS(W_NS, "w:t");
      r.appendChild(first);
      p.appendChild(r);
    }
    first.textContent = next;
    first.setAttribute("xml:space", "preserve");
    for (const t of ts.slice(1)) t.textContent = "";
  }

  xml(): string {
    return new XMLSerializer().serializeToString(this.doc as unknown as Node);
  }
}

/** docx の本文を書き換えた中身を返す */
export function fillDocx(file: Uint8Array, fill: (b: DocxBody) => void): Uint8Array {
  const zip = unzipSync(file);
  const path = "word/document.xml";
  const xml = zip[path];
  if (!xml) throw new Error("様式の本文が見つかりません");
  const b = new DocxBody(strFromU8(xml));
  fill(b);
  zip[path] = strToU8(b.xml());
  return zipSync(zip, { level: 6 });
}
