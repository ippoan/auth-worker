/**
 * docx (Word) の本文 (word/document.xml) の決まった位置に文を書く小さな道具。
 *
 * Workers には DOMParser が無いので @xmldom/xmldom で読む (型は `types/xmldom.d.ts`。package の型は DOM を引き込むため使わない)。差し込み用の目印が無い様式を、
 * 本文の何番目の要素 (段落・表) か・表の何行何列の何番目の段落かで指す。書く前に位置の文字を
 * 確かめ、合わなければ書かずに例外にする (様式の版のずれ)。
 *
 * alc-app の `web/app/utils/tenko-forms.ts` の `DocxBody` (ブラウザの DOMParser 版) と同じ考え方。
 */
import { DOMParser, XMLSerializer, type XmlDocument, type XmlElement } from "@xmldom/xmldom/lib/index.js";
import { strFromU8, strToU8, unzipSync, zipSync } from "fflate";

const W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";

/** 子の要素 (文字や注釈を除く) */
function elementChildren(el: XmlElement): XmlElement[] {
  const out: XmlElement[] = [];
  for (let n = el.firstChild; n; n = n.nextSibling) if (n.nodeType === 1) out.push(n as XmlElement);
  return out;
}

/** 子孫の要素を localName で引く (接頭辞に頼らない) */
function descendants(el: XmlElement | XmlDocument, local: string): XmlElement[] {
  return Array.from(el.getElementsByTagName("*")).filter((e) => e.localName === local);
}

/** 段落の既定の文字の大きさ (無ければ 10.5pt) で、文の幅 (twips) を数える関数。全角を 1・半角を 0.5 */
function lineWidth(p: XmlElement): (s: string) => number {
  const pPr = elementChildren(p).find((e) => e.localName === "pPr");
  const rPr = pPr && elementChildren(pPr).find((e) => e.localName === "rPr");
  const sz = Number(rPr && descendants(rPr, "sz")[0]?.getAttribute("w:val")) || 21;
  const full = sz * 10;
  return (s) => [...s].reduce((n, ch) => n + (ch.charCodeAt(0) < 0x100 ? full / 2 : full), 0);
}

export class DocxBody {
  readonly doc: XmlDocument;
  readonly body: XmlElement;

  constructor(xml: string) {
    this.doc = new DOMParser().parseFromString(xml, "text/xml");
    const body = descendants(this.doc, "body")[0];
    if (!body) throw new Error("様式の本文が見つかりません");
    this.body = body;
  }

  /** 本文の直下の i 番目の要素 (段落・表) */
  child(i: number): XmlElement {
    const el = elementChildren(this.body)[i];
    if (!el) throw new Error(`様式の本文に ${i} 番目の要素がありません`);
    return el;
  }

  /** 本文の直下の表のうち n 番目 */
  table(n: number): XmlElement {
    const t = elementChildren(this.body).filter((e) => e.localName === "tbl")[n];
    if (!t) throw new Error(`様式に ${n + 1} 番目の表がありません`);
    return t;
  }

  rows(tbl: XmlElement): XmlElement[] {
    return elementChildren(tbl).filter((e) => e.localName === "tr");
  }

  /** 表の r 行 c 列の段落 (無ければ空) */
  cellParas(tbl: XmlElement, r: number, c: number): XmlElement[] {
    const row = this.rows(tbl)[r];
    const cell = row && elementChildren(row).filter((e) => e.localName === "tc")[c];
    return cell ? elementChildren(cell).filter((e) => e.localName === "p") : [];
  }

  /** 表の r 行 c 列の p 番目の段落 */
  cellPara(tbl: XmlElement, r: number, c: number, p = 0): XmlElement {
    const para = this.cellParas(tbl, r, c)[p];
    if (!para) throw new Error(`様式の表の ${r + 1} 行 ${c + 1} 列が見つかりません`);
    return para;
  }

  static text(p: XmlElement): string {
    return descendants(p, "t")
      .map((t) => t.textContent ?? "")
      .join("");
  }

  /**
   * 段落の文を `f(今の文)` に置き換える。先頭の文の run に全部を書き、ほかの run の文は空にする。
   * 文の run が無ければ、段落の既定の書式で run を足す。`expect` があれば、今の文がそれを
   * 含まないとき書かずに例外にする。
   */
  setText(p: XmlElement, f: (now: string) => string, expect?: string): void {
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

  /**
   * 段落を複数行にする (先頭の文の run に `<w:br/>` と文を足す)。ほかの run の文は空にする。
   * `expect` は {@link setText} と同じ。
   */
  setLines(p: XmlElement, lines: string[], expect?: string): void {
    this.setText(p, () => lines[0] ?? "", expect);
    const run = descendants(p, "t")[0]!.parentNode as XmlElement;
    for (const line of lines.slice(1)) {
      run.appendChild(this.doc.createElementNS(W_NS, "w:br"));
      const t = this.doc.createElementNS(W_NS, "w:t");
      t.textContent = line;
      t.setAttribute("xml:space", "preserve");
      run.appendChild(t);
    }
  }

  /** 本文の幅 (twips) = 用紙の幅 - 左右の余白。読めなければ A4 縦・余白 20mm の幅 */
  textWidth(): number {
    const size = descendants(this.body, "pgSz")[0];
    const mar = descendants(this.body, "pgMar")[0];
    const num = (el: XmlElement | undefined, name: string) => Number(el?.getAttribute(name) ?? NaN);
    const w = num(size, "w:w") - num(mar, "w:left") - num(mar, "w:right");
    return Number.isFinite(w) && w > 0 ? w : 9638;
  }

  /**
   * 段落の字下げを「どの行も同じ位置から始まる」形 (左の字下げだけ) にし、いちばん長い行が本文の幅に
   * 収まるところまで左へ寄せる (元の 1 行目の位置より右へは出さない)。1 行目だけ右へ寄せた欄
   * (「申請者　住所」など) に長い住所を書くと、2 行目が左端へ戻ってしまうため。
   * 文字の幅は段落の既定の文字の大きさ (無ければ 10.5pt) で、全角を 1・半角を 0.5 と数える。
   */
  fitIndent(p: XmlElement, lines: string[]): void {
    const pPr = elementChildren(p).find((e) => e.localName === "pPr");
    if (!pPr) return;
    let ind = elementChildren(pPr).find((e) => e.localName === "ind");
    if (!ind) {
      ind = this.doc.createElementNS(W_NS, "w:ind");
      pPr.appendChild(ind);
    }
    const num = (name: string) => Number(ind!.getAttribute(name) ?? 0) || 0;
    const start = num("w:left") + num("w:firstLine");
    const width = lineWidth(p);
    const need = Math.max(0, ...lines.map(width));
    const left = Math.max(0, Math.min(start, this.textWidth() - need));
    for (const a of ["w:firstLine", "w:firstLineChars", "w:hanging", "w:hangingChars", "w:leftChars", "w:start", "w:startChars"]) {
      ind.removeAttribute(a);
    }
    ind.setAttribute("w:left", String(Math.floor(left)));
  }

  /**
   * 空の段落を並べた枠に `lines` を書いた後、折り返しで増える行の分だけ、使わなかった段落を末尾から消す
   * (枠の高さを保ち、後ろを次のページへ押し出さない)。欄の幅は `w:tcW` (無ければ本文の幅) から
   * 左右の余白 (既定 108 twips ずつ) を引いたもの、文字の幅は {@link fitIndent} と同じ数え方
   */
  dropWrapped(paras: XmlElement[], lines: string[]): void {
    const first = paras[0];
    if (!first) return;
    const tc = first.parentNode as XmlElement | null;
    const tcPr = tc && elementChildren(tc).find((e) => e.localName === "tcPr");
    const tcW = tcPr && elementChildren(tcPr).find((e) => e.localName === "tcW");
    const w = tcW?.getAttribute("w:type") === "dxa" ? Number(tcW.getAttribute("w:w")) : NaN;
    const room = (Number.isFinite(w) && w > 0 ? w : this.textWidth()) - 216;
    const width = lineWidth(first);
    const extra = lines.reduce((n, line) => n + Math.max(0, Math.ceil(width(line) / room) - 1), 0);
    const unused = paras.slice(lines.length).reverse();
    for (const p of unused.slice(0, extra)) p.parentNode?.removeChild(p);
  }

  xml(): string {
    return new XMLSerializer().serializeToString(this.doc);
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
