/**
 * `@xmldom/xmldom` の使う分だけの型 (`lib/docx-fill.ts`)。
 *
 * package の `index.d.ts` は先頭で `/// <reference lib="dom" />` を引き込み、Workers の型
 * (`BufferSource`・`BodyInit`・`Headers` など) と衝突して、無関係なファイルまで型検査が落ちる。
 * そのため型定義の無い `lib/index.js` を直接読み込み、ここで最小の型を宣言する (DOM の型には頼らない)。
 */
declare module "@xmldom/xmldom/lib/index.js" {
  export interface XmlNode {
    readonly nodeType: number;
    readonly firstChild: XmlNode | null;
    readonly nextSibling: XmlNode | null;
    readonly localName: string | null;
    readonly parentNode: XmlNode | null;
    textContent: string | null;
    appendChild(node: XmlNode): XmlNode;
    removeChild(node: XmlNode): XmlNode;
    cloneNode(deep: boolean): XmlNode;
  }
  export interface XmlElement extends XmlNode {
    getElementsByTagName(name: string): ArrayLike<XmlElement>;
    setAttribute(name: string, value: string): void;
    getAttribute(name: string): string | null;
    removeAttribute(name: string): void;
  }
  export interface XmlDocument extends XmlNode {
    getElementsByTagName(name: string): ArrayLike<XmlElement>;
    createElementNS(ns: string, qualifiedName: string): XmlElement;
  }
  export const DOMParser: new () => { parseFromString(xml: string, mimeType: string): XmlDocument };
  export const XMLSerializer: new () => { serializeToString(node: XmlNode): string };
}
