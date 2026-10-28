/**
 * Workers RPC entrypoint — alc-notify-worker が **service binding 越しにだけ**呼ぶ、
 * alc-redact (GCP Cloud Run、IAM の invoker で守る) への口 (W8c-2、Refs ippoan/rust-alc-api#680)。
 *
 *   - `redact(pdf)` → alc-redact の `POST /redact` (1 ページ目を黒塗りした JPEG)
 *   - `extract(pdf, selfCompany)` → alc-redact の `POST /extract` (配車の 14 項目の JSON)
 *
 * ★ **ID token を作る SA の鍵は auth-worker の 1 か所のまま** (notify-worker に配らない)。
 *   既存の `ALC_API_PROXY_SA_KEY` で aud = `ALC_REDACT_ORIGIN` の ID token を mint して呼ぶ。
 * ★ **他の entrypoint と別 class** — 呼べるメソッドが binding ごとに閉じる (blast radius)。
 *   呼び手 = notify-worker だけ。path と method は固定で、呼び手に選ばせない。
 * ★ **`AlcRpcResult` は使わない** — body が string だと JPEG を運べない。戻り値の body は
 *   `ArrayBuffer`、headers は alc-redact の計測のヘッダー (`X-Redactions-Applied`・`X-Redact-*-Ms`) だけ。
 *   RPC の上限 (32 MiB) は、上り (PDF は呼び手が 25 MiB で切る) と下り (JPEG) のどちらも収まる。
 *
 * 失敗は throw せず返す (他の entrypoint と同じ流儀)。alc-redact のエラー (`{"error": "<code>"}`) は
 * status と body をそのまま返し、呼び手がコードで状態に対応づける。この口の失敗は
 * alc-redact に無いコード (`redact_unconfigured` / `upstream_auth` / `upstream_unreachable`) にする
 * (呼び手は一時的な失敗として再試行する)。ID token・SA key は log と戻り値に出さない。
 */
import { WorkerEntrypoint } from "cloudflare:workers";
import type { Env } from "./index";
import { resolveSecret } from "./lib/secret";
import { mintGoogleIdToken } from "./lib/oidc";

export interface AlcRedactResult {
  status: number;
  body: ArrayBuffer;
  contentType: string | null;
  /** alc-redact の計測のヘッダー (名前は小文字)。 */
  headers: Record<string, string>;
}

/** 呼び手へ返す alc-redact の応答ヘッダー (`x-redact-llm-ms` 等は接頭辞で拾う)。 */
function pickHeaders(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  res.headers.forEach((value, name) => {
    const n = name.toLowerCase();
    if (n === "x-redactions-applied" || n.startsWith("x-redact-")) out[n] = value;
  });
  return out;
}

function errorResult(status: number, error: string): AlcRedactResult {
  return {
    status,
    body: new TextEncoder().encode(JSON.stringify({ error })).buffer as ArrayBuffer,
    contentType: "application/json",
    headers: {},
  };
}

function toArrayBuffer(pdf: unknown): ArrayBuffer | null {
  if (pdf instanceof ArrayBuffer) return pdf;
  if (ArrayBuffer.isView(pdf)) {
    return pdf.buffer.slice(pdf.byteOffset, pdf.byteOffset + pdf.byteLength) as ArrayBuffer;
  }
  return null;
}

export class AlcRedactEntrypoint extends WorkerEntrypoint<Env> {
  /** `POST /redact` — 200 は `image/jpeg`。 */
  async redact(pdf: ArrayBuffer): Promise<AlcRedactResult> {
    return this.post("/redact", pdf, {});
  }

  /** `POST /extract` — 200 は `{"logistics": {...}}`。自社名は UTF-8 を percent-encode して送る。 */
  async extract(pdf: ArrayBuffer, selfCompany: string): Promise<AlcRedactResult> {
    const headers: Record<string, string> = {};
    if (typeof selfCompany === "string" && selfCompany.trim() !== "") {
      headers["X-Self-Company"] = encodeURIComponent(selfCompany.trim());
    }
    return this.post("/extract", pdf, headers);
  }

  private async post(
    path: "/redact" | "/extract",
    pdf: unknown,
    extra: Record<string, string>,
  ): Promise<AlcRedactResult> {
    const body = toArrayBuffer(pdf);
    if (!body) return errorResult(400, "bad_request");

    const saKey = await resolveSecret(this.env.ALC_API_PROXY_SA_KEY);
    const origin = this.env.ALC_REDACT_ORIGIN;
    if (!saKey || !origin) return errorResult(503, "redact_unconfigured");

    let idToken: string;
    try {
      idToken = await mintGoogleIdToken(saKey, origin);
    } catch {
      return errorResult(502, "upstream_auth"); // 詳細は log のみ
    }

    let res: Response;
    try {
      res = await fetch(`${origin.replace(/\/$/, "")}${path}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${idToken}`,
          "Content-Type": "application/pdf",
          ...extra,
        },
        body,
      });
    } catch {
      return errorResult(502, "upstream_unreachable");
    }
    return {
      status: res.status,
      body: await res.arrayBuffer(),
      contentType: res.headers.get("content-type"),
      headers: pickHeaders(res),
    };
  }
}
