import { describe, it, expect } from "vitest";
import { renderTopPage, renderStagingFooter } from "../../src/lib/top-html";

/**
 * 埋め込み `<script>` から `decodeJwtPayload` (Refs #529) の本体だけを取り出して
 * 実行可能な関数にする。renderTopPage は DOM 前提の巨大な inline script を返す
 * ので、jsdom を足さずにこの純粋関数だけを実機の atob() で検証する。
 */
function extractDecodeJwtPayload(html: string): (token: string) => unknown {
  const m = /function decodeJwtPayload\(token\) \{[\s\S]*?\n {4}\}/.exec(html);
  if (!m) throw new Error("decodeJwtPayload not found in rendered HTML");
  // eslint-disable-next-line no-new-func
  return new Function(`return (${m[0]});`)() as (token: string) => unknown;
}

describe("renderTopPage", () => {
  it("returns a string", () => {
    const result = renderTopPage([], "https://auth.example.com");
    expect(typeof result).toBe("string");
  });

  it("contains DOCTYPE html", () => {
    const result = renderTopPage([], "https://auth.example.com");
    expect(result).toContain("<!DOCTYPE html>");
  });

  it("handles empty apps array", () => {
    const result = renderTopPage([], "https://auth.example.com");
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
  });

  it("includes apps data in output", () => {
    const apps = [
      { name: "Test App", url: "https://app.example.com", icon: "T", description: "A test app" },
    ];
    const result = renderTopPage(apps, "https://auth.example.com");
    expect(result).toContain("Test App");
  });

  it("includes authWorkerOrigin", () => {
    const result = renderTopPage([], "https://auth.my-domain.com");
    expect(result).toContain("auth.my-domain.com");
  });

  describe("staging footer", () => {
    it("omits the staging footer when workerEnv is prod", () => {
      const result = renderTopPage([], "https://auth.example.com", {
        workerEnv: "prod",
        alcApiOrigin: "https://alc.example.com",
        tenantId: "tid-1",
      });
      expect(result).not.toContain("staging-footer");
    });

    it("omits the footer when alcApiOrigin is missing", () => {
      const result = renderTopPage([], "https://auth.example.com", {
        workerEnv: "staging",
      });
      expect(result).not.toContain("staging-footer");
    });

    it("renders the footer when workerEnv is staging and alcApiOrigin is set", () => {
      const result = renderTopPage([], "https://auth.example.com", {
        workerEnv: "staging",
        alcApiOrigin: "https://alc-staging.example.com",
        tenantId: "tid-1",
      });
      expect(result).toContain("staging-footer");
      expect(result).toContain("STAGING");
    });

    it("defaults to no footer when stagingOpts is omitted", () => {
      const result = renderTopPage([], "https://auth.example.com");
      expect(result).not.toContain("staging-footer");
    });
  });

  describe("client-side decodeJwtPayload (Refs #529)", () => {
    // signJwt (jwt.ts) が吐く実運用の AppClaims 相当。name に日本語 (多バイト UTF-8)
    // が乗ると base64url encode が `-`/`_` を含みやすく、旧実装 (atob 直呼び) は
    // InvalidCharacterError で例外 → /top ↔ /login 無限ループになっていた
    // (2026-09-10 本番 wrangler tail で実測)。この token は実際に `-` を含む。
    const REALISTIC_PAYLOAD_B64URL =
      "eyJzdWIiOiJ1MCIsImVtYWlsIjoidGFybzBAZXhhbXBsZS5jb20iLCJuYW1lIjoi5aSn55-zIOWkqumDjiIsInRlbmFudF9pZCI6IjAwMDAwMDAwLTExMTEtNDExMS04MTExLTExMTExMTExMTExMSIsInJvbGUiOiJtZW1iZXIiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OX0";

    it("has a `-` in the payload segment (sanity check for the fixture below)", () => {
      expect(REALISTIC_PAYLOAD_B64URL).toContain("-");
    });

    it("raw atob() throws on this payload (documents the bug this guards against)", () => {
      expect(() => atob(REALISTIC_PAYLOAD_B64URL)).toThrow();
    });

    it("decodeJwtPayload decodes a base64url payload containing `-`/`_` without throwing", () => {
      const html = renderTopPage([], "https://auth.example.com");
      const decodeJwtPayload = extractDecodeJwtPayload(html);
      const token = `header.${REALISTIC_PAYLOAD_B64URL}.sig`;
      const payload = decodeJwtPayload(token) as { name?: string; tenant_id?: string; exp?: number };
      expect(payload).not.toBeNull();
      expect(payload.name).toBe("大石 太郎");
      expect(payload.tenant_id).toBe("00000000-1111-4111-8111-111111111111");
      expect(payload.exp).toBe(9999999999);
    });

    it("returns null (not throw) for a malformed token", () => {
      const html = renderTopPage([], "https://auth.example.com");
      const decodeJwtPayload = extractDecodeJwtPayload(html);
      expect(decodeJwtPayload("not-a-jwt")).toBeNull();
    });
  });
});

describe("renderStagingFooter", () => {
  it("embeds the alc api origin via JSON.stringify", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-1");
    expect(html).toContain(JSON.stringify("https://alc.example.com"));
  });

  it("embeds the tenant_id via JSON.stringify", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-xyz");
    expect(html).toContain(JSON.stringify("tid-xyz"));
  });

  it("uses /api/staging/export with URL-encoded tenant_id", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-xyz");
    expect(html).toContain("/api/staging/export");
    expect(html).toContain("encodeURIComponent(TENANT_ID)");
  });

  it("uses POST /api/staging/import", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-xyz");
    expect(html).toContain("/api/staging/import");
    expect(html).toContain("method: 'POST'");
  });

  it("contains Export and Import buttons", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-xyz");
    expect(html).toContain("staging-btn-export");
    expect(html).toContain("staging-btn-import");
  });

  it("safely escapes a tenant_id that contains a quote", () => {
    const html = renderStagingFooter("https://alc.example.com", 'tid\";alert(1);//');
    expect(html).toContain(JSON.stringify('tid\";alert(1);//'));
    expect(html).not.toContain('"tid";alert(1);//"');
  });
});
