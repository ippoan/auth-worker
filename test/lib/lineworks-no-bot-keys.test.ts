import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * LINE WORKS の App の Client Secret と Private Key を扱うのは alc-lineworks worker だけ
 * (Refs ohishi-exp/rust-leave-worker#1)。auth-worker の LINE WORKS Bot の経路に、
 * 鍵の取り出し・JWT の署名・OAuth2 の token 交換が戻ってこないことを source で固定する。
 */
const FILES = [
  "src/lib/lineworks-bot-api.ts",
  "src/lib/lineworks-bot-creds.ts",
  "src/lib/device-notify-send.ts",
  "src/handlers/api-rich-menu.ts",
  "src/handlers/mcp-tools.ts",
  "src/handlers/alc-internal-proxy.ts",
];

const FORBIDDEN: Array<[string, RegExp]> = [
  ["rust の bot config の秘密の取り出し口", /bot\/configs\/[^"'`]*\/secrets/],
  ["private key", /private_?key/i],
  ["client secret", /client_?secret/i],
  ["service account (JWT の sub)", /service_?account/i],
  ["鍵の import / 署名", /importKey|subtle\.sign/],
  ["JWT bearer の token 交換", /jwt-bearer|auth\.worksmobile\.com\/oauth2/],
];

function read(rel: string): string {
  return readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../..", rel), "utf8");
}

describe("LINE WORKS Bot の鍵を auth-worker が扱わない", () => {
  for (const file of FILES) {
    it(`${file} に鍵を扱うコードが無い`, () => {
      const src = read(file);
      for (const [label, re] of FORBIDDEN) {
        expect(re.test(src), `${file}: ${label}`).toBe(false);
      }
    });
  }

  it("lineworks-bot-api は token を受け取る形だけを export する (BotCredentials は無い)", async () => {
    const mod = (await import("../../src/lib/lineworks-bot-api")) as Record<string, unknown>;
    expect(Object.keys(mod)).not.toContain("getAccessToken");
    expect(Object.keys(mod)).not.toContain("createJwt");
    expect(read("src/lib/lineworks-bot-api.ts")).not.toContain("BotCredentials");
  });
});
