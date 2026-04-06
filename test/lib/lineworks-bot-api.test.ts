import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  listRichMenus,
  createRichMenu,
  deleteRichMenu,
  uploadImage,
  checkRichMenuImage,
  setDefaultRichMenu,
  getDefaultRichMenu,
  deleteDefaultRichMenu,
  type BotCredentials,
} from "../../src/lib/lineworks-bot-api";

// Valid base64 PEM (content doesn't matter since we mock crypto.subtle)
const FAKE_PEM = `-----BEGIN PRIVATE KEY-----
MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA0Z3VS5JJcds3xf0G
PGdqwYx0KVT5ePCMNkjaWOL0tEJhvsud4JL7dMtXEfehfslDrV5Rcqeqr3rSDGOu
cQIDAQABAkEAhZ3MsMYTs1Eiiekn8bfGd2sdU86WnKpynHjN+SWM3ePaiT6vK7sn
rDWCa3FG9vSzaxmQzSgMxlu5/5BffMVwwQIhAPe9lON+rnTiAhgKn3CKaaLz9Ave
eJR5k0VhTCGo/xThAiEA2S7qcIFrPZsT3F0T0G03JaKwrp4pCCe9xAvHtEVqxOkC
IEIuexLVNq3sCQ1DQ3TiRkZI2U7ChC4FaLzfhJKdLPIhAiEAgYLnkBbQfbvUDJYV
cRaQMwCdV7KNfJi7Llgwdmn+Y/kCIQDW5ndbYcIktYeKJC2qX20V8CeBVw+Yq5pJ
WJnH2j3VAw==
-----END PRIVATE KEY-----`;

function makeCreds(): BotCredentials {
  return {
    clientId: "test-client",
    clientSecret: "test-secret",
    serviceAccount: "test@service",
    privateKey: FAKE_PEM,
    botId: "test-bot",
  };
}

// Mock crypto.subtle to bypass RSA key operations
const mockSign = vi.fn().mockResolvedValue(new ArrayBuffer(256));
const mockImportKey = vi.fn().mockResolvedValue({ type: "private" });

const originalFetch = globalThis.fetch;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const g = globalThis as any;
const originalSubtle = g.crypto?.subtle;

beforeEach(() => {
  vi.restoreAllMocks();
  mockSign.mockResolvedValue(new ArrayBuffer(256));
  mockImportKey.mockResolvedValue({ type: "private" });
  Object.defineProperty(g.crypto, "subtle", {
    value: { importKey: mockImportKey, sign: mockSign },
    configurable: true,
  });
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalSubtle) {
    Object.defineProperty(g.crypto, "subtle", {
      value: originalSubtle,
      configurable: true,
    });
  }
});

/** Mock token endpoint + API call (2 sequential fetches) */
function mockTokenAndApi(apiResponse: Response) {
  vi.stubGlobal(
    "fetch",
    vi.fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "mock-token" }), { status: 200 }),
      )
      .mockResolvedValueOnce(apiResponse),
  );
}

function mockTokenAndApiError(status: number, body: string) {
  mockTokenAndApi(new Response(body, { status }));
}

describe("lineworks-bot-api", () => {
  describe("listRichMenus", () => {
    it("returns array of richmenus on success", async () => {
      const menus = [{ richmenuId: "rm1", richmenuName: "Menu 1", size: { width: 2500, height: 1686 }, areas: [] }];
      mockTokenAndApi(new Response(JSON.stringify({ richmenus: menus }), { status: 200 }));
      const result = await listRichMenus(makeCreds());
      expect(result).toEqual(menus);
    });

    it("returns empty array when richmenus is undefined", async () => {
      mockTokenAndApi(new Response(JSON.stringify({}), { status: 200 }));
      const result = await listRichMenus(makeCreds());
      expect(result).toEqual([]);
    });

    it("throws on error response", async () => {
      mockTokenAndApiError(500, "Internal Server Error");
      await expect(listRichMenus(makeCreds())).rejects.toThrow(
        "listRichMenus failed: 500 Internal Server Error",
      );
    });
  });

  describe("createRichMenu", () => {
    it("returns created menu on success", async () => {
      const menu = { richmenuId: "rm-new", richmenuName: "New", size: { width: 2500, height: 1686 }, areas: [] };
      mockTokenAndApi(new Response(JSON.stringify(menu), { status: 200 }));
      const result = await createRichMenu(makeCreds(), {
        richmenuName: "New",
        size: { width: 2500, height: 1686 },
        areas: [],
      });
      expect(result.richmenuId).toBe("rm-new");
    });

    it("throws on error response", async () => {
      mockTokenAndApiError(400, "Bad Request");
      await expect(
        createRichMenu(makeCreds(), { richmenuName: "x", size: { width: 1, height: 1 }, areas: [] }),
      ).rejects.toThrow("createRichMenu failed: 400 Bad Request");
    });
  });

  describe("deleteRichMenu", () => {
    it("resolves on success", async () => {
      mockTokenAndApi(new Response("", { status: 200 }));
      await expect(deleteRichMenu(makeCreds(), "rm1")).resolves.toBeUndefined();
    });

    it("throws on error response", async () => {
      mockTokenAndApiError(404, "Not Found");
      await expect(deleteRichMenu(makeCreds(), "rm1")).rejects.toThrow(
        "deleteRichMenu failed: 404 Not Found",
      );
    });
  });

  describe("uploadImage", () => {
    it("completes 3-step upload on success", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ access_token: "mock-token" }), { status: 200 }),
          )
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ fileId: "f1", uploadUrl: "https://upload.example.com" }), { status: 200 }),
          )
          .mockResolvedValueOnce(new Response("ok", { status: 200 }))
          .mockResolvedValueOnce(new Response("ok", { status: 200 })),
      );
      await expect(
        uploadImage(makeCreds(), "rm1", new ArrayBuffer(100), "test.png"),
      ).resolves.toBeUndefined();
    });

    it("uses fileId from upload response when available", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ access_token: "mock-token" }), { status: 200 }),
          )
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ fileId: "f1", uploadUrl: "https://upload.example.com" }), { status: 200 }),
          )
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ fileId: "f2-from-upload" }), { status: 200 }),
          )
          .mockResolvedValueOnce(new Response("ok", { status: 200 })),
      );
      await uploadImage(makeCreds(), "rm1", new ArrayBuffer(100), "test.jpg");
      const calls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls;
      const step3Body = calls[3]![1].body;
      expect(JSON.parse(step3Body as string).fileId).toBe("f2-from-upload");
    });

    it("falls back to step1 fileId when upload response is not JSON", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ access_token: "mock-token" }), { status: 200 }),
          )
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ fileId: "f1-original", uploadUrl: "https://upload.example.com" }), { status: 200 }),
          )
          .mockResolvedValueOnce(new Response("not-json", { status: 200 }))
          .mockResolvedValueOnce(new Response("ok", { status: 200 })),
      );
      await uploadImage(makeCreds(), "rm1", new ArrayBuffer(100), "test.png");
      const calls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls;
      const step3Body = calls[3]![1].body;
      expect(JSON.parse(step3Body as string).fileId).toBe("f1-original");
    });

    it("throws when attachments step fails", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ access_token: "mock-token" }), { status: 200 }),
          )
          .mockResolvedValueOnce(new Response("error", { status: 500 })),
      );
      await expect(
        uploadImage(makeCreds(), "rm1", new ArrayBuffer(100), "test.png"),
      ).rejects.toThrow("attachments failed: 500 error");
    });

    it("throws when upload step fails", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ access_token: "mock-token" }), { status: 200 }),
          )
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ fileId: "f1", uploadUrl: "https://upload.example.com" }), { status: 200 }),
          )
          .mockResolvedValueOnce(new Response("upload error", { status: 413 })),
      );
      await expect(
        uploadImage(makeCreds(), "rm1", new ArrayBuffer(100), "test.png"),
      ).rejects.toThrow("image upload failed: 413 upload error");
    });

    it("throws when image association step fails", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ access_token: "mock-token" }), { status: 200 }),
          )
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ fileId: "f1", uploadUrl: "https://upload.example.com" }), { status: 200 }),
          )
          .mockResolvedValueOnce(new Response("ok", { status: 200 }))
          .mockResolvedValueOnce(new Response("assoc error", { status: 400 })),
      );
      await expect(
        uploadImage(makeCreds(), "rm1", new ArrayBuffer(100), "test.png"),
      ).rejects.toThrow("image association failed: 400 assoc error");
    });
  });

  describe("checkRichMenuImage", () => {
    it("returns true when image exists", async () => {
      mockTokenAndApi(new Response("image-data", { status: 200 }));
      const result = await checkRichMenuImage(makeCreds(), "rm1");
      expect(result).toBe(true);
    });

    it("returns false when image not found", async () => {
      mockTokenAndApi(new Response("", { status: 404 }));
      const result = await checkRichMenuImage(makeCreds(), "rm1");
      expect(result).toBe(false);
    });

    it("returns false when fetch throws", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ access_token: "mock-token" }), { status: 200 }),
          )
          .mockRejectedValueOnce(new Error("network error")),
      );
      const result = await checkRichMenuImage(makeCreds(), "rm1");
      expect(result).toBe(false);
    });
  });

  describe("setDefaultRichMenu", () => {
    it("resolves on success", async () => {
      mockTokenAndApi(new Response("", { status: 200 }));
      await expect(setDefaultRichMenu(makeCreds(), "rm1")).resolves.toBeUndefined();
    });

    it("throws on error", async () => {
      mockTokenAndApiError(500, "Server Error");
      await expect(setDefaultRichMenu(makeCreds(), "rm1")).rejects.toThrow(
        "setDefault failed: 500 Server Error",
      );
    });
  });

  describe("getDefaultRichMenu", () => {
    it("returns default menu on success", async () => {
      mockTokenAndApi(
        new Response(JSON.stringify({ defaultRichmenuId: "rm-default" }), { status: 200 }),
      );
      const result = await getDefaultRichMenu(makeCreds());
      expect(result).toEqual({ defaultRichmenuId: "rm-default" });
    });

    it("returns null on 404", async () => {
      mockTokenAndApi(new Response("", { status: 404 }));
      const result = await getDefaultRichMenu(makeCreds());
      expect(result).toBeNull();
    });

    it("throws on other error", async () => {
      mockTokenAndApiError(500, "Server Error");
      await expect(getDefaultRichMenu(makeCreds())).rejects.toThrow(
        "getDefault failed: 500 Server Error",
      );
    });
  });

  describe("deleteDefaultRichMenu", () => {
    it("resolves on success (200)", async () => {
      mockTokenAndApi(new Response("", { status: 200 }));
      await expect(deleteDefaultRichMenu(makeCreds())).resolves.toBeUndefined();
    });

    it("resolves on 404 (no default set)", async () => {
      mockTokenAndApi(new Response("", { status: 404 }));
      await expect(deleteDefaultRichMenu(makeCreds())).resolves.toBeUndefined();
    });

    it("throws on other error", async () => {
      mockTokenAndApiError(500, "Server Error");
      await expect(deleteDefaultRichMenu(makeCreds())).rejects.toThrow(
        "deleteDefault failed: 500 Server Error",
      );
    });
  });

  describe("getAccessToken (via botFetch)", () => {
    it("throws when token endpoint fails", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValueOnce(
          new Response("token error", { status: 401 }),
        ),
      );
      await expect(listRichMenus(makeCreds())).rejects.toThrow(
        "Token issue failed: 401 token error",
      );
    });
  });
});
