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
  worksApiGet,
  type BotAccess,
} from "../../src/lib/lineworks-bot-api";

const ORIGINAL_FETCH = globalThis.fetch;

/** alc-lineworks が出した token (auth-worker は token を受け取るだけで、鍵も JWT も扱わない)。 */
function makeBot(): BotAccess {
  return { accessToken: "mock-token", botId: "test-bot" };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  globalThis.fetch = ORIGINAL_FETCH;
});

/** API call 1 回 (token の取得は呼び手の側。ここでは fetch しない) */
function mockApi(apiResponse: Response) {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(apiResponse));
}

function mockApiError(status: number, body: string) {
  mockApi(new Response(body, { status }));
}

describe("lineworks-bot-api", () => {
  describe("worksApiGet", () => {
    it("GETs the URL with the given token (no token request of its own)", async () => {
      const fetchMock = vi.fn().mockResolvedValueOnce(new Response('{"boards":[]}', { status: 200 }));
      vi.stubGlobal("fetch", fetchMock);

      const res = await worksApiGet("board-token", "https://www.worksapis.com/v1.0/boards");

      expect(res.status).toBe(200);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock.mock.calls[0]![0]).toBe("https://www.worksapis.com/v1.0/boards");
      expect((fetchMock.mock.calls[0]![1] as RequestInit).headers).toEqual({
        Authorization: "Bearer board-token",
      });
    });

    it("Rich Menu calls use the given token and bot id, without a token request", async () => {
      const fetchMock = vi
        .fn()
        .mockResolvedValueOnce(new Response(JSON.stringify({ richmenus: [] }), { status: 200 }));
      vi.stubGlobal("fetch", fetchMock);
      await listRichMenus(makeBot());
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock.mock.calls[0]![0]).toBe(
        "https://www.worksapis.com/v1.0/bots/test-bot/richmenus?count=100",
      );
      expect((fetchMock.mock.calls[0]![1] as RequestInit).headers).toEqual({
        Authorization: "Bearer mock-token",
      });
    });
  });

  describe("listRichMenus", () => {
    it("returns array of richmenus on success", async () => {
      const menus = [{ richmenuId: "rm1", richmenuName: "Menu 1", size: { width: 2500, height: 1686 }, areas: [] }];
      mockApi(new Response(JSON.stringify({ richmenus: menus }), { status: 200 }));
      const result = await listRichMenus(makeBot());
      expect(result).toEqual(menus);
    });

    it("returns empty array when richmenus is undefined", async () => {
      mockApi(new Response(JSON.stringify({}), { status: 200 }));
      const result = await listRichMenus(makeBot());
      expect(result).toEqual([]);
    });

    it("throws on error response", async () => {
      mockApiError(500, "Internal Server Error");
      await expect(listRichMenus(makeBot())).rejects.toThrow(
        "listRichMenus failed: 500 Internal Server Error",
      );
    });
  });

  describe("createRichMenu", () => {
    it("returns created menu on success", async () => {
      const menu = { richmenuId: "rm-new", richmenuName: "New", size: { width: 2500, height: 1686 }, areas: [] };
      mockApi(new Response(JSON.stringify(menu), { status: 200 }));
      const result = await createRichMenu(makeBot(), {
        richmenuName: "New",
        size: { width: 2500, height: 1686 },
        areas: [],
      });
      expect(result.richmenuId).toBe("rm-new");
    });

    it("throws on error response", async () => {
      mockApiError(400, "Bad Request");
      await expect(
        createRichMenu(makeBot(), { richmenuName: "x", size: { width: 1, height: 1 }, areas: [] }),
      ).rejects.toThrow("createRichMenu failed: 400 Bad Request");
    });
  });

  describe("deleteRichMenu", () => {
    it("resolves on success", async () => {
      mockApi(new Response("", { status: 200 }));
      await expect(deleteRichMenu(makeBot(), "rm1")).resolves.toBeUndefined();
    });

    it("throws on error response", async () => {
      mockApiError(404, "Not Found");
      await expect(deleteRichMenu(makeBot(), "rm1")).rejects.toThrow(
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
            new Response(JSON.stringify({ fileId: "f1", uploadUrl: "https://upload.example.com" }), { status: 200 }),
          )
          .mockResolvedValueOnce(new Response("ok", { status: 200 }))
          .mockResolvedValueOnce(new Response("ok", { status: 200 })),
      );
      await expect(
        uploadImage(makeBot(), "rm1", new ArrayBuffer(100), "test.png"),
      ).resolves.toBeUndefined();
    });

    it("uses fileId from upload response when available", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ fileId: "f1", uploadUrl: "https://upload.example.com" }), { status: 200 }),
          )
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ fileId: "f2-from-upload" }), { status: 200 }),
          )
          .mockResolvedValueOnce(new Response("ok", { status: 200 })),
      );
      await uploadImage(makeBot(), "rm1", new ArrayBuffer(100), "test.jpg");
      const calls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls;
      const step3Body = calls[2]![1].body;
      expect(JSON.parse(step3Body as string).fileId).toBe("f2-from-upload");
    });

    it("falls back to step1 fileId when upload response is not JSON", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ fileId: "f1-original", uploadUrl: "https://upload.example.com" }), { status: 200 }),
          )
          .mockResolvedValueOnce(new Response("not-json", { status: 200 }))
          .mockResolvedValueOnce(new Response("ok", { status: 200 })),
      );
      await uploadImage(makeBot(), "rm1", new ArrayBuffer(100), "test.png");
      const calls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls;
      const step3Body = calls[2]![1].body;
      expect(JSON.parse(step3Body as string).fileId).toBe("f1-original");
    });

    it("throws when attachments step fails", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(new Response("error", { status: 500 })),
      );
      await expect(
        uploadImage(makeBot(), "rm1", new ArrayBuffer(100), "test.png"),
      ).rejects.toThrow("attachments failed: 500 error");
    });

    it("throws when upload step fails", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ fileId: "f1", uploadUrl: "https://upload.example.com" }), { status: 200 }),
          )
          .mockResolvedValueOnce(new Response("upload error", { status: 413 })),
      );
      await expect(
        uploadImage(makeBot(), "rm1", new ArrayBuffer(100), "test.png"),
      ).rejects.toThrow("image upload failed: 413 upload error");
    });

    it("throws when image association step fails", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ fileId: "f1", uploadUrl: "https://upload.example.com" }), { status: 200 }),
          )
          .mockResolvedValueOnce(new Response("ok", { status: 200 }))
          .mockResolvedValueOnce(new Response("assoc error", { status: 400 })),
      );
      await expect(
        uploadImage(makeBot(), "rm1", new ArrayBuffer(100), "test.png"),
      ).rejects.toThrow("image association failed: 400 assoc error");
    });
  });

  describe("checkRichMenuImage", () => {
    it("returns true when image exists", async () => {
      mockApi(new Response("image-data", { status: 200 }));
      const result = await checkRichMenuImage(makeBot(), "rm1");
      expect(result).toBe(true);
    });

    it("returns false when image not found", async () => {
      mockApi(new Response("", { status: 404 }));
      const result = await checkRichMenuImage(makeBot(), "rm1");
      expect(result).toBe(false);
    });

    it("returns false when fetch throws", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockRejectedValueOnce(new Error("network error")),
      );
      const result = await checkRichMenuImage(makeBot(), "rm1");
      expect(result).toBe(false);
    });
  });

  describe("setDefaultRichMenu", () => {
    it("resolves on success", async () => {
      mockApi(new Response("", { status: 200 }));
      await expect(setDefaultRichMenu(makeBot(), "rm1")).resolves.toBeUndefined();
    });

    it("throws on error", async () => {
      mockApiError(500, "Server Error");
      await expect(setDefaultRichMenu(makeBot(), "rm1")).rejects.toThrow(
        "setDefault failed: 500 Server Error",
      );
    });
  });

  describe("getDefaultRichMenu", () => {
    it("returns default menu on success", async () => {
      mockApi(
        new Response(JSON.stringify({ defaultRichmenuId: "rm-default" }), { status: 200 }),
      );
      const result = await getDefaultRichMenu(makeBot());
      expect(result).toEqual({ defaultRichmenuId: "rm-default" });
    });

    it("returns null on 404", async () => {
      mockApi(new Response("", { status: 404 }));
      const result = await getDefaultRichMenu(makeBot());
      expect(result).toBeNull();
    });

    it("throws on other error", async () => {
      mockApiError(500, "Server Error");
      await expect(getDefaultRichMenu(makeBot())).rejects.toThrow(
        "getDefault failed: 500 Server Error",
      );
    });
  });

  describe("deleteDefaultRichMenu", () => {
    it("resolves on success (200)", async () => {
      mockApi(new Response("", { status: 200 }));
      await expect(deleteDefaultRichMenu(makeBot())).resolves.toBeUndefined();
    });

    it("resolves on 404 (no default set)", async () => {
      mockApi(new Response("", { status: 404 }));
      await expect(deleteDefaultRichMenu(makeBot())).resolves.toBeUndefined();
    });

    it("throws on other error", async () => {
      mockApiError(500, "Server Error");
      await expect(deleteDefaultRichMenu(makeBot())).rejects.toThrow(
        "deleteDefault failed: 500 Server Error",
      );
    });
  });
});
