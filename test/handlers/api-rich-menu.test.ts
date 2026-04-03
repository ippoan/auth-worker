import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

const {
  mockGetConfig,
  mockListRichMenus,
  mockCreateRichMenu,
  mockDeleteRichMenu,
  mockUploadImage,
  mockCheckRichMenuImage,
  mockSetDefaultRichMenu,
  mockGetDefaultRichMenu,
  mockDeleteDefaultRichMenu,
} = vi.hoisted(() => ({
  mockGetConfig: vi.fn(),
  mockListRichMenus: vi.fn(),
  mockCreateRichMenu: vi.fn(),
  mockDeleteRichMenu: vi.fn(),
  mockUploadImage: vi.fn(),
  mockCheckRichMenuImage: vi.fn(),
  mockSetDefaultRichMenu: vi.fn(),
  mockGetDefaultRichMenu: vi.fn(),
  mockDeleteDefaultRichMenu: vi.fn(),
}));

vi.mock("@connectrpc/connect", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@connectrpc/connect")>();
  return {
    ...actual,
    createClient: vi.fn(() => ({
      getConfigWithSecrets: mockGetConfig,
    })),
  };
});
vi.mock("../../src/lib/transport", () => ({
  createTransportWithAuth: vi.fn(),
}));
vi.mock("@yhonda-ohishi-pub-dev/logi-proto", () => ({
  BotConfigService: {},
}));
vi.mock("../../src/lib/lineworks-bot-api", () => ({
  listRichMenus: mockListRichMenus,
  createRichMenu: mockCreateRichMenu,
  deleteRichMenu: mockDeleteRichMenu,
  uploadImage: mockUploadImage,
  checkRichMenuImage: mockCheckRichMenuImage,
  setDefaultRichMenu: mockSetDefaultRichMenu,
  getDefaultRichMenu: mockGetDefaultRichMenu,
  deleteDefaultRichMenu: mockDeleteDefaultRichMenu,
}));

import {
  handleRichMenuList,
  handleRichMenuCreate,
  handleRichMenuDelete,
  handleRichMenuImageUpload,
  handleRichMenuDefaultSet,
  handleRichMenuDefaultDelete,
} from "../../src/handlers/api-rich-menu";

function jsonRequest(url: string, body: unknown, token?: string) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return new Request(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

function formDataRequest(
  url: string,
  fields: Record<string, string | File>,
  token?: string,
) {
  const form = new FormData();
  for (const [k, v] of Object.entries(fields)) {
    form.append(k, v);
  }
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return new Request(url, { method: "POST", headers, body: form });
}

const defaultCreds = {
  clientId: "cid",
  clientSecret: "cs",
  serviceAccount: "sa",
  privateKey: "pk",
  botId: "bid",
};

// ---------- handleRichMenuList ----------

describe("handleRichMenuList", () => {
  const env = createMockEnv();
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 401 without token", async () => {
    const res = await handleRichMenuList(
      jsonRequest("https://x.com", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 without botConfigId", async () => {
    const res = await handleRichMenuList(
      jsonRequest("https://x.com", {}, "tok"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns richmenus with default and image status on success", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockListRichMenus.mockResolvedValueOnce([
      { richmenuId: "rm1", name: "Menu1" },
      { richmenuId: "rm2", name: "Menu2" },
    ]);
    mockGetDefaultRichMenu.mockResolvedValueOnce({
      defaultRichmenuId: "rm1",
    });
    mockCheckRichMenuImage
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(false);

    const res = await handleRichMenuList(
      jsonRequest("https://x.com", { botConfigId: "bc1" }, "tok"),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { richmenus: unknown[]; defaultRichmenuId: string; imageStatus: Record<string, boolean> };
    expect(data.richmenus).toHaveLength(2);
    expect(data.defaultRichmenuId).toBe("rm1");
    expect(data.imageStatus).toEqual({ rm1: true, rm2: false });
  });

  it("handles null defaultRichmenuId", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockListRichMenus.mockResolvedValueOnce([]);
    mockGetDefaultRichMenu.mockResolvedValueOnce(null);

    const res = await handleRichMenuList(
      jsonRequest("https://x.com", { botConfigId: "bc1" }, "tok"),
      env,
    );
    const data = await res.json<{ defaultRichmenuId: string | null; imageStatus: Record<string, boolean> }>();
    expect(data.defaultRichmenuId).toBeNull();
    expect(data.imageStatus).toEqual({});
  });

  it("handles undefined checkRichMenuImage result as false", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockListRichMenus.mockResolvedValueOnce([{ richmenuId: "rm1" }]);
    mockGetDefaultRichMenu.mockResolvedValueOnce(null);
    mockCheckRichMenuImage.mockResolvedValueOnce(undefined);

    const res = await handleRichMenuList(
      jsonRequest("https://x.com", { botConfigId: "bc1" }, "tok"),
      env,
    );
    const data = await res.json<{ imageStatus: Record<string, boolean> }>();
    expect(data.imageStatus).toEqual({ rm1: false });
  });

  it("returns 400 on ConnectError", async () => {
    const { ConnectError } = await import("@connectrpc/connect");
    mockGetConfig.mockRejectedValueOnce(new ConnectError("gRPC fail", 3));

    const res = await handleRichMenuList(
      jsonRequest("https://x.com", { botConfigId: "bc1" }, "tok"),
      env,
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("[invalid_argument] gRPC fail");
  });

  it("returns 500 on regular Error", async () => {
    mockGetConfig.mockRejectedValueOnce(new Error("boom"));

    const res = await handleRichMenuList(
      jsonRequest("https://x.com", { botConfigId: "bc1" }, "tok"),
      env,
    );
    expect(res.status).toBe(500);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("boom");
  });

  it("throws non-Error", async () => {
    mockGetConfig.mockRejectedValueOnce("string error");

    await expect(
      handleRichMenuList(
        jsonRequest("https://x.com", { botConfigId: "bc1" }, "tok"),
        env,
      ),
    ).rejects.toBe("string error");
  });
});

// ---------- handleRichMenuCreate ----------

describe("handleRichMenuCreate", () => {
  const env = createMockEnv();
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 401 without token", async () => {
    const res = await handleRichMenuCreate(
      jsonRequest("https://x.com", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 without botConfigId", async () => {
    const res = await handleRichMenuCreate(
      jsonRequest(
        "https://x.com",
        { richmenuName: "n", size: { width: 1, height: 1 }, areas: [{}] },
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 without richmenuName", async () => {
    const res = await handleRichMenuCreate(
      jsonRequest(
        "https://x.com",
        { botConfigId: "bc1", size: { width: 1, height: 1 }, areas: [{}] },
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 without size", async () => {
    const res = await handleRichMenuCreate(
      jsonRequest(
        "https://x.com",
        { botConfigId: "bc1", richmenuName: "n", areas: [{}] },
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 without areas", async () => {
    const res = await handleRichMenuCreate(
      jsonRequest(
        "https://x.com",
        {
          botConfigId: "bc1",
          richmenuName: "n",
          size: { width: 1, height: 1 },
        },
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 with empty areas array", async () => {
    const res = await handleRichMenuCreate(
      jsonRequest(
        "https://x.com",
        {
          botConfigId: "bc1",
          richmenuName: "n",
          size: { width: 1, height: 1 },
          areas: [],
        },
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns created menu on success", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockCreateRichMenu.mockResolvedValueOnce({ richmenuId: "rm1" });

    const res = await handleRichMenuCreate(
      jsonRequest(
        "https://x.com",
        {
          botConfigId: "bc1",
          richmenuName: "Menu1",
          size: { width: 2500, height: 1686 },
          areas: [{ bounds: { x: 0, y: 0, width: 1250, height: 843 }, action: { type: "uri", uri: "https://example.com" } }],
        },
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(200);
    const data = await res.json<{ richmenuId: string }>();
    expect(data.richmenuId).toBe("rm1");
  });

  it("returns 400 on ConnectError", async () => {
    const { ConnectError } = await import("@connectrpc/connect");
    mockGetConfig.mockRejectedValueOnce(new ConnectError("fail", 3));

    const res = await handleRichMenuCreate(
      jsonRequest(
        "https://x.com",
        {
          botConfigId: "bc1",
          richmenuName: "n",
          size: { width: 1, height: 1 },
          areas: [{}],
        },
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 500 on regular Error", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockCreateRichMenu.mockRejectedValueOnce(new Error("API error"));

    const res = await handleRichMenuCreate(
      jsonRequest(
        "https://x.com",
        {
          botConfigId: "bc1",
          richmenuName: "n",
          size: { width: 1, height: 1 },
          areas: [{}],
        },
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(500);
  });

  it("throws non-Error", async () => {
    mockGetConfig.mockRejectedValueOnce(42);

    await expect(
      handleRichMenuCreate(
        jsonRequest(
          "https://x.com",
          {
            botConfigId: "bc1",
            richmenuName: "n",
            size: { width: 1, height: 1 },
            areas: [{}],
          },
          "tok",
        ),
        env,
      ),
    ).rejects.toBe(42);
  });
});

// ---------- handleRichMenuDelete ----------

describe("handleRichMenuDelete", () => {
  const env = createMockEnv();
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 401 without token", async () => {
    const res = await handleRichMenuDelete(
      jsonRequest("https://x.com", { botConfigId: "bc1", richmenuId: "rm1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 without botConfigId", async () => {
    const res = await handleRichMenuDelete(
      jsonRequest("https://x.com", { richmenuId: "rm1" }, "tok"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 without richmenuId", async () => {
    const res = await handleRichMenuDelete(
      jsonRequest("https://x.com", { botConfigId: "bc1" }, "tok"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns success on delete", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockDeleteRichMenu.mockResolvedValueOnce(undefined);

    const res = await handleRichMenuDelete(
      jsonRequest(
        "https://x.com",
        { botConfigId: "bc1", richmenuId: "rm1" },
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true });
  });

  it("returns 400 on ConnectError", async () => {
    const { ConnectError } = await import("@connectrpc/connect");
    mockGetConfig.mockRejectedValueOnce(new ConnectError("fail", 3));

    const res = await handleRichMenuDelete(
      jsonRequest(
        "https://x.com",
        { botConfigId: "bc1", richmenuId: "rm1" },
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 500 on regular Error", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockDeleteRichMenu.mockRejectedValueOnce(new Error("fail"));

    const res = await handleRichMenuDelete(
      jsonRequest(
        "https://x.com",
        { botConfigId: "bc1", richmenuId: "rm1" },
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(500);
  });

  it("throws non-Error", async () => {
    mockGetConfig.mockRejectedValueOnce(null);

    await expect(
      handleRichMenuDelete(
        jsonRequest(
          "https://x.com",
          { botConfigId: "bc1", richmenuId: "rm1" },
          "tok",
        ),
        env,
      ),
    ).rejects.toBeNull();
  });
});

// ---------- handleRichMenuImageUpload ----------

describe("handleRichMenuImageUpload", () => {
  const env = createMockEnv();
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 401 without token", async () => {
    const form = new FormData();
    form.append("botConfigId", "bc1");
    const req = new Request("https://x.com", { method: "POST", body: form });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(401);
  });

  it("returns 400 on invalid form data", async () => {
    const req = new Request("https://x.com", {
      method: "POST",
      headers: {
        Authorization: "Bearer tok",
        "Content-Type": "text/plain",
      },
      body: "not form data",
    });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Invalid multipart form data");
  });

  it("returns 400 without required fields", async () => {
    const res = await handleRichMenuImageUpload(
      formDataRequest("https://x.com", { botConfigId: "bc1" }, "tok"),
      env,
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe(
      "botConfigId, richmenuId, and image are required",
    );
  });

  it("returns 400 without botConfigId", async () => {
    const file = new File(["x"], "img.png", { type: "image/png" });
    const res = await handleRichMenuImageUpload(
      formDataRequest(
        "https://x.com",
        { richmenuId: "rm1", image: file } as Record<string, string | File>,
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 when image exceeds 1MB", async () => {
    const bigContent = new Uint8Array(1024 * 1024 + 1);
    const file = new File([bigContent], "big.png", { type: "image/png" });
    const res = await handleRichMenuImageUpload(
      formDataRequest(
        "https://x.com",
        {
          botConfigId: "bc1",
          richmenuId: "rm1",
          image: file,
        } as Record<string, string | File>,
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Image must be 1MB or less");
  });

  it("returns 400 for unsupported extension", async () => {
    const file = new File(["x"], "img.gif", { type: "image/gif" });
    const res = await handleRichMenuImageUpload(
      formDataRequest(
        "https://x.com",
        {
          botConfigId: "bc1",
          richmenuId: "rm1",
          image: file,
        } as Record<string, string | File>,
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Image must be JPEG or PNG");
  });

  it("accepts .png extension", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockUploadImage.mockResolvedValueOnce(undefined);
    const file = new File(["x"], "img.png", { type: "image/png" });
    const res = await handleRichMenuImageUpload(
      formDataRequest(
        "https://x.com",
        {
          botConfigId: "bc1",
          richmenuId: "rm1",
          image: file,
        } as Record<string, string | File>,
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true });
  });

  it("accepts .jpg extension", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockUploadImage.mockResolvedValueOnce(undefined);
    const file = new File(["x"], "photo.jpg", { type: "image/jpeg" });
    const res = await handleRichMenuImageUpload(
      formDataRequest(
        "https://x.com",
        {
          botConfigId: "bc1",
          richmenuId: "rm1",
          image: file,
        } as Record<string, string | File>,
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(200);
  });

  it("accepts .jpeg extension", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockUploadImage.mockResolvedValueOnce(undefined);
    const file = new File(["x"], "photo.JPEG", { type: "image/jpeg" });
    const res = await handleRichMenuImageUpload(
      formDataRequest(
        "https://x.com",
        {
          botConfigId: "bc1",
          richmenuId: "rm1",
          image: file,
        } as Record<string, string | File>,
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(200);
  });

  it("accepts .jpeg extension", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockUploadImage.mockResolvedValueOnce(undefined);
    const file = new File(["x"], "photo.jpeg", { type: "image/jpeg" });
    const res = await handleRichMenuImageUpload(
      formDataRequest(
        "https://x.com",
        {
          botConfigId: "bc1",
          richmenuId: "rm1",
          image: file,
        } as Record<string, string | File>,
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(200);
  });

  it("returns 400 on ConnectError", async () => {
    const { ConnectError } = await import("@connectrpc/connect");
    mockGetConfig.mockRejectedValueOnce(new ConnectError("fail", 3));
    const file = new File(["x"], "img.png", { type: "image/png" });
    const res = await handleRichMenuImageUpload(
      formDataRequest(
        "https://x.com",
        {
          botConfigId: "bc1",
          richmenuId: "rm1",
          image: file,
        } as Record<string, string | File>,
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 500 on regular Error", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockUploadImage.mockRejectedValueOnce(new Error("upload fail"));
    const file = new File(["x"], "img.png", { type: "image/png" });
    const res = await handleRichMenuImageUpload(
      formDataRequest(
        "https://x.com",
        {
          botConfigId: "bc1",
          richmenuId: "rm1",
          image: file,
        } as Record<string, string | File>,
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(500);
  });

  it("throws non-Error", async () => {
    mockGetConfig.mockRejectedValueOnce(false);
    const file = new File(["x"], "img.png", { type: "image/png" });
    await expect(
      handleRichMenuImageUpload(
        formDataRequest(
          "https://x.com",
          {
            botConfigId: "bc1",
            richmenuId: "rm1",
            image: file,
          } as Record<string, string | File>,
          "tok",
        ),
        env,
      ),
    ).rejects.toBe(false);
  });
});

// ---------- handleRichMenuDefaultSet ----------

describe("handleRichMenuDefaultSet", () => {
  const env = createMockEnv();
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 401 without token", async () => {
    const res = await handleRichMenuDefaultSet(
      jsonRequest("https://x.com", { botConfigId: "bc1", richmenuId: "rm1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 without botConfigId", async () => {
    const res = await handleRichMenuDefaultSet(
      jsonRequest("https://x.com", { richmenuId: "rm1" }, "tok"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 without richmenuId", async () => {
    const res = await handleRichMenuDefaultSet(
      jsonRequest("https://x.com", { botConfigId: "bc1" }, "tok"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns success on set default", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockSetDefaultRichMenu.mockResolvedValueOnce(undefined);

    const res = await handleRichMenuDefaultSet(
      jsonRequest(
        "https://x.com",
        { botConfigId: "bc1", richmenuId: "rm1" },
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true });
  });

  it("returns 400 on ConnectError", async () => {
    const { ConnectError } = await import("@connectrpc/connect");
    mockGetConfig.mockRejectedValueOnce(new ConnectError("fail", 3));

    const res = await handleRichMenuDefaultSet(
      jsonRequest(
        "https://x.com",
        { botConfigId: "bc1", richmenuId: "rm1" },
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 500 on regular Error", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockSetDefaultRichMenu.mockRejectedValueOnce(new Error("fail"));

    const res = await handleRichMenuDefaultSet(
      jsonRequest(
        "https://x.com",
        { botConfigId: "bc1", richmenuId: "rm1" },
        "tok",
      ),
      env,
    );
    expect(res.status).toBe(500);
  });

  it("throws non-Error", async () => {
    mockGetConfig.mockRejectedValueOnce(undefined);

    await expect(
      handleRichMenuDefaultSet(
        jsonRequest(
          "https://x.com",
          { botConfigId: "bc1", richmenuId: "rm1" },
          "tok",
        ),
        env,
      ),
    ).rejects.toBeUndefined();
  });
});

// ---------- handleRichMenuDefaultDelete ----------

describe("handleRichMenuDefaultDelete", () => {
  const env = createMockEnv();
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 401 without token", async () => {
    const res = await handleRichMenuDefaultDelete(
      jsonRequest("https://x.com", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 without botConfigId", async () => {
    const res = await handleRichMenuDefaultDelete(
      jsonRequest("https://x.com", {}, "tok"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns success on delete default", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockDeleteDefaultRichMenu.mockResolvedValueOnce(undefined);

    const res = await handleRichMenuDefaultDelete(
      jsonRequest("https://x.com", { botConfigId: "bc1" }, "tok"),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true });
  });

  it("returns 400 on ConnectError", async () => {
    const { ConnectError } = await import("@connectrpc/connect");
    mockGetConfig.mockRejectedValueOnce(new ConnectError("fail", 3));

    const res = await handleRichMenuDefaultDelete(
      jsonRequest("https://x.com", { botConfigId: "bc1" }, "tok"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 500 on regular Error", async () => {
    mockGetConfig.mockResolvedValueOnce(defaultCreds);
    mockDeleteDefaultRichMenu.mockRejectedValueOnce(new Error("fail"));

    const res = await handleRichMenuDefaultDelete(
      jsonRequest("https://x.com", { botConfigId: "bc1" }, "tok"),
      env,
    );
    expect(res.status).toBe(500);
  });

  it("throws non-Error", async () => {
    mockGetConfig.mockRejectedValueOnce("str");

    await expect(
      handleRichMenuDefaultDelete(
        jsonRequest("https://x.com", { botConfigId: "bc1" }, "tok"),
        env,
      ),
    ).rejects.toBe("str");
  });
});
