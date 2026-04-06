import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import {
  stubOrReal,
  testEnv,
  authJsonRequest,
  authRequest,
  noAuthJsonRequest,
  noAuthRequest,
  restoreFetch,
  waitIfLive,
  isLive,
} from "../helpers/stub-or-real";

// Mock lineworks-bot-api to avoid real API calls and crypto operations
vi.mock("../../src/lib/lineworks-bot-api", () => ({
  listRichMenus: vi.fn(),
  createRichMenu: vi.fn(),
  deleteRichMenu: vi.fn(),
  uploadImage: vi.fn(),
  checkRichMenuImage: vi.fn(),
  setDefaultRichMenu: vi.fn(),
  getDefaultRichMenu: vi.fn(),
  deleteDefaultRichMenu: vi.fn(),
}));

import {
  handleRichMenuList,
  handleRichMenuCreate,
  handleRichMenuDelete,
  handleRichMenuImageUpload,
  handleRichMenuDefaultSet,
  handleRichMenuDefaultDelete,
} from "../../src/handlers/api-rich-menu";
import {
  listRichMenus,
  createRichMenu,
  deleteRichMenu,
  uploadImage,
  checkRichMenuImage,
  setDefaultRichMenu,
  getDefaultRichMenu,
  deleteDefaultRichMenu,
} from "../../src/lib/lineworks-bot-api";

afterAll(() => restoreFetch());
waitIfLive();

// Helper: mock getCredsFromConfig (it calls fetch internally)
function stubGetCreds(): void {
  stubOrReal(
    new Response(
      JSON.stringify({
        client_id: "cid",
        client_secret: "csec",
        service_account: "sa",
        private_key: "pk",
        bot_id: "bid",
      }),
      { status: 200 },
    ),
  );
}

// ---------- handleRichMenuList ----------

describe("handleRichMenuList", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleRichMenuList(
      noAuthJsonRequest("/x", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 when botConfigId is missing", async () => {
    const res = await handleRichMenuList(authJsonRequest("/x", {}), env);
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("botConfigId is required");
  });

  it("returns richmenus with image status and default on success", async () => {
    stubGetCreds();
    vi.mocked(listRichMenus).mockResolvedValueOnce([
      {
        richmenuId: "rm1",
        richmenuName: "Menu1",
        size: { width: 2500, height: 1686 },
        areas: [],
      },
    ]);
    vi.mocked(getDefaultRichMenu).mockResolvedValueOnce({
      defaultRichmenuId: "rm1",
    });
    vi.mocked(checkRichMenuImage).mockResolvedValueOnce(true);

    const res = await handleRichMenuList(
      authJsonRequest("/x", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      richmenus: Array<{ richmenuId: string }>;
      defaultRichmenuId: string | null;
      imageStatus: Record<string, boolean>;
    };
    expect(data.richmenus).toHaveLength(1);
    expect(data.richmenus[0]!.richmenuId).toBe("rm1");
    expect(data.defaultRichmenuId).toBe("rm1");
    expect(data.imageStatus["rm1"]).toBe(true);
  });

  it("returns null defaultRichmenuId when no default set", async () => {
    stubGetCreds();
    vi.mocked(listRichMenus).mockResolvedValueOnce([]);
    vi.mocked(getDefaultRichMenu).mockResolvedValueOnce(null);

    const res = await handleRichMenuList(
      authJsonRequest("/x", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { defaultRichmenuId: string | null };
    expect(data.defaultRichmenuId).toBe(null);
  });

  it("returns 500 when getCredsFromConfig fails", async () => {
    stubOrReal(new Response("Forbidden", { status: 403 }));

    const res = await handleRichMenuList(
      authJsonRequest("/x", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(500);
    const data = (await res.json()) as { error: string };
    expect(data.error).toContain("Failed to get bot config");
  });

  it("returns 500 when listRichMenus throws", async () => {
    stubGetCreds();
    vi.mocked(listRichMenus).mockRejectedValueOnce(new Error("API error"));
    vi.mocked(getDefaultRichMenu).mockResolvedValueOnce(null);

    const res = await handleRichMenuList(
      authJsonRequest("/x", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(500);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("API error");
  });
});

// ---------- handleRichMenuCreate ----------

describe("handleRichMenuCreate", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleRichMenuCreate(
      noAuthJsonRequest("/x", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 when required fields are missing", async () => {
    const res = await handleRichMenuCreate(
      authJsonRequest("/x", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toContain("required");
  });

  it("returns 400 when areas is empty", async () => {
    const res = await handleRichMenuCreate(
      authJsonRequest("/x", {
        botConfigId: "bc1",
        richmenuName: "Menu",
        size: { width: 2500, height: 1686 },
        areas: [],
      }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns created menu on success", async () => {
    stubGetCreds();
    const mockMenu = {
      richmenuId: "rm-new",
      richmenuName: "NewMenu",
      size: { width: 2500, height: 1686 },
      areas: [
        {
          bounds: { x: 0, y: 0, width: 1250, height: 843 },
          action: { type: "uri" as const, uri: "https://example.com" },
        },
      ],
    };
    vi.mocked(createRichMenu).mockResolvedValueOnce(mockMenu);

    const res = await handleRichMenuCreate(
      authJsonRequest("/x", {
        botConfigId: "bc1",
        richmenuName: "NewMenu",
        size: { width: 2500, height: 1686 },
        areas: [
          {
            bounds: { x: 0, y: 0, width: 1250, height: 843 },
            action: { type: "uri", uri: "https://example.com" },
          },
        ],
      }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { richmenuId: string };
    expect(data.richmenuId).toBe("rm-new");
  });

  it("returns 500 when createRichMenu throws", async () => {
    stubGetCreds();
    vi.mocked(createRichMenu).mockRejectedValueOnce(new Error("create failed"));

    const res = await handleRichMenuCreate(
      authJsonRequest("/x", {
        botConfigId: "bc1",
        richmenuName: "Menu",
        size: { width: 2500, height: 1686 },
        areas: [
          {
            bounds: { x: 0, y: 0, width: 100, height: 100 },
            action: { type: "uri" as const, uri: "https://x.com" },
          },
        ],
      }),
      env,
    );
    expect(res.status).toBe(500);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("create failed");
  });
});

// ---------- handleRichMenuDelete ----------

describe("handleRichMenuDelete", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleRichMenuDelete(
      noAuthJsonRequest("/x", { botConfigId: "bc1", richmenuId: "rm1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 when botConfigId is missing", async () => {
    const res = await handleRichMenuDelete(
      authJsonRequest("/x", { richmenuId: "rm1" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 when richmenuId is missing", async () => {
    const res = await handleRichMenuDelete(
      authJsonRequest("/x", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns success on delete", async () => {
    stubGetCreds();
    vi.mocked(deleteRichMenu).mockResolvedValueOnce(undefined);

    const res = await handleRichMenuDelete(
      authJsonRequest("/x", { botConfigId: "bc1", richmenuId: "rm1" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { success: boolean };
    expect(data.success).toBe(true);
  });

  it("returns 500 when deleteRichMenu throws", async () => {
    stubGetCreds();
    vi.mocked(deleteRichMenu).mockRejectedValueOnce(new Error("delete failed"));

    const res = await handleRichMenuDelete(
      authJsonRequest("/x", { botConfigId: "bc1", richmenuId: "rm1" }),
      env,
    );
    expect(res.status).toBe(500);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("delete failed");
  });
});

// ---------- handleRichMenuImageUpload ----------

describe("handleRichMenuImageUpload", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const formData = new FormData();
    formData.append("botConfigId", "bc1");
    formData.append("richmenuId", "rm1");
    formData.append("image", new Blob(["img"], { type: "image/png" }), "test.png");
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      body: formData,
    });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(401);
  });

  it("returns 400 for invalid multipart data", async () => {
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      headers: {
        Authorization: "Bearer test-token",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({}),
    });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Invalid multipart form data");
  });

  it("returns 400 when required fields are missing", async () => {
    const formData = new FormData();
    formData.append("botConfigId", "bc1");
    // missing richmenuId and image
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      headers: { Authorization: "Bearer test-token" },
      body: formData,
    });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toContain("required");
  });

  it("returns 400 when image exceeds 1MB", async () => {
    const largeData = new Uint8Array(1024 * 1024 + 1);
    const formData = new FormData();
    formData.append("botConfigId", "bc1");
    formData.append("richmenuId", "rm1");
    formData.append("image", new Blob([largeData], { type: "image/png" }), "big.png");
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      headers: { Authorization: "Bearer test-token" },
      body: formData,
    });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Image must be 1MB or less");
  });

  it("returns 400 for unsupported image format", async () => {
    const formData = new FormData();
    formData.append("botConfigId", "bc1");
    formData.append("richmenuId", "rm1");
    formData.append("image", new Blob(["gif"], { type: "image/gif" }), "test.gif");
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      headers: { Authorization: "Bearer test-token" },
      body: formData,
    });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Image must be JPEG or PNG");
  });

  it("returns success on valid PNG upload", async () => {
    stubGetCreds();
    vi.mocked(uploadImage).mockResolvedValueOnce(undefined);

    const formData = new FormData();
    formData.append("botConfigId", "bc1");
    formData.append("richmenuId", "rm1");
    formData.append("image", new Blob(["img"], { type: "image/png" }), "menu.png");
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      headers: { Authorization: "Bearer test-token" },
      body: formData,
    });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(200);
    const data = (await res.json()) as { success: boolean };
    expect(data.success).toBe(true);
  });

  it("returns success on valid JPEG upload", async () => {
    stubGetCreds();
    vi.mocked(uploadImage).mockResolvedValueOnce(undefined);

    const formData = new FormData();
    formData.append("botConfigId", "bc1");
    formData.append("richmenuId", "rm1");
    formData.append("image", new Blob(["img"], { type: "image/jpeg" }), "menu.jpg");
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      headers: { Authorization: "Bearer test-token" },
      body: formData,
    });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(200);
  });

  it("accepts .jpeg extension", async () => {
    stubGetCreds();
    vi.mocked(uploadImage).mockResolvedValueOnce(undefined);

    const formData = new FormData();
    formData.append("botConfigId", "bc1");
    formData.append("richmenuId", "rm1");
    formData.append("image", new Blob(["img"], { type: "image/jpeg" }), "menu.jpeg");
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      headers: { Authorization: "Bearer test-token" },
      body: formData,
    });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(200);
  });

  it("returns 500 when uploadImage throws", async () => {
    stubGetCreds();
    vi.mocked(uploadImage).mockRejectedValueOnce(new Error("upload failed"));

    const formData = new FormData();
    formData.append("botConfigId", "bc1");
    formData.append("richmenuId", "rm1");
    formData.append("image", new Blob(["img"], { type: "image/png" }), "menu.png");
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      headers: { Authorization: "Bearer test-token" },
      body: formData,
    });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(500);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("upload failed");
  });
});

// ---------- handleRichMenuDefaultSet ----------

describe("handleRichMenuDefaultSet", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleRichMenuDefaultSet(
      noAuthJsonRequest("/x", { botConfigId: "bc1", richmenuId: "rm1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 when botConfigId is missing", async () => {
    const res = await handleRichMenuDefaultSet(
      authJsonRequest("/x", { richmenuId: "rm1" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 when richmenuId is missing", async () => {
    const res = await handleRichMenuDefaultSet(
      authJsonRequest("/x", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns success on set default", async () => {
    stubGetCreds();
    vi.mocked(setDefaultRichMenu).mockResolvedValueOnce(undefined);

    const res = await handleRichMenuDefaultSet(
      authJsonRequest("/x", { botConfigId: "bc1", richmenuId: "rm1" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { success: boolean };
    expect(data.success).toBe(true);
  });

  it("returns 500 when setDefaultRichMenu throws", async () => {
    stubGetCreds();
    vi.mocked(setDefaultRichMenu).mockRejectedValueOnce(new Error("set failed"));

    const res = await handleRichMenuDefaultSet(
      authJsonRequest("/x", { botConfigId: "bc1", richmenuId: "rm1" }),
      env,
    );
    expect(res.status).toBe(500);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("set failed");
  });
});

// ---------- handleRichMenuDefaultDelete ----------

describe("handleRichMenuDefaultDelete", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleRichMenuDefaultDelete(
      noAuthJsonRequest("/x", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 when botConfigId is missing", async () => {
    const res = await handleRichMenuDefaultDelete(
      authJsonRequest("/x", {}),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns success on delete default", async () => {
    stubGetCreds();
    vi.mocked(deleteDefaultRichMenu).mockResolvedValueOnce(undefined);

    const res = await handleRichMenuDefaultDelete(
      authJsonRequest("/x", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { success: boolean };
    expect(data.success).toBe(true);
  });

  it("returns 500 when deleteDefaultRichMenu throws", async () => {
    stubGetCreds();
    vi.mocked(deleteDefaultRichMenu).mockRejectedValueOnce(
      new Error("delete default failed"),
    );

    const res = await handleRichMenuDefaultDelete(
      authJsonRequest("/x", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(500);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("delete default failed");
  });
});
