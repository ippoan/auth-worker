import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import {
  testEnv,
  authJsonRequest,
  authRequest,
  noAuthJsonRequest,
  noAuthRequest,
  restoreFetch,
  waitIfLive,
  isLive,
} from "../helpers/stub-or-real";
import { makeJwt, TEST_TENANT_ID } from "../helpers/live-env";
import { TEST_JWT_SECRET } from "../helpers/mock-env";
import type { Env } from "../../src/index";

// 認証情報の取得は buildAdminForwardHeaders で JWT を検証してから rust へ転送する
// (#434 の tenant header 対応)。creds まで届くテストは JWT_SECRET で署名した token を使う。
const VALID_AUTH = `Bearer ${makeJwt(TEST_JWT_SECRET)}`;

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

/** ALC_LINEWORKS の binding の偽物 (token の口)。呼ばれた要求を記録する。 */
function lineworksBinding(respond: () => Response): { fetcher: Fetcher; calls: Request[] } {
  const calls: Request[] = [];
  const fetcher = {
    fetch: vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(new Request(input, init));
      return respond();
    }),
  } as unknown as Fetcher;
  return { fetcher, calls };
}

// Helper: getBotAccess が alc-lineworks の token の口から token を取れるようにする
function stubGetCreds(env: Env): Request[] {
  const lw = lineworksBinding(
    () =>
      new Response(JSON.stringify({ access_token: "at-1", expires_at: 1, bot_id: "bid" }), {
        status: 200,
      }),
  );
  env.ALC_LINEWORKS = lw.fetcher;
  return lw.calls;
}

const BOT = { accessToken: "at-1", botId: "bid" };

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
    stubGetCreds(env);
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
    stubGetCreds(env);
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

  it("asks the token endpoint with the caller's tenant and scope=bot, then uses that token", async () => {
    const calls = stubGetCreds(env);
    vi.mocked(listRichMenus).mockResolvedValueOnce([]);
    vi.mocked(getDefaultRichMenu).mockResolvedValueOnce(null);

    const res = await handleRichMenuList(
      authJsonRequest("/x", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(200);
    expect(calls).toHaveLength(1);
    expect(new URL(calls[0]!.url).pathname).toBe("/api/internal/lineworks/token");
    expect(calls[0]!.headers.get("X-Tenant-ID")).toBe(TEST_TENANT_ID);
    expect(await calls[0]!.json()).toEqual({ bot_config_id: "bc1", scope: "bot" });
    expect(vi.mocked(listRichMenus)).toHaveBeenCalledWith(BOT);
    expect(vi.mocked(getDefaultRichMenu)).toHaveBeenCalledWith(BOT);
  });

  it("returns 500 when the token endpoint fails", async () => {
    const lw = lineworksBinding(
      () =>
        new Response(JSON.stringify({ error: "bot_config_not_found", message: "x" }), {
          status: 404,
        }),
    );
    env.ALC_LINEWORKS = lw.fetcher;

    const res = await handleRichMenuList(
      authJsonRequest("/x", { botConfigId: "bc1" }),
      env,
    );
    expect(res.status).toBe(500);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Failed to get LINE WORKS token: 404 bot_config_not_found");
  });

  it("returns 500 Forbidden for a non-admin caller without asking for a token", async () => {
    const calls = stubGetCreds(env);
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${makeJwt(TEST_JWT_SECRET, { role: "user" })}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ botConfigId: "bc1" }),
    });
    const res = await handleRichMenuList(req, env);
    expect(res.status).toBe(500);
    expect(((await res.json()) as { error: string }).error).toBe("Forbidden");
    expect(calls).toHaveLength(0);
  });

  it("returns 500 when listRichMenus throws", async () => {
    stubGetCreds(env);
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
    stubGetCreds(env);
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
    stubGetCreds(env);
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
    stubGetCreds(env);
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
    stubGetCreds(env);
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
        Authorization: VALID_AUTH,
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
      headers: { Authorization: VALID_AUTH },
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
      headers: { Authorization: VALID_AUTH },
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
      headers: { Authorization: VALID_AUTH },
      body: formData,
    });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Image must be JPEG or PNG");
  });

  it("returns success on valid PNG upload", async () => {
    stubGetCreds(env);
    vi.mocked(uploadImage).mockResolvedValueOnce(undefined);

    const formData = new FormData();
    formData.append("botConfigId", "bc1");
    formData.append("richmenuId", "rm1");
    formData.append("image", new Blob(["img"], { type: "image/png" }), "menu.png");
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      headers: { Authorization: VALID_AUTH },
      body: formData,
    });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(200);
    const data = (await res.json()) as { success: boolean };
    expect(data.success).toBe(true);
  });

  it("returns success on valid JPEG upload", async () => {
    stubGetCreds(env);
    vi.mocked(uploadImage).mockResolvedValueOnce(undefined);

    const formData = new FormData();
    formData.append("botConfigId", "bc1");
    formData.append("richmenuId", "rm1");
    formData.append("image", new Blob(["img"], { type: "image/jpeg" }), "menu.jpg");
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      headers: { Authorization: VALID_AUTH },
      body: formData,
    });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(200);
  });

  it("accepts .jpeg extension", async () => {
    stubGetCreds(env);
    vi.mocked(uploadImage).mockResolvedValueOnce(undefined);

    const formData = new FormData();
    formData.append("botConfigId", "bc1");
    formData.append("richmenuId", "rm1");
    formData.append("image", new Blob(["img"], { type: "image/jpeg" }), "menu.jpeg");
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      headers: { Authorization: VALID_AUTH },
      body: formData,
    });
    const res = await handleRichMenuImageUpload(req, env);
    expect(res.status).toBe(200);
  });

  it("returns 500 when uploadImage throws", async () => {
    stubGetCreds(env);
    vi.mocked(uploadImage).mockRejectedValueOnce(new Error("upload failed"));

    const formData = new FormData();
    formData.append("botConfigId", "bc1");
    formData.append("richmenuId", "rm1");
    formData.append("image", new Blob(["img"], { type: "image/png" }), "menu.png");
    const req = new Request("https://auth.test.example/x", {
      method: "POST",
      headers: { Authorization: VALID_AUTH },
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
    stubGetCreds(env);
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
    stubGetCreds(env);
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
    stubGetCreds(env);
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
    stubGetCreds(env);
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
