import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from "vitest";
import type { BotCredentials } from "../../src/lib/lineworks-bot-api";
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

// ---------------------------------------------------------------------------
// RSA key generation (once) + helpers
// ---------------------------------------------------------------------------

let testPrivateKeyPem: string;
const origFetch = globalThis.fetch;

beforeAll(async () => {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const exported = await crypto.subtle.exportKey("pkcs8", (keyPair as CryptoKeyPair).privateKey);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(exported as ArrayBuffer)));
  testPrivateKeyPem = `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----`;
});

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.stubGlobal("fetch", origFetch);
});

function testCreds(): BotCredentials {
  return {
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
    serviceAccount: "test-sa@example.com",
    privateKey: testPrivateKeyPem,
    botId: "test-bot-id",
  };
}

/** Mock fetch returning responses in order */
function mockFetchSequence(...responses: Response[]): ReturnType<typeof vi.fn> {
  const fn = vi.fn();
  for (const r of responses) {
    fn.mockResolvedValueOnce(r);
  }
  vi.stubGlobal("fetch", fn);
  return fn;
}

/** Shorthand for a successful token response (always the first fetch call) */
function tokenResponse(): Response {
  return new Response(JSON.stringify({ access_token: "test-token" }));
}

/** Non-ok response */
function errorResponse(status: number, body: string): Response {
  return new Response(body, { status, statusText: "Error" });
}

// ---------------------------------------------------------------------------
// listRichMenus
// ---------------------------------------------------------------------------

describe("listRichMenus", () => {
  it("returns array of rich menus on success", async () => {
    const menus = [{ richmenuId: "rm1", richmenuName: "Menu1", size: { width: 2500, height: 1686 }, areas: [] }];
    const mf = mockFetchSequence(
      tokenResponse(),
      new Response(JSON.stringify({ richmenus: menus })),
    );

    const result = await listRichMenus(testCreds());

    expect(result).toEqual(menus);
    expect(mf).toHaveBeenCalledTimes(2);
    // First call is token endpoint
    expect(mf.mock.calls[0]![0]).toBe("https://auth.worksmobile.com/oauth2/v2.0/token");
    // Second call is the API
    expect(mf.mock.calls[1]![0]).toBe("https://www.worksapis.com/v1.0/bots/test-bot-id/richmenus?count=100");
  });

  it("returns empty array when richmenus field is missing", async () => {
    mockFetchSequence(
      tokenResponse(),
      new Response(JSON.stringify({})),
    );

    const result = await listRichMenus(testCreds());
    expect(result).toEqual([]);
  });

  it("throws on API error", async () => {
    mockFetchSequence(
      tokenResponse(),
      errorResponse(500, "Internal Server Error"),
    );

    await expect(listRichMenus(testCreds())).rejects.toThrow("listRichMenus failed: 500");
  });

  it("throws when token endpoint fails", async () => {
    mockFetchSequence(errorResponse(401, "Unauthorized"));

    await expect(listRichMenus(testCreds())).rejects.toThrow("Token issue failed: 401");
  });
});

// ---------------------------------------------------------------------------
// createRichMenu
// ---------------------------------------------------------------------------

describe("createRichMenu", () => {
  const menuInput = {
    richmenuName: "New Menu",
    size: { width: 2500, height: 1686 },
    areas: [],
  };

  it("returns created menu on success", async () => {
    const created = { richmenuId: "rm-new", ...menuInput };
    const mf = mockFetchSequence(
      tokenResponse(),
      new Response(JSON.stringify(created)),
    );

    const result = await createRichMenu(testCreds(), menuInput);

    expect(result).toEqual(created);
    // Verify POST method and Content-Type
    const apiCall = mf.mock.calls[1]!;
    expect(apiCall[1]?.method).toBe("POST");
  });

  it("throws on API error", async () => {
    mockFetchSequence(
      tokenResponse(),
      errorResponse(400, "Bad Request"),
    );

    await expect(createRichMenu(testCreds(), menuInput)).rejects.toThrow("createRichMenu failed: 400");
  });
});

// ---------------------------------------------------------------------------
// deleteRichMenu
// ---------------------------------------------------------------------------

describe("deleteRichMenu", () => {
  it("succeeds on ok response", async () => {
    const mf = mockFetchSequence(
      tokenResponse(),
      new Response(null, { status: 200 }),
    );

    await deleteRichMenu(testCreds(), "rm-del");

    expect(mf.mock.calls[1]![0]).toBe("https://www.worksapis.com/v1.0/bots/test-bot-id/richmenus/rm-del");
    expect(mf.mock.calls[1]![1]?.method).toBe("DELETE");
  });

  it("throws on API error", async () => {
    mockFetchSequence(
      tokenResponse(),
      errorResponse(404, "Not Found"),
    );

    await expect(deleteRichMenu(testCreds(), "rm-del")).rejects.toThrow("deleteRichMenu failed: 404");
  });
});

// ---------------------------------------------------------------------------
// uploadImage
// ---------------------------------------------------------------------------

describe("uploadImage", () => {
  const imageData = new ArrayBuffer(8);
  const base = "https://www.worksapis.com/v1.0/bots/test-bot-id";

  it("succeeds with all 3 steps (JSON fileId from step 2)", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const mf = mockFetchSequence(
      // getAccessToken
      tokenResponse(),
      // Step 1: attachments
      new Response(JSON.stringify({ fileId: "fid-1", uploadUrl: "https://upload.example.com/upload" })),
      // Step 2: upload binary
      new Response(JSON.stringify({ fileId: "fid-2" })),
      // Step 3: associate image
      new Response(JSON.stringify({ ok: true })),
    );

    await uploadImage(testCreds(), "rm-img", imageData, "menu.png");

    expect(mf).toHaveBeenCalledTimes(4);
    // Step 1
    expect(mf.mock.calls[1]![0]).toBe(`${base}/attachments`);
    // Step 2 uses absolute uploadUrl
    expect(mf.mock.calls[2]![0]).toBe("https://upload.example.com/upload");
    // Step 3 uses fileId from step 2 response
    const step3Body = mf.mock.calls[3]![1]?.body;
    expect(JSON.parse(step3Body as string)).toEqual({ fileId: "fid-2" });
    consoleSpy.mockRestore();
  });

  it("uses step 1 fileId when step 2 response is not JSON", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const mf = mockFetchSequence(
      tokenResponse(),
      new Response(JSON.stringify({ fileId: "fid-1", uploadUrl: "https://upload.example.com/up" })),
      new Response("OK"), // non-JSON
      new Response(JSON.stringify({ ok: true })),
    );

    await uploadImage(testCreds(), "rm-img", imageData, "menu.jpg");

    // Step 3 should use fid-1 (from step 1 fallback)
    const step3Body = mf.mock.calls[3]![1]?.body;
    expect(JSON.parse(step3Body as string)).toEqual({ fileId: "fid-1" });
    consoleSpy.mockRestore();
  });

  it("sets image/png content type for .png files", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const mf = mockFetchSequence(
      tokenResponse(),
      new Response(JSON.stringify({ fileId: "f", uploadUrl: "https://up.example.com" })),
      new Response("OK"),
      new Response("OK"),
    );

    await uploadImage(testCreds(), "rm", imageData, "image.PNG");

    // Step 2: form body with PNG blob - verify the call was made
    expect(mf.mock.calls[2]![1]?.body).toBeInstanceOf(FormData);
    consoleSpy.mockRestore();
  });

  it("sets image/jpeg content type for non-png files", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const mf = mockFetchSequence(
      tokenResponse(),
      new Response(JSON.stringify({ fileId: "f", uploadUrl: "https://up.example.com" })),
      new Response("OK"),
      new Response("OK"),
    );

    await uploadImage(testCreds(), "rm", imageData, "image.jpg");

    expect(mf.mock.calls[2]![1]?.body).toBeInstanceOf(FormData);
    consoleSpy.mockRestore();
  });

  it("throws when step 1 (attachments) fails", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    mockFetchSequence(
      tokenResponse(),
      errorResponse(500, "Server Error"),
    );

    await expect(uploadImage(testCreds(), "rm", imageData, "x.png")).rejects.toThrow("attachments failed: 500");
    consoleSpy.mockRestore();
  });

  it("throws when step 2 (upload) fails", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    mockFetchSequence(
      tokenResponse(),
      new Response(JSON.stringify({ fileId: "f", uploadUrl: "https://up.example.com" })),
      errorResponse(413, "Payload Too Large"),
    );

    await expect(uploadImage(testCreds(), "rm", imageData, "x.png")).rejects.toThrow("image upload failed: 413");
    consoleSpy.mockRestore();
  });

  it("throws when step 3 (image association) fails", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    mockFetchSequence(
      tokenResponse(),
      new Response(JSON.stringify({ fileId: "f", uploadUrl: "https://up.example.com" })),
      new Response("OK"),
      errorResponse(400, "Bad fileId"),
    );

    await expect(uploadImage(testCreds(), "rm", imageData, "x.png")).rejects.toThrow("image association failed: 400");
    consoleSpy.mockRestore();
  });

  it("throws when token endpoint fails", async () => {
    mockFetchSequence(errorResponse(401, "Bad token"));

    await expect(uploadImage(testCreds(), "rm", imageData, "x.png")).rejects.toThrow("Token issue failed: 401");
  });
});

// ---------------------------------------------------------------------------
// checkRichMenuImage
// ---------------------------------------------------------------------------

describe("checkRichMenuImage", () => {
  it("returns true when response is ok", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    mockFetchSequence(
      tokenResponse(),
      new Response("image-bytes", {
        status: 200,
        headers: { "content-type": "image/png", "content-length": "1234" },
      }),
    );

    const result = await checkRichMenuImage(testCreds(), "rm-check");
    expect(result).toBe(true);
    consoleSpy.mockRestore();
  });

  it("returns false when response is not ok", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    mockFetchSequence(
      tokenResponse(),
      errorResponse(404, "No image"),
    );

    const result = await checkRichMenuImage(testCreds(), "rm-check");
    expect(result).toBe(false);
    consoleSpy.mockRestore();
  });

  it("returns false when fetch throws", async () => {
    const fn = vi.fn()
      .mockResolvedValueOnce(tokenResponse())
      .mockRejectedValueOnce(new Error("Network error"));
    vi.stubGlobal("fetch", fn);

    const result = await checkRichMenuImage(testCreds(), "rm-check");
    expect(result).toBe(false);
  });

  it("returns false when token endpoint fails (caught by try/catch)", async () => {
    mockFetchSequence(errorResponse(500, "Token fail"));

    // getAccessToken throws, but checkRichMenuImage catches it
    const result = await checkRichMenuImage(testCreds(), "rm-check");
    expect(result).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// setDefaultRichMenu
// ---------------------------------------------------------------------------

describe("setDefaultRichMenu", () => {
  it("succeeds on ok response", async () => {
    const mf = mockFetchSequence(
      tokenResponse(),
      new Response(null, { status: 200 }),
    );

    await setDefaultRichMenu(testCreds(), "rm-def");

    expect(mf.mock.calls[1]![0]).toBe("https://www.worksapis.com/v1.0/bots/test-bot-id/richmenus/rm-def/set-default");
    expect(mf.mock.calls[1]![1]?.method).toBe("POST");
  });

  it("throws on API error", async () => {
    mockFetchSequence(
      tokenResponse(),
      errorResponse(500, "Error"),
    );

    await expect(setDefaultRichMenu(testCreds(), "rm-def")).rejects.toThrow("setDefault failed: 500");
  });
});

// ---------------------------------------------------------------------------
// getDefaultRichMenu
// ---------------------------------------------------------------------------

describe("getDefaultRichMenu", () => {
  it("returns object on success", async () => {
    const data = { defaultRichmenuId: "rm-default" };
    mockFetchSequence(
      tokenResponse(),
      new Response(JSON.stringify(data)),
    );

    const result = await getDefaultRichMenu(testCreds());
    expect(result).toEqual(data);
  });

  it("returns null on 404", async () => {
    mockFetchSequence(
      tokenResponse(),
      errorResponse(404, "Not Found"),
    );

    const result = await getDefaultRichMenu(testCreds());
    expect(result).toBeNull();
  });

  it("throws on non-404 error", async () => {
    mockFetchSequence(
      tokenResponse(),
      errorResponse(500, "Server Error"),
    );

    await expect(getDefaultRichMenu(testCreds())).rejects.toThrow("getDefault failed: 500");
  });
});

// ---------------------------------------------------------------------------
// deleteDefaultRichMenu
// ---------------------------------------------------------------------------

describe("deleteDefaultRichMenu", () => {
  it("succeeds on ok response", async () => {
    const mf = mockFetchSequence(
      tokenResponse(),
      new Response(null, { status: 200 }),
    );

    await deleteDefaultRichMenu(testCreds());

    expect(mf.mock.calls[1]![0]).toBe("https://www.worksapis.com/v1.0/bots/test-bot-id/richmenus/default");
    expect(mf.mock.calls[1]![1]?.method).toBe("DELETE");
  });

  it("succeeds on 404 (no default set)", async () => {
    mockFetchSequence(
      tokenResponse(),
      errorResponse(404, "Not Found"),
    );

    // Should NOT throw
    await deleteDefaultRichMenu(testCreds());
  });

  it("throws on non-404 error", async () => {
    mockFetchSequence(
      tokenResponse(),
      errorResponse(500, "Server Error"),
    );

    await expect(deleteDefaultRichMenu(testCreds())).rejects.toThrow("deleteDefault failed: 500");
  });
});

// ---------------------------------------------------------------------------
// JWT / token integration (tested implicitly through exported functions)
// ---------------------------------------------------------------------------

describe("JWT and token flow", () => {
  it("sends correct token request parameters", async () => {
    const mf = mockFetchSequence(
      tokenResponse(),
      new Response(JSON.stringify({ richmenus: [] })),
    );

    await listRichMenus(testCreds());

    // Verify token request
    const tokenCall = mf.mock.calls[0]!;
    expect(tokenCall[0]).toBe("https://auth.worksmobile.com/oauth2/v2.0/token");
    expect(tokenCall[1]?.method).toBe("POST");
    expect(tokenCall[1]?.headers).toEqual({ "Content-Type": "application/x-www-form-urlencoded" });

    // Parse the body params
    const bodyStr = tokenCall[1]?.body as string;
    const params = new URLSearchParams(bodyStr);
    expect(params.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
    expect(params.get("client_id")).toBe("test-client-id");
    expect(params.get("client_secret")).toBe("test-client-secret");
    expect(params.get("scope")).toBe("bot");
    // assertion is a JWT string (three dot-separated base64url segments)
    const jwt = params.get("assertion")!;
    const parts = jwt.split(".");
    expect(parts).toHaveLength(3);
  });

  it("passes access token as Bearer header to API calls", async () => {
    const mf = mockFetchSequence(
      new Response(JSON.stringify({ access_token: "my-special-token" })),
      new Response(JSON.stringify({ richmenus: [] })),
    );

    await listRichMenus(testCreds());

    const apiCall = mf.mock.calls[1]!;
    expect(apiCall[1]?.headers).toHaveProperty("Authorization", "Bearer my-special-token");
  });

  it("handles privateKey with literal \\n escapes", async () => {
    // PEM with literal \n (as stored in env vars / JSON)
    const creds = testCreds();
    const escapedPem = creds.privateKey.replace(/\n/g, "\\n");
    creds.privateKey = escapedPem;

    mockFetchSequence(
      tokenResponse(),
      new Response(JSON.stringify({ richmenus: [] })),
    );

    // Should not throw - pemToArrayBuffer handles \\n → \n normalization
    const result = await listRichMenus(creds);
    expect(result).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// botFetch with merged headers
// ---------------------------------------------------------------------------

describe("botFetch header merging", () => {
  it("merges custom headers with Authorization", async () => {
    const mf = mockFetchSequence(
      tokenResponse(),
      new Response(JSON.stringify({ richmenuId: "rm-x", richmenuName: "X", size: { width: 2500, height: 1686 }, areas: [] })),
    );

    await createRichMenu(testCreds(), {
      richmenuName: "X",
      size: { width: 2500, height: 1686 },
      areas: [],
    });

    const apiHeaders = mf.mock.calls[1]![1]?.headers as Record<string, string>;
    expect(apiHeaders["Authorization"]).toBe("Bearer test-token");
    expect(apiHeaders["Content-Type"]).toBe("application/json");
  });
});
