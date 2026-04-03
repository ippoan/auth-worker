import { describe, it, expect } from "vitest";
import {
  jsonResponse,
  corsJsonResponse,
  corsPreflight,
  extractToken,
  errorResponse,
} from "../../src/lib/errors";

describe("jsonResponse", () => {
  it("returns JSON with default 200 status", async () => {
    const res = jsonResponse({ ok: true });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("application/json");
    expect(await res.json()).toEqual({ ok: true });
  });

  it("accepts custom status code", () => {
    const res = jsonResponse({ error: "bad" }, 400);
    expect(res.status).toBe(400);
  });
});

describe("corsJsonResponse", () => {
  it("returns JSON with CORS headers", async () => {
    const res = corsJsonResponse({ data: 1 });
    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(res.headers.get("Access-Control-Allow-Methods")).toBe("POST, OPTIONS");
    expect(res.headers.get("Access-Control-Allow-Headers")).toBe("Content-Type, Authorization");
    expect(await res.json()).toEqual({ data: 1 });
  });

  it("accepts custom status", () => {
    const res = corsJsonResponse({ error: "fail" }, 401);
    expect(res.status).toBe(401);
  });
});

describe("corsPreflight", () => {
  it("returns null body with CORS headers", () => {
    const res = corsPreflight();
    expect(res.body).toBeNull();
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });
});

describe("extractToken", () => {
  it("extracts Bearer token", () => {
    const req = new Request("https://x.com", {
      headers: { Authorization: "Bearer abc123" },
    });
    expect(extractToken(req)).toBe("abc123");
  });

  it("returns null without Authorization header", () => {
    expect(extractToken(new Request("https://x.com"))).toBeNull();
  });

  it("returns null for non-Bearer scheme", () => {
    const req = new Request("https://x.com", {
      headers: { Authorization: "Basic abc" },
    });
    expect(extractToken(req)).toBeNull();
  });
});

describe("errorResponse", () => {
  it("returns JSON error with status", async () => {
    const res = errorResponse(404, "Not found");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "Not found" });
  });
});
