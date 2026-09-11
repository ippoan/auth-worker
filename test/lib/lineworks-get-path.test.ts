import { describe, it, expect } from "vitest";
import {
  resolveLineworksGetTarget,
  WORKS_API_ORIGIN,
} from "../../src/lib/lineworks-get-path";

describe("resolveLineworksGetTarget", () => {
  it("maps /v1.0/boards and its sub-paths to board.read", () => {
    expect(resolveLineworksGetTarget("/v1.0/boards", undefined)).toEqual({
      ok: true,
      url: `${WORKS_API_ORIGIN}/v1.0/boards`,
      scope: "board.read",
    });
    expect(
      resolveLineworksGetTarget("/v1.0/boards/4000000000000000001/posts/1/readers", undefined),
    ).toEqual({
      ok: true,
      url: `${WORKS_API_ORIGIN}/v1.0/boards/4000000000000000001/posts/1/readers`,
      scope: "board.read",
    });
  });

  it("maps /v1.0/users and UUID sub-paths (with hyphens) to directory.read", () => {
    expect(
      resolveLineworksGetTarget("/v1.0/users/00000000-0000-4000-8000-000000000001", undefined),
    ).toEqual({
      ok: true,
      url: `${WORKS_API_ORIGIN}/v1.0/users/00000000-0000-4000-8000-000000000001`,
      scope: "directory.read",
    });
  });

  it("appends query parameters URL-encoded", () => {
    expect(
      resolveLineworksGetTarget("/v1.0/boards/recent/posts", { count: "40", cursor: "a+b/c=" }),
    ).toEqual({
      ok: true,
      url: `${WORKS_API_ORIGIN}/v1.0/boards/recent/posts?count=40&cursor=a%2Bb%2Fc%3D`,
      scope: "board.read",
    });
  });

  it("rejects a non-string or relative path", () => {
    expect(resolveLineworksGetTarget(123, undefined)).toEqual({
      ok: false,
      error: "path must be a string starting with /",
    });
    expect(resolveLineworksGetTarget("v1.0/boards", undefined).ok).toBe(false);
  });

  it.each([
    "/v1.0/boards/%2e%2e/bots",
    "/v1.0/boards\\..\\bots",
    "/v1.0/boards?count=1",
    "/v1.0/boards#frag",
    "/v1.0/boards /x",
    "/v1.0/boards\t",
    "/v1.0/boards\n",
    "/v1.0/boards\u0001",
    "/v1.0/boards\u007f",
    "//evil.example/v1.0/boards",
    "/v1.0/boards//x",
  ])("rejects forbidden characters and //: %j", (path) => {
    expect(resolveLineworksGetTarget(path, undefined)).toEqual({
      ok: false,
      error: `path not allowed: ${path}`,
    });
  });

  it("rejects dot segments that URL would collapse", () => {
    expect(resolveLineworksGetTarget("/v1.0/boards/../bots", undefined)).toEqual({
      ok: false,
      error: "path not allowed: /v1.0/boards/../bots",
    });
    expect(resolveLineworksGetTarget("/v1.0/boards/./x", undefined).ok).toBe(false);
  });

  it.each([
    "/v1.0/bots/1/messages",
    "/v1.0/audits/logs/download",
    "/v1.0/boardsX",
    "/v1.0/usersX/1",
    "/V1.0/boards",
  ])("rejects paths outside the allowlist, including prefix look-alikes: %s", (path) => {
    expect(resolveLineworksGetTarget(path, undefined)).toEqual({
      ok: false,
      error: `path not allowed: ${path}`,
    });
  });

  it("rejects a non-object query and non-string values", () => {
    const notObject = { ok: false, error: "query must be an object of string values" };
    expect(resolveLineworksGetTarget("/v1.0/boards", null)).toEqual(notObject);
    expect(resolveLineworksGetTarget("/v1.0/boards", "count=1")).toEqual(notObject);
    expect(resolveLineworksGetTarget("/v1.0/boards", ["a"])).toEqual(notObject);
    expect(resolveLineworksGetTarget("/v1.0/boards", { count: 40 })).toEqual({
      ok: false,
      error: "query.count must be a string",
    });
  });
});
