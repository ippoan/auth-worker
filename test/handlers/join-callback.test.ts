import { describe, it, expect } from "vitest";
import { handleJoinDone } from "../../src/handlers/join-callback";

describe("handleJoinDone", () => {
  it("returns HTML response with correct content type", () => {
    const res = handleJoinDone("test-org");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
  });

  it("includes slug in rendered HTML", async () => {
    const res = handleJoinDone("my-company");
    const html = await res.text();
    expect(html).toContain("my-company");
  });
});
