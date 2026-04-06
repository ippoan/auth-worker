import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/lib/join-html", () => ({
  renderJoinDonePage: vi.fn(
    (slug: string) => `<!DOCTYPE html><html>mock join done ${slug}</html>`,
  ),
}));

import { handleJoinDone } from "../../src/handlers/join-callback";
import { renderJoinDonePage } from "../../src/lib/join-html";

describe("handleJoinDone", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 200 with text/html Content-Type", () => {
    const res = handleJoinDone("test-org");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
  });

  it("passes slug to renderJoinDonePage", () => {
    handleJoinDone("my-org-slug");
    expect(renderJoinDonePage).toHaveBeenCalledWith("my-org-slug");
  });

  it("returns HTML containing DOCTYPE", async () => {
    const res = handleJoinDone("test-org");
    const html = await res.text();
    expect(html).toContain("<!DOCTYPE html>");
  });

  it("returns rendered content from renderJoinDonePage", async () => {
    const res = handleJoinDone("abc");
    const html = await res.text();
    expect(html).toContain("mock join done abc");
  });
});
