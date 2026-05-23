import { describe, expect, it } from "vitest";
import {
  MCP_SCOPES_SUPPORTED,
  mcpToGithubScope,
  normalizeMcpScope,
  parseMcpScope,
} from "../../src/lib/mcp-scope";

describe("parseMcpScope — whitelist + default decay", () => {
  it("empty string → default {'mcp.read'}", () => {
    expect(parseMcpScope("")).toEqual(new Set(["mcp.read"]));
  });

  it("single mcp.read → {'mcp.read'}", () => {
    expect(parseMcpScope("mcp.read")).toEqual(new Set(["mcp.read"]));
  });

  it("single mcp.write → {'mcp.write'} (does not implicitly add mcp.read)", () => {
    expect(parseMcpScope("mcp.write")).toEqual(new Set(["mcp.write"]));
  });

  it("single mcp.admin → {'mcp.admin'} (does not imply read/write)", () => {
    expect(parseMcpScope("mcp.admin")).toEqual(new Set(["mcp.admin"]));
  });

  it("combo mcp.read + mcp.write preserved", () => {
    expect(parseMcpScope("mcp.read mcp.write")).toEqual(
      new Set(["mcp.read", "mcp.write"]),
    );
  });

  it("combo mcp.admin + mcp.write preserved (disjoint tool surfaces)", () => {
    expect(parseMcpScope("mcp.admin mcp.write")).toEqual(
      new Set(["mcp.admin", "mcp.write"]),
    );
  });

  it("unknown token dropped, mcp.write kept", () => {
    expect(parseMcpScope("garbage mcp.write")).toEqual(new Set(["mcp.write"]));
  });

  it("unknown token dropped, mcp.admin kept", () => {
    expect(parseMcpScope("garbage mcp.admin")).toEqual(new Set(["mcp.admin"]));
  });

  it("all-unknown decays to {'mcp.read'}", () => {
    expect(parseMcpScope("garbage   another")).toEqual(new Set(["mcp.read"]));
  });

  it("multiple internal whitespace tolerated", () => {
    expect(parseMcpScope("mcp.read   mcp.write")).toEqual(
      new Set(["mcp.read", "mcp.write"]),
    );
  });

  it("offline_access alone preserved (no auto mcp.read)", () => {
    expect(parseMcpScope("offline_access")).toEqual(new Set(["offline_access"]));
  });

  it("leading/trailing whitespace handled", () => {
    expect(parseMcpScope("  mcp.write  ")).toEqual(new Set(["mcp.write"]));
  });
});

describe("normalizeMcpScope — canonical ordering", () => {
  it("empty → 'mcp.read'", () => {
    expect(normalizeMcpScope("")).toBe("mcp.read");
  });

  it("all-unknown → 'mcp.read'", () => {
    expect(normalizeMcpScope("garbage")).toBe("mcp.read");
  });

  it("reorders to canonical MCP_SCOPES_SUPPORTED order", () => {
    expect(normalizeMcpScope("offline_access mcp.write mcp.read")).toBe(
      "mcp.read mcp.write offline_access",
    );
  });

  it("reorders to canonical order including mcp.admin", () => {
    expect(normalizeMcpScope("offline_access mcp.admin mcp.write mcp.read")).toBe(
      "mcp.read mcp.write mcp.admin offline_access",
    );
  });

  it("reorders the new ci-dashboard scopes (mcp.workflow / mcp.project) to canonical order", () => {
    expect(normalizeMcpScope("offline_access mcp.project mcp.workflow mcp.write mcp.read")).toBe(
      "mcp.read mcp.write mcp.workflow mcp.project offline_access",
    );
  });

  it("dedupes while preserving canonical order", () => {
    expect(normalizeMcpScope("mcp.write mcp.read mcp.write")).toBe(
      "mcp.read mcp.write",
    );
  });

  it("normalizes mcp.admin alone (no decay)", () => {
    expect(normalizeMcpScope("mcp.admin")).toBe("mcp.admin");
  });
});

describe("mcpToGithubScope — translation map", () => {
  it("mcp.read only → 'read:user'", () => {
    expect(mcpToGithubScope(new Set(["mcp.read"]))).toBe("read:user");
  });

  it("mcp.write → 'read:user repo'", () => {
    expect(mcpToGithubScope(new Set(["mcp.write"]))).toBe("read:user repo");
  });

  it("mcp.read + mcp.write → 'read:user repo'", () => {
    expect(mcpToGithubScope(new Set(["mcp.read", "mcp.write"]))).toBe(
      "read:user repo",
    );
  });

  it("mcp.admin → 'read:user repo' (branch protection API requires `repo` scope)", () => {
    expect(mcpToGithubScope(new Set(["mcp.admin"]))).toBe("read:user repo");
  });

  it("mcp.admin + mcp.read → 'read:user repo'", () => {
    expect(mcpToGithubScope(new Set(["mcp.admin", "mcp.read"]))).toBe(
      "read:user repo",
    );
  });

  it("offline_access alone does NOT escalate to repo", () => {
    expect(mcpToGithubScope(new Set(["offline_access"]))).toBe("read:user");
  });

  it("mcp.workflow alone → 'read:user workflow' (no repo escalation)", () => {
    expect(mcpToGithubScope(new Set(["mcp.workflow"]))).toBe("read:user workflow");
  });

  it("mcp.project alone → 'read:user project' (no repo escalation)", () => {
    expect(mcpToGithubScope(new Set(["mcp.project"]))).toBe("read:user project");
  });

  it("mcp.write + mcp.workflow + mcp.project → 'read:user repo workflow project' (ci-dashboard requested set)", () => {
    expect(mcpToGithubScope(new Set(["mcp.write", "mcp.workflow", "mcp.project"])))
      .toBe("read:user repo workflow project");
  });

  it("mcp.workflow + mcp.project (no write) → 'read:user workflow project' (additive translation)", () => {
    expect(mcpToGithubScope(new Set(["mcp.workflow", "mcp.project"])))
      .toBe("read:user workflow project");
  });
});

describe("MCP_SCOPES_SUPPORTED — AS metadata contract", () => {
  it("matches AS metadata advertisement (mcp.workflow / mcp.project added for ci-dashboard, #184)", () => {
    expect([...MCP_SCOPES_SUPPORTED]).toEqual([
      "mcp.read",
      "mcp.write",
      "mcp.admin",
      "mcp.workflow",
      "mcp.project",
      "offline_access",
    ]);
  });
});
