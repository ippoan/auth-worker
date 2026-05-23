/**
 * `branch-protection-presets` unit tests (issue #159 Phase 1).
 *
 * preset 値は dashboard / admin-exec / 将来の cron 監査経路で共有されるため、
 * job 名 / boolean 値が動いたら明示的に test を更新する設計で固定値を assert
 * している (CI job rename 時の早期検出)。
 */

import { describe, it, expect } from "vitest";
import {
  PRESETS,
  buildPayload,
  isPresetId,
} from "../../src/lib/branch-protection-presets";

describe("PRESETS — ippoan-rust-default", () => {
  const p = PRESETS["ippoan-rust-default"];

  it("required_checks lists the 4 rust-ci.yml jobs in order", () => {
    expect(p.required_checks).toEqual([
      "ci / rustfmt",
      "ci / clippy",
      "ci / cargo test",
      "ci / cargo build --release",
    ]);
  });

  it("payload disables force pushes / deletions / admin bypass and uses approval=0", () => {
    expect(p.payload.allow_force_pushes).toBe(false);
    expect(p.payload.allow_deletions).toBe(false);
    expect(p.payload.enforce_admins).toBe(true);
    expect(p.payload.required_pull_request_reviews).toBeNull();
    expect(p.payload.restrictions).toBeNull();
  });

  it("required_status_checks.strict = true and contexts match required_checks", () => {
    const rsc = p.payload.required_status_checks;
    expect(rsc).not.toBeNull();
    expect(rsc!.strict).toBe(true);
    expect(rsc!.contexts).toEqual(p.required_checks);
  });

  it("project_type is 'rust' (drives dashboard auto-pick)", () => {
    expect(p.project_type).toBe("rust");
  });
});

describe("PRESETS — ippoan-worker-default", () => {
  const p = PRESETS["ippoan-worker-default"];

  it("required_checks lists the frontend-ci.yml jobs (Type Check + Vitest + Coverage)", () => {
    // These match the real `name:` fields in
    // ippoan/ci-workflows/.github/workflows/frontend-ci.yml prefixed by the
    // caller's job id `ci`. Mismatched names here would silently block all
    // PRs on every consumer repo, so the test pins the exact strings.
    expect(p.required_checks).toEqual([
      "ci / Type Check",
      "ci / Vitest + Coverage",
    ]);
  });

  it("shares the same safety knobs as the rust preset", () => {
    expect(p.payload.allow_force_pushes).toBe(false);
    expect(p.payload.allow_deletions).toBe(false);
    expect(p.payload.enforce_admins).toBe(true);
    expect(p.payload.required_pull_request_reviews).toBeNull();
  });

  it("project_type is 'worker' (drives dashboard auto-pick)", () => {
    expect(p.project_type).toBe("worker");
  });
});

describe("PRESETS — ippoan-go-default", () => {
  const p = PRESETS["ippoan-go-default"];

  it("required_checks lists the go-ci.yml jobs (vet + test + build) in order", () => {
    // These pin the `ci-workflows/.github/workflows/go-ci.yml` job names
    // prefixed by the caller's `ci` job id. Same drift-detection contract
    // as the worker preset: rename the upstream jobs → update this test.
    expect(p.required_checks).toEqual([
      "ci / vet",
      "ci / test",
      "ci / build",
    ]);
  });

  it("shares the same safety knobs as the rust / worker presets", () => {
    expect(p.payload.allow_force_pushes).toBe(false);
    expect(p.payload.allow_deletions).toBe(false);
    expect(p.payload.enforce_admins).toBe(true);
    expect(p.payload.required_pull_request_reviews).toBeNull();
    expect(p.payload.restrictions).toBeNull();
  });

  it("required_status_checks.strict = true and contexts match required_checks", () => {
    const rsc = p.payload.required_status_checks;
    expect(rsc).not.toBeNull();
    expect(rsc!.strict).toBe(true);
    expect(rsc!.contexts).toEqual(p.required_checks);
  });

  it("project_type is 'go' (drives dashboard auto-pick)", () => {
    expect(p.project_type).toBe("go");
  });
});

describe("PRESETS — ippoan-lib-default", () => {
  const p = PRESETS["ippoan-lib-default"];

  it("required_checks lists the lib-ci.yml jobs (typecheck + test) in order", () => {
    // These pin the `ci-workflows/.github/workflows/lib-ci.yml` job names
    // prefixed by the caller's `ci` job id. `ci / lint` is intentionally
    // excluded because lib-ci.yml auto-skips lint when no eslint config is
    // present — pinning it as required would silently block all PRs on
    // libs without lint (worker preset 初版 silent block 再発回避)。
    expect(p.required_checks).toEqual([
      "ci / typecheck",
      "ci / test",
    ]);
  });

  it("shares the same safety knobs as the rust / worker / go presets", () => {
    expect(p.payload.allow_force_pushes).toBe(false);
    expect(p.payload.allow_deletions).toBe(false);
    expect(p.payload.enforce_admins).toBe(true);
    expect(p.payload.required_pull_request_reviews).toBeNull();
    expect(p.payload.restrictions).toBeNull();
  });

  it("required_status_checks.strict = true and contexts match required_checks", () => {
    const rsc = p.payload.required_status_checks;
    expect(rsc).not.toBeNull();
    expect(rsc!.strict).toBe(true);
    expect(rsc!.contexts).toEqual(p.required_checks);
  });

  it("project_type is 'lib' (drives dashboard auto-pick)", () => {
    expect(p.project_type).toBe("lib");
  });
});

describe("isPresetId", () => {
  it("accepts known preset ids", () => {
    expect(isPresetId("ippoan-rust-default")).toBe(true);
    expect(isPresetId("ippoan-worker-default")).toBe(true);
    expect(isPresetId("ippoan-go-default")).toBe(true);
    expect(isPresetId("ippoan-lib-default")).toBe(true);
  });
  it("rejects unknown / non-string values", () => {
    expect(isPresetId("malicious-preset")).toBe(false);
    expect(isPresetId(undefined)).toBe(false);
    expect(isPresetId(123)).toBe(false);
    expect(isPresetId(null)).toBe(false);
  });
});

describe("buildPayload", () => {
  it("returns the preset payload unchanged when no override is given", () => {
    const out = buildPayload("ippoan-rust-default");
    expect(out).toEqual(PRESETS["ippoan-rust-default"].payload);
  });

  it("replaces required_status_checks.contexts when an override array is given", () => {
    const out = buildPayload("ippoan-rust-default", ["ci / custom"]);
    expect(out.required_status_checks).toEqual({
      strict: true,
      contexts: ["ci / custom"],
    });
    // other fields preserved
    expect(out.allow_force_pushes).toBe(false);
    expect(out.enforce_admins).toBe(true);
  });

  it("sets required_status_checks to null when override is an empty array", () => {
    const out = buildPayload("ippoan-rust-default", []);
    expect(out.required_status_checks).toBeNull();
  });

  it("ignores empty / whitespace strings in the override array", () => {
    const out = buildPayload("ippoan-rust-default", ["", "  ", "ci / a"]);
    expect(out.required_status_checks).toEqual({
      strict: true,
      contexts: ["ci / a"],
    });
  });

  it("treats null override as 'preset default'", () => {
    const out = buildPayload("ippoan-rust-default", null);
    expect(out).toEqual(PRESETS["ippoan-rust-default"].payload);
  });
});
