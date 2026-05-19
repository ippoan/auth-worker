/**
 * Branch protection presets (issue #159 Phase 1).
 *
 * Phase 1 では 2 つの preset を定義する。`/dashboard/branch-protection` から
 * `[Apply <preset>]` を踏むと、対応する PUT payload が GitHub
 * `/repos/:o/:r/branches/:b/protection` に送られる。
 *
 * Preset を別 file に集約する理由:
 *   - dashboard handler / admin-exec proxy / 将来の cron 監査経路で同じ定義を使い回す
 *   - issue #159 Phase 2 で `ci-workflows` 側 job 名が動いた時の追従点を 1 箇所にする
 *   - test で `toMatchObject(preset)` できるよう pure value にしておく
 *
 * Preset の選定理由 (issue 本文 Phase 2):
 *   - `ippoan-rust-default`:
 *     - rust-ci.yml の 4 job (`rustfmt` / `clippy` / `cargo test` /
 *       `cargo build --release`) を required_status_checks に固定。
 *     - force push / branch 削除を禁止 (`allow_force_pushes=false`,
 *       `allow_deletions=false`)。
 *     - approval=0 → `required_pull_request_reviews: null`。Phase 1 の motivation
 *       (#59) は「自動化が UI に行かないこと」なので、人間レビューを必須にすると
 *       ippoan/* 1 人運用が止まる。Phase 2 で multi-reviewer 運用に切り替わる時に
 *       上書き preset を追加する。
 *     - bypass disabled → `enforce_admins=true`。admin が誤って force push できる
 *       状態は #59 と同じ事故の温床なので塞ぐ。
 *     - conversation resolution は CI 系 preset では false にする (auto-merge を
 *       潰すため)。
 *   - `ippoan-worker-default`:
 *     - Cloudflare Workers 系 (Vitest + tsc typecheck) の 2 job。実 job 名は
 *       `ci-workflows/.github/workflows/frontend-ci.yml` の `name:` フィールド
 *       (それぞれ `Vitest + Coverage` / `Type Check`) を caller の job id `ci`
 *       で prefix した `ci / Vitest + Coverage` / `ci / Type Check`。staging で
 *       初版 (`ci / test` / `ci / typecheck`) を required にしてしまい全 PR が
 *       silent block された事故に対応して実態名に揃えた (drift 検出は別系統で
 *       `ci-workflows/branch-protection-drift-check.yml` が拾う)。
 *     - 残りの safety knob (force push / 削除 / approval / bypass) は rust と同じ。
 */

export type PresetId = "ippoan-rust-default" | "ippoan-worker-default";

export interface BranchProtectionPayload {
  required_status_checks: {
    strict: boolean;
    contexts: string[];
  } | null;
  required_pull_request_reviews: null | {
    required_approving_review_count: number;
    dismiss_stale_reviews: boolean;
  };
  enforce_admins: boolean;
  restrictions: null;
  required_linear_history: boolean;
  allow_force_pushes: boolean;
  allow_deletions: boolean;
  required_conversation_resolution: boolean;
}

export interface PresetDefinition {
  id: PresetId;
  label: string;
  description: string;
  required_checks: string[];
  payload: BranchProtectionPayload;
}

const IPPOAN_RUST_DEFAULT_CHECKS = [
  "ci / rustfmt",
  "ci / clippy",
  "ci / cargo test",
  "ci / cargo build --release",
];

const IPPOAN_WORKER_DEFAULT_CHECKS = [
  "ci / Type Check",
  "ci / Vitest + Coverage",
];

export const PRESETS: Record<PresetId, PresetDefinition> = {
  "ippoan-rust-default": {
    id: "ippoan-rust-default",
    label: "Apply ippoan-rust-default",
    description:
      "Rust CI 4 jobs (rustfmt / clippy / cargo test / cargo build --release) required. No force push, no branch deletion, approval=0, admins cannot bypass.",
    required_checks: IPPOAN_RUST_DEFAULT_CHECKS,
    payload: {
      required_status_checks: {
        strict: true,
        contexts: IPPOAN_RUST_DEFAULT_CHECKS,
      },
      required_pull_request_reviews: null,
      enforce_admins: true,
      restrictions: null,
      required_linear_history: false,
      allow_force_pushes: false,
      allow_deletions: false,
      required_conversation_resolution: false,
    },
  },
  "ippoan-worker-default": {
    id: "ippoan-worker-default",
    label: "Apply ippoan-worker-default",
    description:
      "Cloudflare Workers CI (wrangler test + typecheck) required. No force push, no branch deletion, approval=0, admins cannot bypass.",
    required_checks: IPPOAN_WORKER_DEFAULT_CHECKS,
    payload: {
      required_status_checks: {
        strict: true,
        contexts: IPPOAN_WORKER_DEFAULT_CHECKS,
      },
      required_pull_request_reviews: null,
      enforce_admins: true,
      restrictions: null,
      required_linear_history: false,
      allow_force_pushes: false,
      allow_deletions: false,
      required_conversation_resolution: false,
    },
  },
};

export function isPresetId(s: unknown): s is PresetId {
  return s === "ippoan-rust-default" || s === "ippoan-worker-default";
}

/**
 * Build the PUT payload for `set_branch_protection`. If
 * `required_status_checks_override` is provided, it replaces the preset's
 * required_checks (allowing the dashboard to ship a custom checks list while
 * keeping the rest of the preset). Empty / null → preset default.
 */
export function buildPayload(
  preset: PresetId,
  required_status_checks_override?: string[] | null,
): BranchProtectionPayload {
  const base = PRESETS[preset].payload;
  if (
    required_status_checks_override === undefined ||
    required_status_checks_override === null
  ) {
    return base;
  }
  const checks = required_status_checks_override
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (checks.length === 0) {
    return { ...base, required_status_checks: null };
  }
  return {
    ...base,
    required_status_checks: { strict: true, contexts: checks },
  };
}
