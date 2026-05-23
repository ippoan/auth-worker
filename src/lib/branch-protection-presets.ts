/**
 * Branch protection presets (issue #159 Phase 1).
 *
 * Phase 1 では 3 つの preset を定義する。`/dashboard/branch-protection` から
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
 *   - `ippoan-go-default`:
 *     - Go service 系 (現状 `ippoan/secrets-inventory-gcp` の Cloud Run proxy)。
 *       `ci-workflows/.github/workflows/go-ci.yml` reusable workflow を caller
 *       が job id `ci` で呼ぶ前提で、`vet` / `test` / `build` の 3 job 名
 *       (`ci / vet` / `ci / test` / `ci / build`) を required に固定する。
 *     - 現状 ippoan/* に Go repo は secrets-inventory-gcp 1 つだけで、まだ
 *       reusable workflow に揃っていない。preset を Apply する前に caller 側
 *       workflow を go-ci.yml reusable に揃えるか、dashboard の required
 *       override で実 job 名に差し替えること。一致しない preset を当てると
 *       worker preset 初版と同じ silent block 事故になる。
 *     - safety knob (force push / 削除 / approval / bypass) は rust / worker
 *       と同一。Cloud Run の attached SA + ADC 運用前提なので merge 後に
 *       deploy が即走る ⇒ force push 経路を塞ぐ価値が他より高い。
 *   - `ippoan-lib-default`:
 *     - Node.js library 系 (`@ippoan/*` GitHub Packages publish)。
 *       `ci-workflows/.github/workflows/lib-ci.yml` reusable workflow を caller
 *       が job id `ci` で呼ぶ前提で、`typecheck` / `test` の 2 job 名
 *       (`ci / typecheck` / `ci / test`) を required に固定する。`ci / lint`
 *       は lib-ci.yml の auto-detect (eslint config / `lint` script の存在)
 *       で skip され得るため required に入れない — worker preset 初版の silent
 *       block 事故を再発させないため。
 *     - 初期 consumer は `ippoan/mcp-cf-workers` (PR #1)。他の GitHub Packages
 *       publish 候補として `secrets-inventory` の `packages/rotate-mcp` も
 *       今後この preset に乗る予定。
 *     - safety knob は rust / worker / go と同一。lib として公開 registry に
 *       publish される以上、staging 運用でも品質ガードは緩めない方が安全。
 */

export type PresetId =
  | "ippoan-rust-default"
  | "ippoan-worker-default"
  | "ippoan-go-default"
  | "ippoan-lib-default";

/**
 * Project type a preset applies to. The dashboard auto-detects each repo's
 * type (via `detectProjectType` in `branch-protection-github.ts`) and shows
 * only the matching preset, so a Rust repo never sees the worker preset and
 * vice versa. `"unknown"` repos are shown every preset with a hint instead
 * of being silently locked out.
 */
export type ProjectType = "worker" | "rust" | "go" | "lib" | "unknown";

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
  /** Project type this preset targets — used by the dashboard to filter. */
  project_type: ProjectType;
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

const IPPOAN_GO_DEFAULT_CHECKS = [
  "ci / vet",
  "ci / test",
  "ci / build",
];

const IPPOAN_LIB_DEFAULT_CHECKS = [
  "ci / typecheck",
  "ci / test",
];

export const PRESETS: Record<PresetId, PresetDefinition> = {
  "ippoan-rust-default": {
    id: "ippoan-rust-default",
    label: "Apply ippoan-rust-default",
    description:
      "Rust CI 4 jobs (rustfmt / clippy / cargo test / cargo build --release) required. No force push, no branch deletion, approval=0, admins cannot bypass.",
    required_checks: IPPOAN_RUST_DEFAULT_CHECKS,
    project_type: "rust",
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
    project_type: "worker",
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
  "ippoan-go-default": {
    id: "ippoan-go-default",
    label: "Apply ippoan-go-default",
    description:
      "Go service CI (go vet + go test + go build) required. No force push, no branch deletion, approval=0, admins cannot bypass.",
    required_checks: IPPOAN_GO_DEFAULT_CHECKS,
    project_type: "go",
    payload: {
      required_status_checks: {
        strict: true,
        contexts: IPPOAN_GO_DEFAULT_CHECKS,
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
  "ippoan-lib-default": {
    id: "ippoan-lib-default",
    label: "Apply ippoan-lib-default",
    description:
      "Node.js library CI (typecheck + vitest) required. lint job is auto-skipped when no eslint config is present, so it is intentionally omitted from required_checks. No force push, no branch deletion, approval=0, admins cannot bypass.",
    required_checks: IPPOAN_LIB_DEFAULT_CHECKS,
    project_type: "lib",
    payload: {
      required_status_checks: {
        strict: true,
        contexts: IPPOAN_LIB_DEFAULT_CHECKS,
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
  return (
    s === "ippoan-rust-default" ||
    s === "ippoan-worker-default" ||
    s === "ippoan-go-default" ||
    s === "ippoan-lib-default"
  );
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
