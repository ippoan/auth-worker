#!/bin/bash
# rust-alc-api の TypeScript 型定義を CI artifact から取得し、指定ディレクトリに出力
#
# Usage:
#   ./scripts/export-ts-bindings.sh <output-dir>              # latest main
#   ./scripts/export-ts-bindings.sh <output-dir> <sha>        # 特定 SHA
#
# Examples:
#   # auth-worker
#   ./scripts/export-ts-bindings.sh ../auth-worker/src/types
#   # alc-app
#   ./scripts/export-ts-bindings.sh ../alc-app/web/app/types
#   # nuxt-dtako-admin
#   ./scripts/export-ts-bindings.sh ../nuxt-dtako-admin/app/types
#
# 前提: gh CLI、rust-alc-api リポジトリへのアクセス権

set -euo pipefail

REPO="ippoan/rust-alc-api"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <output-dir> [sha]" >&2
  exit 1
fi

DEST="$1"
SHA="${2:-}"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

if [ -n "$SHA" ]; then
  ARTIFACT_NAME="ts-bindings-${SHA}"
  echo "Downloading: $ARTIFACT_NAME"
  RUN_ID=$(gh api "repos/$REPO/actions/artifacts?name=$ARTIFACT_NAME" --jq '.artifacts[0].workflow_run.id' 2>/dev/null)
  if [ -z "$RUN_ID" ] || [ "$RUN_ID" = "null" ]; then
    echo "ERROR: Artifact '$ARTIFACT_NAME' not found" >&2
    exit 1
  fi
else
  # Find latest ts-bindings artifact (check job runs on PR, not main push)
  ARTIFACT_NAME=$(gh api "repos/$REPO/actions/artifacts?per_page=20" \
    --jq '[.artifacts[] | select(.name | startswith("ts-bindings-")) | select(.expired == false)] | .[0].name' 2>/dev/null)
  if [ -z "$ARTIFACT_NAME" ] || [ "$ARTIFACT_NAME" = "null" ]; then
    echo "ERROR: No ts-bindings artifact found" >&2
    exit 1
  fi
  RUN_ID=$(gh api "repos/$REPO/actions/artifacts?name=$ARTIFACT_NAME" --jq '.artifacts[0].workflow_run.id' 2>/dev/null)
  SHA="${ARTIFACT_NAME#ts-bindings-}"
  echo "Downloading latest: $ARTIFACT_NAME"
fi

gh run download "$RUN_ID" -R "$REPO" -n "$ARTIFACT_NAME" -D "$TMPDIR/bindings"

# 出力ファイル生成
mkdir -p "$DEST"
OUTPUT="$DEST/alc-api.ts"

cat > "$OUTPUT" << HEADER
// Auto-generated from rust-alc-api (ts-rs)
// Source SHA: $SHA
// Do not edit. Regenerate: scripts/export-ts-bindings.sh $DEST
HEADER

echo "" >> "$OUTPUT"

# Collect all export type definitions (handling multi-line types with embedded
# /** doc comments */ that ts-rs emits for fields with /// comments), deduplicate
# by type name (includes JsonValue from serde_json/).
#
# Type 終端は `;` で終わる行で判定する。object-shape の `... };` も union-shape の
# `... null;` もこれで正しく拾える。doc comment 終端 ` */` や中間 `,` 行は `;` で
# 終わらないので type 内継続扱いになる。
# `import type { X } from "./Y"` の cross-file ref は不要なので drop する
# (全タイプを 1 ファイルに集約するため、相対 path import は無意味)。
find "$TMPDIR/bindings" -name "*.ts" -print0 | sort -z | xargs -0 awk '
  BEGIN { in_type = 0; skip = 0 }
  # File-level // comments (auto-gen header) — only outside a type definition
  !in_type && /^\/\// { next }
  # Cross-file imports — drop
  !in_type && /^import / { next }
  # Blank lines outside type
  !in_type && NF == 0 { next }
  # Type start
  !in_type && /^export type [A-Za-z0-9_]+/ {
    match($0, /^export type [A-Za-z0-9_]+/)
    name = substr($0, 13, RLENGTH - 12)
    if (seen[name]) skip = 1; else { seen[name] = 1; skip = 0 }
    in_type = 1
  }
  in_type && !skip { print }
  in_type && /;[ \t]*$/ { in_type = 0; skip = 0 }
' >> "$OUTPUT"

echo "" >> "$OUTPUT"
cat >> "$OUTPUT" << 'WRAPPERS'
// List response wrappers
export type SsoConfigListResponse = { configs: SsoConfigRow[] };
export type BotConfigListResponse = { configs: BotConfigResponse[] };
export type UsersListResponse = { users: UserResponse[] };
export type InvitationsListResponse = { invitations: TenantAllowedEmail[] };
WRAPPERS

echo "✅ $OUTPUT (SHA: ${SHA:0:12})"
