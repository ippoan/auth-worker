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

if [ -z "$SHA" ]; then
  SHA=$(gh run list -R "$REPO" --branch main --status success --json headSha --jq '.[0].headSha' 2>/dev/null)
  if [ -z "$SHA" ]; then
    echo "ERROR: Could not find successful run on main" >&2
    exit 1
  fi
fi

ARTIFACT_NAME="ts-bindings-${SHA}"
echo "Downloading: $ARTIFACT_NAME"

RUN_ID=$(gh api "repos/$REPO/actions/artifacts?name=$ARTIFACT_NAME" --jq '.artifacts[0].workflow_run.id' 2>/dev/null)
if [ -z "$RUN_ID" ] || [ "$RUN_ID" = "null" ]; then
  echo "ERROR: Artifact '$ARTIFACT_NAME' not found" >&2
  exit 1
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

# serde_json::Value equivalent (needed by some generated types)
echo "export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };" >> "$OUTPUT"

# Collect all export type lines, deduplicate by type name
find "$TMPDIR/bindings" -name "*.ts" -print0 | sort -z | while IFS= read -r -d '' f; do
  grep "^export type" "$f"
done | awk -F'[ =]' '!seen[$3]++' >> "$OUTPUT"

echo "" >> "$OUTPUT"
cat >> "$OUTPUT" << 'WRAPPERS'
// List response wrappers
export type SsoConfigListResponse = { configs: SsoConfigRow[] };
export type BotConfigListResponse = { configs: BotConfigResponse[] };
export type UsersListResponse = { users: UserResponse[] };
export type InvitationsListResponse = { invitations: TenantAllowedEmail[] };
WRAPPERS

echo "✅ $OUTPUT (SHA: ${SHA:0:12})"
