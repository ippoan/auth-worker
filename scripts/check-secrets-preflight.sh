#!/bin/bash
# .dev.vars (または引数で指定したファイル) の各 secret 値を GCP Secret Manager /
# CF Secrets Store へ投入する **前** に pre-flight 検査する。
#
# 検査内容 (値そのものは絶対に表示しない — secret 名 + 症状 + byte 数のみ):
#   - 末尾 whitespace (space / tab / CR) — #208 で混入した `\n` 系の検出
#   - 空値
#   - JSON 型 secret (GITHUB_MCP_USER_ALLOWLIST) が JSON array として parse 可能か
#
# 背景 (#208): GOOGLE_CLIENT_ID を `echo "$v" | gcloud secrets versions add` で
# 投入して末尾に `\n` が混入し、rust-alc-api 側の OAuth audience string compare が
# InvalidAudience で silent fail した。投入は必ず `printf '%s'` を使い (echo は
# trailing newline を足すので禁止)、その前に本 script で値の健全性を確認する。
#
#   ✅ printf '%s' "$v" | gcloud secrets versions add NAME --data-file=-
#   ❌ echo "$v"        | gcloud secrets versions add NAME --data-file=-
#
# Usage:
#   ./scripts/check-secrets-preflight.sh                # .dev.vars を検査
#   ./scripts/check-secrets-preflight.sh path/to/file   # 指定ファイルを検査
#
# Exit code: 問題が 1 つでもあれば 1、すべて clean なら 0。

set -uo pipefail

FILE="${1:-.dev.vars}"

if [ ! -f "$FILE" ]; then
  echo "error: file not found: $FILE" >&2
  exit 1
fi

# JSON array として検査する secret 名 (前後を space で囲んだ allowlist)。
JSON_ARRAY_SECRETS=" GITHUB_MCP_USER_ALLOWLIST "

problems=0
checked=0

# 先頭末尾の " または ' を 1 組だけ剥がす (dotenv の quoted value 対応)。
strip_quotes() {
  local v="$1"
  case "$v" in
    \"*\") v="${v#\"}"; v="${v%\"}" ;;
    \'*\') v="${v#\'}"; v="${v%\'}" ;;
  esac
  printf '%s' "$v"
}

while IFS= read -r line || [ -n "$line" ]; do
  line="${line%$'\r'}"   # CRLF ファイルの行末 CR を除去
  case "$line" in
    ''|\#*) continue ;;  # 空行 / コメント行
    *=*) ;;              # KEY=VALUE のみ処理
    *) continue ;;
  esac

  key="${line%%=*}"
  rawval="${line#*=}"
  key="${key#export }"   # `export KEY=...` 対応
  key="${key// /}"       # KEY 周りの空白除去
  val="$(strip_quotes "$rawval")"
  checked=$((checked + 1))

  bytes=$(printf '%s' "$val" | wc -c | tr -d ' ')

  if [ -z "$val" ]; then
    echo "FAIL  $key — empty value"
    problems=$((problems + 1))
    continue
  fi

  # 末尾 whitespace (space / tab)。行末 CR は上で除去済。
  case "$val" in
    *[[:space:]])
      echo "FAIL  $key — trailing whitespace (bytes=$bytes)"
      problems=$((problems + 1))
      ;;
  esac

  # JSON array secret の整合性検査。
  case "$JSON_ARRAY_SECRETS" in
    *" $key "*)
      if command -v jq >/dev/null 2>&1; then
        if ! printf '%s' "$val" | jq -e 'type == "array"' >/dev/null 2>&1; then
          echo "FAIL  $key — not a valid JSON array"
          problems=$((problems + 1))
        fi
      else
        echo "WARN  $key — jq not found, skipped JSON array check"
      fi
      ;;
  esac
done < "$FILE"

echo "---"
echo "checked=$checked problems=$problems file=$FILE"
if [ "$problems" -gt 0 ]; then
  echo "pre-flight FAILED: 上記の値を直してから再実行。投入は printf '%s' を使う (echo 禁止)。" >&2
  exit 1
fi
echo "pre-flight OK: all values clean."
exit 0
