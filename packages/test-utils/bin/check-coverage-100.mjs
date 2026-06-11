#!/usr/bin/env node
/**
 * coverage_100.toml に登録されたファイルが 100% カバレッジを維持しているか検証する。
 * coverage/coverage-summary.json を読み込み、登録ファイルの lines.pct を確認。
 * json-summary reporter を出していない repo 向けに coverage-final.json からの
 * 合成 fallback を持つ。branches = true のファイルは branches.pct も 100% を要求する。
 * coverage_100.toml は org 標準の [[files]] entries と旧 `files = [...]` 配列の
 * 両形式を受け付ける (5 repo の copy drift を吸収、Refs ippoan/auth-worker#257)。
 *
 * Usage: npx check-coverage-100
 * Exit 0: 全ファイル 100% or 登録ファイルなし
 * Exit 1: 100% 未満のファイルあり
 */

import { readFileSync, existsSync } from 'node:fs'
import { resolve, join } from 'node:path'

const ROOT = process.cwd()
const TOML_PATH = join(ROOT, 'coverage_100.toml')
const SUMMARY_PATH = join(ROOT, 'coverage', 'coverage-summary.json')
const FINAL_PATH = join(ROOT, 'coverage', 'coverage-final.json')

function parseToml(content) {
  const entries = []
  let current = null
  for (const line of content.split('\n')) {
    if (line.trim() === '[[files]]') {
      current = { path: '', branches: false }
      entries.push(current)
      continue
    }
    if (!current) continue
    const pathMatch = line.match(/^path\s*=\s*"(.+)"/)
    if (pathMatch) { current.path = pathMatch[1]; continue }
    const branchMatch = line.match(/^branches\s*=\s*true/)
    if (branchMatch) current.branches = true
  }
  const fromSections = entries.filter(e => e.path)
  if (fromSections.length > 0) return fromSections

  // 旧形式: files = ["a.ts", "b.ts", ...] (lines のみ要求)
  const arr = content.match(/files\s*=\s*\[([\s\S]*?)\]/)
  if (arr) {
    for (const m of arr[1].matchAll(/"([^"]+)"/g)) {
      entries.push({ path: m[1], branches: false })
    }
  }
  return entries.filter(e => e.path)
}

/** summary を読み込む。json-summary 未出力なら coverage-final.json から合成。 */
function loadSummary() {
  if (existsSync(SUMMARY_PATH)) {
    return JSON.parse(readFileSync(SUMMARY_PATH, 'utf-8'))
  }
  if (!existsSync(FINAL_PATH)) return null
  const final = JSON.parse(readFileSync(FINAL_PATH, 'utf-8'))
  const summary = {}
  for (const [fp, fc] of Object.entries(final)) {
    const st = fc.s || {}
    let lT = 0
    let lC = 0
    for (const k of Object.keys(st)) {
      lT++
      if (st[k] > 0) lC++
    }
    const br = fc.b || {}
    let bT = 0
    let bC = 0
    for (const k of Object.keys(br)) {
      for (const c of br[k]) {
        bT++
        if (c > 0) bC++
      }
    }
    summary[fp] = {
      lines: { pct: lT === 0 ? 100 : Math.round((lC / lT) * 10000) / 100 },
      branches: { pct: bT === 0 ? 100 : Math.round((bC / bT) * 10000) / 100 },
    }
  }
  return summary
}

if (!existsSync(TOML_PATH)) {
  console.log('coverage_100.toml not found. Skipping check.')
  process.exit(0)
}

const tomlContent = readFileSync(TOML_PATH, 'utf-8')
const registeredFiles = parseToml(tomlContent)

if (registeredFiles.length === 0) {
  console.log('coverage_100.toml: No files registered yet. Skipping check.')
  process.exit(0)
}

const summary = loadSummary()
if (!summary) {
  console.error(`ERROR: neither ${SUMMARY_PATH} nor ${FINAL_PATH} found. Run "npm run test:coverage" first.`)
  process.exit(1)
}
let failed = false
let branchChecked = 0

for (const { path: filePath, branches: checkBranches } of registeredFiles) {
  const absPath = resolve(ROOT, filePath)
  const entry = summary[absPath]

  if (!entry) {
    console.error(`FAIL: ${filePath} — not found in coverage report`)
    failed = true
    continue
  }

  const linesPct = entry.lines.pct
  const branchPct = entry.branches.pct

  if (linesPct < 100) {
    console.error(`FAIL: ${filePath} — lines ${linesPct}% (expected 100%)`)
    failed = true
  } else if (checkBranches && branchPct < 100) {
    console.error(`FAIL: ${filePath} — branches ${branchPct}% (expected 100%)`)
    failed = true
  } else {
    const branchLabel = checkBranches ? ` branches ${branchPct}%` : ''
    console.log(`  OK: ${filePath} — lines 100%${branchLabel}`)
  }

  if (checkBranches) branchChecked++
}

if (failed) {
  console.error('\ncoverage_100 regression detected!')
  process.exit(1)
} else {
  console.log(`\nAll ${registeredFiles.length} files at 100% lines (${branchChecked} also checked branches).`)
  process.exit(0)
}
