import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const BIN = fileURLToPath(new URL('../bin/check-coverage-100.mjs', import.meta.url))

/** bin を cwd=dir で実行。{ code, stdout } を返す */
function runBin(dir: string): { code: number; stdout: string } {
  try {
    const stdout = execFileSync('node', [BIN], {
      cwd: dir,
      encoding: 'utf-8',
    })
    return { code: 0, stdout }
  } catch (e: any) {
    return { code: e.status ?? 1, stdout: (e.stdout ?? '') + (e.stderr ?? '') }
  }
}

function writeSummary(dir: string, files: Record<string, { lines: number; branches: number }>) {
  const summary: Record<string, unknown> = {}
  for (const [rel, pct] of Object.entries(files)) {
    summary[resolve(dir, rel)] = {
      lines: { pct: pct.lines },
      branches: { pct: pct.branches },
    }
  }
  mkdirSync(join(dir, 'coverage'), { recursive: true })
  writeFileSync(join(dir, 'coverage', 'coverage-summary.json'), JSON.stringify(summary))
}

describe('check-coverage-100 bin', () => {
  let dir: string

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'cov100-'))
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('toml が無ければ skip (exit 0)', () => {
    const { code, stdout } = runBin(dir)
    expect(code).toBe(0)
    expect(stdout).toContain('not found. Skipping')
  })

  it('登録ファイルが 0 件なら skip (exit 0)', () => {
    writeFileSync(join(dir, 'coverage_100.toml'), '# empty\n')
    const { code, stdout } = runBin(dir)
    expect(code).toBe(0)
    expect(stdout).toContain('No files registered')
  })

  it('summary が無ければ fail (exit 1)', () => {
    writeFileSync(join(dir, 'coverage_100.toml'), '[[files]]\npath = "src/a.ts"\n')
    const { code, stdout } = runBin(dir)
    expect(code).toBe(1)
    expect(stdout).toContain('coverage-summary.json not found')
  })

  it('全ファイル 100% なら pass (exit 0)', () => {
    writeFileSync(
      join(dir, 'coverage_100.toml'),
      '[[files]]\npath = "src/a.ts"\nbranches = true\n',
    )
    writeSummary(dir, { 'src/a.ts': { lines: 100, branches: 100 } })
    const { code, stdout } = runBin(dir)
    expect(code).toBe(0)
    expect(stdout).toContain('OK: src/a.ts')
  })

  it('lines が 100% 未満なら fail (exit 1)', () => {
    writeFileSync(join(dir, 'coverage_100.toml'), '[[files]]\npath = "src/a.ts"\n')
    writeSummary(dir, { 'src/a.ts': { lines: 90, branches: 100 } })
    const { code, stdout } = runBin(dir)
    expect(code).toBe(1)
    expect(stdout).toContain('lines 90%')
  })

  it('branches=true でブランチが 100% 未満なら fail (exit 1)', () => {
    writeFileSync(
      join(dir, 'coverage_100.toml'),
      '[[files]]\npath = "src/a.ts"\nbranches = true\n',
    )
    writeSummary(dir, { 'src/a.ts': { lines: 100, branches: 80 } })
    const { code, stdout } = runBin(dir)
    expect(code).toBe(1)
    expect(stdout).toContain('branches 80%')
  })

  it('登録ファイルが report に無ければ fail (exit 1)', () => {
    writeFileSync(join(dir, 'coverage_100.toml'), '[[files]]\npath = "src/missing.ts"\n')
    writeSummary(dir, { 'src/other.ts': { lines: 100, branches: 100 } })
    const { code, stdout } = runBin(dir)
    expect(code).toBe(1)
    expect(stdout).toContain('not found in coverage report')
  })
})
