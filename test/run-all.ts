/**
 * test/run-all.ts — Resilient test runner for synoi-sraid.
 *
 * Globs test/*.test.ts, runs each file individually with tsx,
 * collects pass/fail per file, prints a summary, and exits
 * non-zero if any file failed.
 *
 * Usage: npm test
 *        npx tsx test/run-all.ts
 */

import { spawnSync } from 'node:child_process'
import { readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const files = readdirSync(__dirname)
  .filter(f => f.endsWith('.test.ts') && f !== 'run-all.ts')
  .sort()
  .map(f => path.join(__dirname, f))

const results: { file: string; passed: boolean }[] = []

for (const file of files) {
  const rel = path.relative(process.cwd(), file)
  process.stdout.write(`\n${'─'.repeat(60)}\nRUN  ${rel}\n`)

  const result = spawnSync(
    'npx',
    ['tsx', file],
    {
      stdio: 'inherit',
      encoding: 'utf-8',
      env: { ...process.env },
      shell: true,
    }
  )

  const passed = (result.status ?? 1) === 0
  results.push({ file: rel, passed })
  process.stdout.write(passed ? `PASS ${rel}\n` : `FAIL ${rel} (exit ${result.status ?? 'null'})\n`)
}

const totalFiles = results.length
const failedFiles = results.filter(r => !r.passed).length
const passedFiles = totalFiles - failedFiles

process.stdout.write(`\n${'='.repeat(60)}\nSUMMARY: ${passedFiles}/${totalFiles} files passed`)

if (failedFiles > 0) {
  process.stdout.write(`, ${failedFiles} FAILED:\n`)
  for (const r of results.filter(r => !r.passed)) {
    process.stdout.write(`  FAIL  ${r.file}\n`)
  }
  process.exit(1)
} else {
  process.stdout.write(' — all files passed\n')
  process.exit(0)
}
