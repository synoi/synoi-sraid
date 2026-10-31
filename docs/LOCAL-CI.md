# Local CI

**GitHub Actions is blocked by billing on the synoi org, so `.github/workflows/*.yml` does not run
today. Until that is settled, `scripts/local-ci.sh` is this repo's CI:** a pull request is "green"
when a local-ci report for its head commit says `Result: PASSED`, and the report is what gets
linked or pasted into the PR. The workflow files are unchanged and stay the definition of what CI
checks; this script mirrors them, it does not replace their content.

```bash
npm run ci:local                                 # or: bash scripts/local-ci.sh
bash scripts/local-ci.sh --only typecheck,test   # some jobs
bash scripts/local-ci.sh --skip pack             # all but some
bash scripts/local-ci.sh --dir ../other-wt       # check another checkout or worktree
bash scripts/local-ci.sh --list                  # jobs and what each mirrors
```

Run it from Git Bash on Windows, or bash on Linux/macOS (bash 3.2 or later, so the stock macOS
bash works). Needs node, npm, git and tar on `PATH`. `npm ci` needs the npm registry or a warm npm
cache, as it does on a runner.

Two Windows notes:

- `npm run ci:local` needs Git's `bash` first on `PATH`; `C:\Windows\System32\bash.exe` (WSL) can
  shadow it. Calling `bash scripts/local-ci.sh` from Git Bash avoids the question.
- PowerShell strips a bare `--` before running a native command, so
  `npm run ci:local -- --only test` loses the `--` and npm swallows `--only`. Quote it:
  `npm run ci:local '--' --only test`.

## Jobs

| Job | Mirrors |
|---|---|
| `install` | `ci.yml` `test` > Install: `npm ci` |
| `typecheck` | `ci.yml` `test` > Typecheck: `npm run typecheck` |
| `test` | `ci.yml` `test` > Test: `npm test` (the report carries `test/run-all.ts`'s file count, the summed assertion counts, and every `SKIP` line) |
| `build` | `ci.yml` `test` > Build: `npm run build` |
| `pack` | `publish-npm.yml` `publish` up to, not including, "Publish to npm": `npm ci`, `npm run build`, then `npm pack --dry-run --json`, with the would-be tarball checked against `package.json` (every `main` / `types` / `exports` / `typesVersions` target present, every top-level `files` entry present, no `test/`, `bench/`, `.github/`, `node_modules/`, `.env*`, `*.pem`, `*.tgz`) |
| `version-tag` | `publish-npm.yml` > Check version matches tag. There is no dispatched tag locally, so the `v*` tags on HEAD stand in: PASS if one is `v<package.json version>`, FAIL if HEAD has only other `v*` tags, SKIP if it has none (an ordinary branch commit) |

**`npm publish` is never run**, and neither is the workflow's Summary step. `publish-npm.yml`'s
own Typecheck and Test steps are the same commands as `ci.yml`'s, so the `typecheck` and `test`
jobs cover them.

## How a run works

- **Fresh copies of the tree** under `$LOCAL_CI_WORKDIR` (default `${TMPDIR:-/tmp}/sraid-local-ci`),
  holding what a checkout would: tracked files plus untracked, non-ignored files. `install`,
  `typecheck`, `test` and `build` share one copy, in that order, because they are the steps of
  `ci.yml`'s single `test` job; `pack` gets its own copy and its own `npm ci`, because
  `publish-npm.yml` runs on its own runner. Your checkout's `node_modules/` and `dist/` are never
  used or touched.
- **A failing job does not stop the next one**, unlike a failing step on Actions. The one
  exception is honest about itself: if `install` fails, `typecheck`, `test` and `build` are
  reported SKIP ("blocked: install failed"), not run against a missing `node_modules`. If you
  leave `install` out with `--only`/`--skip`, the first of those jobs runs `npm ci` as setup and
  says so in its notes. The script exits nonzero if any job failed.
- **Node version.** The workflows pin Node 20 (`actions/setup-node`); the script uses whatever
  `node` is on `PATH`, records it, and prints and reports a warning when its major differs from
  the workflows'. Note that this repo's own `.nvmrc` (22) and `engines.node` (`>=22`) already
  disagree with the workflows' 20; every report shows all three.
- **The copies are not deleted** by the script (they hold `node_modules`, and this workspace does
  not let automation recursive-delete). Clear old ones by hand.

## The report

Every run writes `ci-reports/local-ci-<UTC date>-<short sha>.md` (with a `-2`, `-3`, ... suffix if
that run id is taken in the report dir or the work dir) plus one log per job in a matching
directory, and `pack-dry-run.json` from the `pack` job. `ci-reports/` is gitignored. The report
holds the commit SHA, branch, whether the tree was dirty (and the `git status` lines if so), host
OS, Node and npm versions, the Node version the workflows use, and per job: PASS / FAIL / SKIP,
duration, notes, and log path. A **counted-skips** line states how many jobs were skipped and how
many individual test cases were skipped inside the `test` job, because a skip is not a pass.

A report from a dirty tree says so. Only a clean-tree report for a PR's head commit stands in for
a green CI run.
