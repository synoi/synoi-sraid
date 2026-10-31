#!/usr/bin/env bash
# Local replacement for this repo's GitHub Actions CI (see docs/LOCAL-CI.md).
#
# GitHub Actions on the synoi org is blocked by billing, so nothing runs .github/workflows/*.yml
# today. This script runs the same steps on the developer's own machine, in fresh copies of the
# tree (the files git would check out, plus untracked-but-not-ignored files): one copy for
# ci.yml's `test` job and one for publish-npm.yml's pre-publish checks, each with its own `npm ci`,
# the way each Actions job gets its own runner. A job that fails does not stop the next. Every run
# writes a dated report to ci-reports/ naming the commit, the host, and each job's
# PASS / FAIL / SKIP, so a skipped job is counted, not mistaken for a pass.
#
# It never runs `npm publish`. publish-npm.yml is mirrored only up to (not including) its
# "Publish to npm" step; what would be uploaded is listed with `npm pack --dry-run`.
#
#   bash scripts/local-ci.sh                       every job
#   bash scripts/local-ci.sh --only typecheck,test just those jobs
#   bash scripts/local-ci.sh --skip pack           everything but those
#   bash scripts/local-ci.sh --dir ../other-wt     check another checkout with this copy of the script
#   bash scripts/local-ci.sh --list                list jobs and what each mirrors
#
# Works in Git Bash on Windows and in bash on Linux/macOS (bash 3.2+). Needs node, npm, git, tar.
#
# The job copies are never deleted by this script: they hold node_modules trees, and this
# workspace's rule is no recursive deletes from automation. Their location is printed in the
# report; clear them by hand when you no longer need the logs or artifacts.

set -uo pipefail

# ── job table ──────────────────────────────────────────────────────────────────────────────────
ALL_JOBS=(install typecheck test build pack version-tag)

job_mirrors() {
  case "$1" in
    install) echo "ci.yml test > Install (npm ci)" ;;
    typecheck) echo "ci.yml test > Typecheck (npm run typecheck)" ;;
    test) echo "ci.yml test > Test (npm test)" ;;
    build) echo "ci.yml test > Build (npm run build)" ;;
    pack) echo "publish-npm.yml publish > Install + Build, then npm pack --dry-run contents (never publishes)" ;;
    version-tag) echo "publish-npm.yml publish > Check version matches tag" ;;
  esac
}

# Jobs that share the ci.yml `test` job's copy, in the workflow's step order.
CI_GROUP=(install typecheck test build)

usage() {
  sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
}

# ── args ───────────────────────────────────────────────────────────────────────────────────────
DIR=""
ONLY=""
SKIP=""
LIST=0
WORK_ROOT="${LOCAL_CI_WORKDIR:-}"
REPORT_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="${2:?--dir needs a path}"; shift 2 ;;
    --dir=*) DIR="${1#*=}"; shift ;;
    --only) ONLY="${2:?--only needs a job list}"; shift 2 ;;
    --only=*) ONLY="${1#*=}"; shift ;;
    --skip) SKIP="${2:?--skip needs a job list}"; shift 2 ;;
    --skip=*) SKIP="${1#*=}"; shift ;;
    --workdir) WORK_ROOT="${2:?--workdir needs a path}"; shift 2 ;;
    --workdir=*) WORK_ROOT="${1#*=}"; shift ;;
    --report-dir) REPORT_DIR="${2:?--report-dir needs a path}"; shift 2 ;;
    --report-dir=*) REPORT_DIR="${1#*=}"; shift ;;
    --list) LIST=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "local-ci: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$LIST" = 1 ]; then
  for j in "${ALL_JOBS[@]}"; do printf '%-12s %s\n' "$j" "$(job_mirrors "$j")"; done
  exit 0
fi

is_job() { local j; for j in "${ALL_JOBS[@]}"; do [ "$j" = "$1" ] && return 0; done; return 1; }
in_list() { case ",$2," in *",$1,"*) return 0 ;; esac; return 1; }
in_ci_group() { local j; for j in "${CI_GROUP[@]}"; do [ "$j" = "$1" ] && return 0; done; return 1; }
for j in ${ONLY//,/ } ${SKIP//,/ }; do
  is_job "$j" || { echo "local-ci: unknown job '$j' (known: ${ALL_JOBS[*]})" >&2; exit 2; }
done

# ── paths and host ─────────────────────────────────────────────────────────────────────────────
# Mixed-form paths (E:/x/y) on Windows: bash, node, npm and git all accept them, and a POSIX
# /e/x/y handed to a native tool can silently become E:\e\x\y.
native_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi; }
abs_dir() { (cd "$1" && native_path "$(pwd)"); }

SCRIPT_DIR="$(abs_dir "$(dirname "$0")")"
TARGET="$(abs_dir "${DIR:-$SCRIPT_DIR/..}")" || { echo "local-ci: --dir '$DIR' is not a directory" >&2; exit 2; }
[ -f "$TARGET/package.json" ] || { echo "local-ci: $TARGET has no package.json" >&2; exit 2; }
git -C "$TARGET" rev-parse --git-dir >/dev/null 2>&1 || { echo "local-ci: $TARGET is not a git checkout" >&2; exit 2; }

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) HOST_OS=windows ;;
  Darwin) HOST_OS=macos ;;
  Linux) HOST_OS=linux ;;
  *) HOST_OS="$(uname -s)" ;;
esac
HOST_DESC="$(uname -srm)"

SHA="$(git -C "$TARGET" rev-parse HEAD)"
SHORT="$(git -C "$TARGET" rev-parse --short HEAD)"
BRANCH="$(git -C "$TARGET" rev-parse --abbrev-ref HEAD)"
# ci-reports/ is gitignored, so this script's own output never makes the tree dirty.
DIRTY_LINES="$(git -C "$TARGET" status --porcelain --untracked-files=all || true)"
if [ -n "$DIRTY_LINES" ]; then DIRTY=yes; else DIRTY=no; fi
UTC_DATE="$(date -u +%Y-%m-%d)"
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

REPORT_DIR="${REPORT_DIR:-$TARGET/ci-reports}"
mkdir -p "$REPORT_DIR"
REPORT_DIR="$(abs_dir "$REPORT_DIR")"
WORK_ROOT="${WORK_ROOT:-${TMPDIR:-/tmp}/sraid-local-ci}"
mkdir -p "$WORK_ROOT"
WORK_ROOT="$(abs_dir "$WORK_ROOT")"
# The run id must be new in both places: the work root is shared by every checkout, and a copy
# extracted over an older run's copy would inherit its node_modules and dist/.
RUN_ID="local-ci-$UTC_DATE-$SHORT"
n=2
while [ -e "$REPORT_DIR/$RUN_ID.md" ] || [ -e "$REPORT_DIR/$RUN_ID" ] || [ -e "$WORK_ROOT/$RUN_ID" ]; do
  RUN_ID="local-ci-$UTC_DATE-$SHORT-$n"; n=$((n + 1))
done
LOG_DIR="$REPORT_DIR/$RUN_ID"
REPORT="$REPORT_DIR/$RUN_ID.md"
mkdir -p "$LOG_DIR"
WORK="$WORK_ROOT/$RUN_ID"
mkdir -p "$WORK"

NODE_V="$(node --version 2>&1 || echo missing)"
NPM_V="$(npm --version 2>&1 || echo missing)"

# The Node major the workflows pin (actions/setup-node `node-version:`), read from the files so a
# change there shows up here without editing this script.
wf_node() {
  local f="$TARGET/.github/workflows/$1"
  [ -f "$f" ] || { echo "?"; return; }
  grep -E '^[[:space:]]*node-version:' "$f" | head -n1 | sed -E "s/.*node-version:[[:space:]]*['\"]?([^'\" ]+).*/\1/"
}
CI_NODE="$(wf_node ci.yml)"
PUBLISH_NODE="$(wf_node publish-npm.yml)"
NVMRC="$( [ -f "$TARGET/.nvmrc" ] && tr -d '[:space:]' <"$TARGET/.nvmrc" || echo none)"
ENGINES_NODE="$(cd "$TARGET" && node -p "(require('./package.json').engines||{}).node||'none'" 2>/dev/null || echo '?')"
HOST_NODE_MAJOR="$(printf '%s' "$NODE_V" | sed -E 's/^v([0-9]+).*/\1/')"
NODE_WARNING=""
if [ "$HOST_NODE_MAJOR" != "$CI_NODE" ] || [ "$HOST_NODE_MAJOR" != "$PUBLISH_NODE" ]; then
  NODE_WARNING="host node $NODE_V is not the Node $CI_NODE (ci.yml) / $PUBLISH_NODE (publish-npm.yml) the workflows use; a result here may differ from GitHub's"
fi

# ── shared helpers used inside jobs ────────────────────────────────────────────────────────────
step() { echo; echo "::: $*"; }

# Copy the tree a checkout would hold: tracked files plus untracked, non-ignored files, minus this
# script's own reports. No .git, no node_modules, no dist: each copy installs and builds for itself.
copy_tree() {
  local src=$1 dest=$2
  mkdir -p "$dest"
  (cd "$src" && git ls-files -z -co --exclude-standard) |
    (cd "$src" && while IFS= read -r -d '' f; do
        case "$f" in ci-reports/*) continue ;; esac
        [ -e "$f" ] || [ -L "$f" ] || continue
        printf '%s\0' "$f"
      done | tar --null -T - -cf -) |
    (cd "$dest" && tar -xf -)
}

meta() { echo "$*" >>"$JOB_DIR/meta"; }
# A job calls this and returns 0 to be reported as SKIP (with the reason) instead of PASS.
skip_job() { meta "skip_reason=$*"; echo "SKIP: $*"; }

# test/run-all.ts prints "N passed, M failed" per file, "SKIP ..." for a skipped case, and a
# "SUMMARY: x/y files passed" line.
summarize_tests() {
  local out=$1 files asserts fails skips
  files="$(grep -E '^SUMMARY: ' "$out" | tail -n1 | sed -E 's/^SUMMARY: ([0-9]+\/[0-9]+ files passed).*/\1/')"
  asserts="$(grep -E '^[0-9]+ passed, [0-9]+ failed' "$out" | awk '{s+=$1} END {print s+0}')"
  fails="$(grep -E '^[0-9]+ passed, [0-9]+ failed' "$out" | awk '{s+=$3} END {print s+0}')"
  skips="$(grep -cE '^SKIP ' "$out" || true)"
  meta "tests: ${files:-no SUMMARY line printed}; $asserts assertions passed, $fails failed; ${skips:-0} skipped"
  meta "test_skips=${skips:-0}"
  grep -E '^SKIP ' "$out" | sed 's/^SKIP /skipped case: /' >>"$JOB_DIR/meta" || true
  [ -n "$files" ]
}

# ── jobs ───────────────────────────────────────────────────────────────────────────────────────
# install / typecheck / test / build run in order in one copy, like the steps of ci.yml's single
# `test` job. Unlike Actions, a failed step does not stop the later ones; a step that needs
# node_modules is SKIPPED (counted) if `install` failed.
job_install() {
  step "npm ci"; npm ci
}

job_typecheck() {
  step "npm run typecheck"; npm run typecheck
}

job_test() {
  local rc
  step "npm test"
  set +e
  npm test 2>&1 | tee "$JOB_DIR/test-output.txt"
  rc=${PIPESTATUS[0]}
  set -e
  summarize_tests "$JOB_DIR/test-output.txt" || { echo "test/run-all.ts printed no SUMMARY line"; [ "$rc" -ne 0 ] || rc=1; }
  [ "$rc" -eq 0 ] || { echo "npm test exited $rc"; return "$rc"; }
}

job_build() {
  step "npm run build"; npm run build
}

# publish-npm.yml's steps before "Publish to npm", in its own copy. Its Typecheck and Test steps
# are the same commands as ci.yml's and are covered by those jobs; this one installs, builds, and
# lists what `npm publish` would upload, then checks that list against package.json.
job_pack() {
  step "npm ci"; npm ci
  step "npm run build"; npm run build
  step "npm pack --dry-run --json (nothing is written or uploaded)"
  npm pack --dry-run --json >"$JOB_DIR/pack.json"
  cp "$JOB_DIR/pack.json" "$LOG_DIR/pack-dry-run.json"
  step "check the would-be tarball's contents against package.json"
  node - "$JOB_DIR/pack.json" "$JOB_DIR/meta" <<'NODE'
const fs = require('fs')
const [packFile, metaFile] = process.argv.slice(2)
const pack = JSON.parse(fs.readFileSync(packFile, 'utf8'))[0]
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'))
const files = new Set(pack.files.map(f => f.path.replace(/\\/g, '/')))
const problems = []

// Everything package.json points a consumer at must be in the tarball.
const wanted = new Set()
const norm = p => p.replace(/^\.\//, '')
const walk = v => {
  if (typeof v === 'string') wanted.add(norm(v))
  else if (Array.isArray(v)) v.forEach(walk)
  else if (v && typeof v === 'object') Object.values(v).forEach(walk)
}
walk(pkg.main); walk(pkg.types); walk(pkg.exports); walk(pkg.typesVersions)
for (const p of wanted) if (!files.has(p)) problems.push(`package.json points at ${p}, which is not in the tarball`)

// Every top-level file named in "files" must be present.
for (const f of pkg.files || []) {
  if (f.includes('/') || f.includes('*')) continue
  if (!files.has(f) && ![...files].some(p => p.startsWith(f + '/'))) problems.push(`"files" entry ${f} is missing from the tarball`)
}

// Nothing that should never ship.
const forbidden = [/^test\//, /^bench\//, /^node_modules\//, /^\.github\//, /^ci-reports\//, /(^|\/)\.env/, /\.tgz$/, /\.pem$/, /\.tsbuildinfo$/]
for (const p of files) if (forbidden.some(re => re.test(p))) problems.push(`tarball would include ${p}`)

console.log(`${pack.id}: ${pack.entryCount} files, ${pack.size} bytes packed, ${pack.unpackedSize} unpacked`)
for (const p of [...files].sort()) console.log(`  ${p}`)
fs.appendFileSync(metaFile, `would publish ${pack.id}: ${pack.entryCount} files, ${pack.size} bytes packed\n`)
if (problems.length) {
  for (const p of problems) console.log(`PROBLEM: ${p}`)
  fs.appendFileSync(metaFile, `pack problems: ${problems.length}\n`)
  process.exit(1)
}
console.log('pack contents match package.json')
NODE
}

# The workflow compares the dispatched tag with "v" + package.json's version. Locally there is no
# dispatched tag, so the tags on HEAD stand in: PASS if HEAD carries v<version>, FAIL if it carries
# only other v* tags, SKIP if it carries none (a branch commit is not a release candidate).
job_version_tag() {
  local version tags
  version="v$(node -p "require('./package.json').version")"
  tags="$(git -C "$TARGET" tag --points-at HEAD --list 'v*' | paste -sd ' ' -)"
  echo "package.json version: $version"
  echo "v* tags on HEAD: ${tags:-none}"
  if [ -z "$tags" ]; then skip_job "HEAD ($SHORT) has no v* tag; publish-npm.yml only runs against a tag"; return 0; fi
  if in_list "$version" "${tags// /,}"; then meta "HEAD is tagged $version"; return 0; fi
  echo "Tag(s) $tags do not match package.json version $version"
  return 1
}

# ── runner ─────────────────────────────────────────────────────────────────────────────────────
# Per-job values live in plain variables (RESULT__install, ...), not associative arrays: macOS
# still ships bash 3.2, which has no `declare -A`.
setv() { printf -v "${1}__${2//-/_}" '%s' "$3"; }
getv() { local n="${1}__${2//-/_}"; printf '%s' "${!n:-}"; }

SELECTED=()
for j in "${ALL_JOBS[@]}"; do
  if [ -n "$ONLY" ] && ! in_list "$j" "$ONLY"; then setv RESULT "$j" SKIP; setv NOTE "$j" "not selected (--only $ONLY)"; continue; fi
  if [ -n "$SKIP" ] && in_list "$j" "$SKIP"; then setv RESULT "$j" SKIP; setv NOTE "$j" "excluded (--skip $SKIP)"; continue; fi
  SELECTED+=("$j")
done

echo "local-ci: $TARGET @ $SHORT ($BRANCH, dirty=$DIRTY) on $HOST_OS"
echo "local-ci: jobs: ${SELECTED[*]+${SELECTED[*]}}"
echo "local-ci: node $NODE_V, npm $NPM_V"
[ -z "$NODE_WARNING" ] || echo "local-ci: WARNING: $NODE_WARNING"
echo "local-ci: logs: $LOG_DIR"
echo "local-ci: work: $WORK"

CI_COPY="$WORK/ci/repo"
CI_COPY_STATE=""     # "", ok, failed
CI_INSTALL_STATE=""  # "", ok, failed

# ${arr[@]+"${arr[@]}"}: an empty array under set -u is an error before bash 4.4.
for j in ${SELECTED[@]+"${SELECTED[@]}"}; do
  if in_ci_group "$j"; then JOB_DIR="$WORK/ci/$j"; else JOB_DIR="$WORK/$j"; fi
  mkdir -p "$JOB_DIR"
  : >"$JOB_DIR/meta"
  log="$LOG_DIR/$j.log"
  : >"$log"
  printf 'local-ci: %-12s ... ' "$j"
  start=$SECONDS
  rc=0
  blocked=""

  if in_ci_group "$j"; then
    if [ -z "$CI_COPY_STATE" ]; then
      echo "::: copy tree to $CI_COPY (shared by the ci.yml test steps)" >>"$log"
      if copy_tree "$TARGET" "$CI_COPY" >>"$log" 2>&1; then CI_COPY_STATE=ok; else CI_COPY_STATE=failed; fi
    fi
    if [ "$CI_COPY_STATE" = failed ]; then
      echo "copying the tree failed" >>"$log"; rc=1
    elif [ "$j" != install ] && [ "$CI_INSTALL_STATE" = failed ]; then
      blocked="needs node_modules, and install failed"
    elif [ "$j" != install ] && [ -z "$CI_INSTALL_STATE" ]; then
      # install was not selected: run it anyway as setup, so the step under test has its deps.
      echo "::: npm ci (setup: the install job was not selected)" >>"$log"
      if (cd "$CI_COPY" && npm ci) >>"$log" 2>&1; then CI_INSTALL_STATE=ok; meta "npm ci run as setup (install not selected)"; else CI_INSTALL_STATE=failed; blocked="setup npm ci failed"; fi
    fi
    JOB_REPO="$CI_COPY"
  else
    JOB_REPO="$JOB_DIR/repo"
    if [ "$j" = pack ]; then
      echo "::: copy tree to $JOB_REPO (publish-npm.yml gets its own runner)" >>"$log"
      copy_tree "$TARGET" "$JOB_REPO" >>"$log" 2>&1 || { echo "copying the tree failed" >>"$log"; rc=1; }
    else
      JOB_REPO="$TARGET"   # version-tag only reads package.json and git tags
    fi
  fi

  if [ -n "$blocked" ]; then
    echo "SKIP: $blocked" >>"$log"
    setv RESULT "$j" SKIP; setv NOTE "$j" "blocked: $blocked"
  else
    if [ "$rc" -eq 0 ]; then
      # A plain statement, not part of && / || / if: set -e inside the subshell only works that way.
      (
        set -euo pipefail
        cd "$JOB_REPO"
        "job_${j//-/_}"
      ) >>"$log" 2>&1
      rc=$?
    fi
    [ "$j" != install ] || { if [ "$rc" -eq 0 ]; then CI_INSTALL_STATE=ok; else CI_INSTALL_STATE=failed; fi; }
    skip_reason="$(grep -E '^skip_reason=' "$JOB_DIR/meta" | head -n1 | cut -d= -f2-)"
    if [ "$rc" -ne 0 ]; then setv RESULT "$j" FAIL
    elif [ -n "$skip_reason" ]; then setv RESULT "$j" SKIP
    else setv RESULT "$j" PASS; fi
    notes="$(grep -v -e '^$' -e '^test_skips=' -e '^skip_reason=' "$JOB_DIR/meta" | awk 'NR > 1 { printf "; " } { printf "%s", $0 }' || true)"
    [ -z "$skip_reason" ] || notes="$skip_reason${notes:+; $notes}"
    if [ "$rc" -ne 0 ]; then
      notes="exit $rc; last line: $(grep -v '^[[:space:]]*$' "$log" | tail -n1 | cut -c1-160)${notes:+; $notes}"
    fi
    setv NOTE "$j" "$notes"
  fi
  setv DURATION "$j" $((SECONDS - start))
  echo "$(getv RESULT "$j") ($(getv DURATION "$j")s)"
done

# ── report ─────────────────────────────────────────────────────────────────────────────────────
fmt_dur() { local s=$1; printf '%dm%02ds' $((s / 60)) $((s % 60)); }
pass=0; fail=0; skip=0; test_skips=0
for j in "${ALL_JOBS[@]}"; do
  case "$(getv RESULT "$j")" in PASS) pass=$((pass + 1)) ;; FAIL) fail=$((fail + 1)) ;; SKIP) skip=$((skip + 1)) ;; esac
done
ts="$(grep -hE '^test_skips=[0-9]+' "$WORK"/ci/test/meta 2>/dev/null | cut -d= -f2 | awk '{s+=$1} END {print s+0}')"
test_skips=${ts:-0}

if [ "$fail" -gt 0 ]; then OVERALL=FAILED; else OVERALL=PASSED; fi

{
  echo "# Local CI report: $RUN_ID"
  echo
  echo "Replaces GitHub Actions while org billing blocks it. Produced by \`scripts/local-ci.sh\`; see \`docs/LOCAL-CI.md\`."
  echo "\`npm publish\` is never run; publish-npm.yml is mirrored only up to its \"Publish to npm\" step."
  echo
  echo "| Field | Value |"
  echo "|---|---|"
  echo "| Commit | \`$SHA\` |"
  echo "| Branch | \`$BRANCH\` |"
  echo "| Checkout | \`$TARGET\` |"
  echo "| Dirty | $DIRTY |"
  echo "| Host OS | $HOST_DESC ($HOST_OS) |"
  echo "| Node / npm | $NODE_V / $NPM_V |"
  echo "| Node the workflows use | ci.yml: $CI_NODE; publish-npm.yml: $PUBLISH_NODE (.nvmrc: $NVMRC; package.json engines.node: $ENGINES_NODE) |"
  if [ -n "$NODE_WARNING" ]; then
    echo "| Node warning | **$NODE_WARNING** |"
  fi
  echo "| Started (UTC) | $STARTED |"
  echo "| Finished (UTC) | $(date -u +%Y-%m-%dT%H:%M:%SZ) |"
  echo "| Job copies | \`$WORK\` (not deleted by the script) |"
  if [ "$DIRTY" = yes ]; then
    echo
    echo "Uncommitted changes in the checkout at start (\`git status --porcelain\`):"
    echo
    echo '```'
    echo "$DIRTY_LINES" | head -n 40
    echo '```'
  fi
  echo
  echo "## Jobs"
  echo
  echo "| Job | Mirrors | Result | Duration | Notes | Log |"
  echo "|---|---|---|---|---|---|"
  for j in "${ALL_JOBS[@]}"; do
    d="-"; [ -n "$(getv DURATION "$j")" ] && d="$(fmt_dur "$(getv DURATION "$j")")"
    l="-"; [ -f "$LOG_DIR/$j.log" ] && l="\`$LOG_DIR/$j.log\`"
    echo "| $j | $(job_mirrors "$j") | **$(getv RESULT "$j")** | $d | $(getv NOTE "$j" | sed 's/|/\\|/g') | $l |"
  done
  echo
  echo "**Counted skips: $skip of ${#ALL_JOBS[@]} jobs SKIPPED (not run, not passed); $test_skips individual test case(s) skipped inside the test job. A skip is not a pass.**"
  echo
  echo "Not mirrored, by design:"
  echo
  echo "- publish-npm.yml \"Publish to npm\" and \"Summary\": publishing, human-gated, and frozen (see the workflow's header)"
  echo "- publish-npm.yml's Typecheck and Test steps run the same commands as ci.yml's; the typecheck and test jobs cover them"
  echo "- actions/setup-node's Node $CI_NODE: this script uses whatever node is on PATH (recorded above)"
  echo
  echo "## Result: $OVERALL ($pass pass, $fail fail, $skip skip)"
} >"$REPORT"

echo
echo "local-ci: $OVERALL ($pass pass, $fail fail, $skip skip; $test_skips test-level skips)"
echo "local-ci: report: $REPORT"
[ -z "$NODE_WARNING" ] || echo "local-ci: WARNING: $NODE_WARNING"
[ "$fail" -eq 0 ]
