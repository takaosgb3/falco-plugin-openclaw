#!/usr/bin/env bash
# deploy_local.sh — Deploy local E2E test results to GitHub Pages
#
# Replicates the CI allure-report + deploy-pages pipeline locally.
# Usage: make e2e-deploy-local  (or: bash e2e/scripts/deploy_local.sh)
#
# Prerequisites:
#   - make e2e-native (or e2e-ci) has been run and e2e/results/test-results.json exists
#   - allure CLI installed (brew install allure)
#   - python3 with pip packages: pytest, allure-pytest
#   - git remote "origin" with gh-pages branch

set -euo pipefail

# --- Configuration ---
BASE_URL="https://takaosgb3.github.io/falco-plugin-openclaw"
RESULTS_DIR="e2e/results"
ALLURE_RESULTS_DIR="allure-results"
ALLURE_REPORT_DIR="allure-report"
SCRIPTS_DIR="e2e/scripts"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# --- Step 1: Prerequisites check ---
info "Checking prerequisites..."

command -v allure >/dev/null 2>&1 || error "allure CLI not found. Install with: brew install allure"
command -v python3 >/dev/null 2>&1 || error "python3 not found"
command -v git >/dev/null 2>&1 || error "git not found"
command -v jq >/dev/null 2>&1 || error "jq not found. Install with: brew install jq"

ok "All prerequisites found"

# --- Step 2: Test results check ---
if [ ! -f "${RESULTS_DIR}/test-results.json" ]; then
    error "Test results not found: ${RESULTS_DIR}/test-results.json\nRun 'make e2e-native' first"
fi

ok "Test results found: ${RESULTS_DIR}/test-results.json"

# --- Step 3: Generate Allure results (pytest wrapper) ---
info "Generating Allure results..."
rm -rf "${ALLURE_RESULTS_DIR}"
make e2e-report
ok "Allure results generated in ${ALLURE_RESULTS_DIR}/"

# --- Step 4: Fetch history from gh-pages ---
info "Fetching history from gh-pages..."

git fetch origin gh-pages --depth=1 2>/dev/null || { warn "No gh-pages branch yet, skipping history"; }

LATEST=$(git ls-tree --name-only origin/gh-pages -- e2e-report/ 2>/dev/null \
    | sed 's|^e2e-report/||' | grep -E '^[0-9]+$' | sort -n | tail -1) || true

if [ -n "$LATEST" ]; then
    info "Fetching history from e2e-report/${LATEST}"
    mkdir -p "${ALLURE_RESULTS_DIR}/history"

    for f in categories-trend.json duration-trend.json history-trend.json history.json retry-trend.json; do
        git show "origin/gh-pages:e2e-report/${LATEST}/history/${f}" \
            > "${ALLURE_RESULTS_DIR}/history/${f}" 2>/dev/null || true
    done

    # Fetch Rule Mapping Trend history
    git show "origin/gh-pages:e2e-report/${LATEST}/widgets/rule-mapping-trend-history.json" \
        > "${ALLURE_RESULTS_DIR}/history/rule-mapping-trend-history.json" 2>/dev/null || true

    ok "History files retrieved:"
    ls -la "${ALLURE_RESULTS_DIR}/history/" || true
else
    warn "No previous report found, skipping history"
fi

# --- Determine run number ---
if [ -n "$LATEST" ]; then
    RUN_NUMBER=$((LATEST + 1))
else
    RUN_NUMBER=1
fi
REPORT_URL="${BASE_URL}/e2e-report/${RUN_NUMBER}/"
info "Run number: ${RUN_NUMBER}"
info "Report URL: ${REPORT_URL}"

# --- Step 5: Inject metadata ---
info "Injecting Allure metadata..."

BRANCH=$(git rev-parse --abbrev-ref HEAD)
COMMIT=$(git rev-parse HEAD)

cat > "${ALLURE_RESULTS_DIR}/environment.properties" <<PROPS
Plugin=falco-plugin-openclaw
Runner=Local (macOS)
Run.Number=${RUN_NUMBER}
Branch=${BRANCH}
Commit=${COMMIT}
PROPS

cat > "${ALLURE_RESULTS_DIR}/executor.json" <<JSON
{
  "name": "Local Deploy",
  "type": "local",
  "buildName": "E2E Tests #${RUN_NUMBER} (local)",
  "reportUrl": "${REPORT_URL}",
  "buildOrder": ${RUN_NUMBER}
}
JSON

ok "Metadata injected"

# --- Step 6: Generate Rule Mapping Trend HTML ---
info "Generating Rule Mapping Trend HTML..."

mkdir -p "${ALLURE_RESULTS_DIR}/widgets"
python3 "${SCRIPTS_DIR}/generate_rule_mapping_trend_html.py" \
    --test-results "${RESULTS_DIR}/test-results.json" \
    --run-number "${RUN_NUMBER}" \
    --report-url "${REPORT_URL}" \
    --history-input "${ALLURE_RESULTS_DIR}/history/rule-mapping-trend-history.json" \
    --history-output "${ALLURE_RESULTS_DIR}/widgets/rule-mapping-trend-history.json" \
    --html-output "${ALLURE_RESULTS_DIR}/widgets/rule-mapping-trend.html" \
    --max-history 20

ok "Rule Mapping Trend HTML generated"

# --- Step 7: Generate Allure HTML report ---
info "Generating Allure HTML report..."
allure generate "${ALLURE_RESULTS_DIR}" -o "${ALLURE_REPORT_DIR}" --clean
ok "Allure report generated in ${ALLURE_REPORT_DIR}/"

# --- Step 8: Merge Rule Mapping + copy widgets ---
info "Merging Rule Mapping into Categories Trend..."

python3 "${SCRIPTS_DIR}/generate_rule_mapping_trend.py" \
    --test-results "${RESULTS_DIR}/test-results.json" \
    --run-number "${RUN_NUMBER}" \
    --report-url "${REPORT_URL}" \
    --history-input "${ALLURE_REPORT_DIR}/history/categories-trend.json" \
    --history-output "${ALLURE_REPORT_DIR}/history/categories-trend.json" \
    --max-history 20 \
    --verbose || true

# Copy merged data to widgets for chart rendering
if [ -f "${ALLURE_REPORT_DIR}/history/categories-trend.json" ]; then
    mkdir -p "${ALLURE_REPORT_DIR}/widgets"
    cp "${ALLURE_REPORT_DIR}/history/categories-trend.json" "${ALLURE_REPORT_DIR}/widgets/categories-trend.json"
fi

# Copy Rule Mapping Trend widgets to report
if [ -d "${ALLURE_RESULTS_DIR}/widgets" ]; then
    mkdir -p "${ALLURE_REPORT_DIR}/widgets"
    cp -r "${ALLURE_RESULTS_DIR}/widgets/"* "${ALLURE_REPORT_DIR}/widgets/"
fi

ok "Widgets merged and copied"

# --- Step 9: Deploy to gh-pages via git worktree ---
info "Deploying to gh-pages (run #${RUN_NUMBER})..."

TMP_DIR=$(mktemp -d)
cleanup() {
    info "Cleaning up worktree..."
    git worktree remove --force "$TMP_DIR" 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT

git worktree add "$TMP_DIR" origin/gh-pages 2>/dev/null

# Copy numbered report (immutable archive)
mkdir -p "$TMP_DIR/e2e-report/${RUN_NUMBER}"
cp -r "${ALLURE_REPORT_DIR}/"* "$TMP_DIR/e2e-report/${RUN_NUMBER}/"

# Create latest redirect
mkdir -p "$TMP_DIR/e2e-report/latest"
cat > "$TMP_DIR/e2e-report/latest/index.html" <<HTML
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="0; url=../${RUN_NUMBER}/">
  <link rel="canonical" href="../${RUN_NUMBER}/">
  <title>Redirecting to latest report...</title>
</head>
<body>
  <p>Redirecting to <a href="../${RUN_NUMBER}/">latest report (#${RUN_NUMBER})</a>...</p>
</body>
</html>
HTML

# Create root redirect
cat > "$TMP_DIR/index.html" <<HTML
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="0; url=e2e-report/${RUN_NUMBER}/">
  <link rel="canonical" href="e2e-report/${RUN_NUMBER}/">
  <title>Falco Plugin OpenClaw - E2E Reports</title>
</head>
<body>
  <p>Redirecting to <a href="e2e-report/${RUN_NUMBER}/">latest E2E report (#${RUN_NUMBER})</a>...</p>
</body>
</html>
HTML

# Commit and push
cd "$TMP_DIR"
git add .
git commit -m "Local deploy: E2E report #${RUN_NUMBER}" || { warn "Nothing to commit"; }
git push origin HEAD:gh-pages

cd - >/dev/null

ok "Deployed to gh-pages"

# --- Step 10: Summary ---
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Deploy Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "  Report #${RUN_NUMBER}: ${CYAN}${REPORT_URL}${NC}"
echo -e "  Rule Mapping: ${CYAN}${REPORT_URL}widgets/rule-mapping-trend.html${NC}"
echo -e "  Latest:       ${CYAN}${BASE_URL}/e2e-report/latest/${NC}"
echo -e "  Root:         ${CYAN}${BASE_URL}/${NC}"
echo ""

# Display Rule Mapping stats if available
HISTORY_FILE="${ALLURE_REPORT_DIR}/widgets/rule-mapping-trend-history.json"
if [ -f "$HISTORY_FILE" ]; then
    CURRENT_RUN=$(jq -r '.[-1]' "$HISTORY_FILE")
    MATCH=$(echo "$CURRENT_RUN" | jq -r '.data["Rule Match"] // 0')
    MISMATCH=$(echo "$CURRENT_RUN" | jq -r '.data["Rule Mismatch"] // 0')
    EXPECTED_NOT=$(echo "$CURRENT_RUN" | jq -r '.data["Expected Not Detected"] // 0')
    NOT_DEF=$(echo "$CURRENT_RUN" | jq -r '.data["Not Defined"] // 0')
    TOTAL_RM=$((MATCH + MISMATCH + EXPECTED_NOT + NOT_DEF))
    if [ "$TOTAL_RM" -gt 0 ]; then
        MATCH_RATE=$(echo "scale=1; $MATCH * 100 / $TOTAL_RM" | bc)
        echo "  Rule Mapping:"
        echo "    Rule Match:          ${MATCH}"
        echo "    Rule Mismatch:       ${MISMATCH}"
        echo "    Expected Not Detected: ${EXPECTED_NOT}"
        echo "    Not Defined:         ${NOT_DEF}"
        echo -e "    Match Rate:          ${GREEN}${MATCH_RATE}%${NC}"
        echo ""
    fi
fi
