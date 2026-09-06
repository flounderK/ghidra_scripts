#!/bin/bash
# Build the API fixture and run the ghidra_api test suite through Ghidra's
# headless analyzer, in a single session.
#
# Usage: ./run_api_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GHIDRA_DIR="/opt/ghidra_11.4.2_PUBLIC"
PROJECT_DIR="/tmp/ghidra_api_test"
PROJECT_NAME="GhidraApiTest"
TEST_BINARY="$SCRIPT_DIR/api_test_binary"
LOG="$SCRIPT_DIR/api_test_output.log"

echo "[*] Compiling fixture ..."
gcc -O0 -g -fno-builtin -o "$TEST_BINARY" "$SCRIPT_DIR/api_test_cases.c"

rm -rf "$PROJECT_DIR"; mkdir -p "$PROJECT_DIR"
echo "[*] Running ghidra_api suite ..."
"$GHIDRA_DIR/support/analyzeHeadless" \
    "$PROJECT_DIR" "$PROJECT_NAME" \
    -import "$TEST_BINARY" \
    -postScript test_ghidra_api.py \
    -scriptPath "$SCRIPT_DIR" \
    -deleteProject 2>&1 | tee "$LOG"

echo ""
if grep -q "ALL TESTS PASSED" "$LOG"; then
    echo "[+] ALL TESTS PASSED"
    exit 0
fi
echo "[-] SOME TESTS FAILED -- see $LOG"
exit 1
