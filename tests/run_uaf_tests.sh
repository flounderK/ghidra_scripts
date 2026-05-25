#!/bin/bash
# Build the test binary and run the UAF finder test harness
# through Ghidra's headless analyzer.
#
# Usage: ./run_uaf_tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
GHIDRA_DIR="/opt/ghidra_11.4.2_PUBLIC"
PROJECT_DIR="/tmp/ghidra_uaf_test"
PROJECT_NAME="UAFTest"
TEST_BINARY="$SCRIPT_DIR/uaf_test_binary"
TEST_SOURCE="$SCRIPT_DIR/uaf_test_cases.c"

echo "[*] Compiling test cases ..."
gcc -O0 -g -fno-builtin -o "$TEST_BINARY" "$TEST_SOURCE"
echo "[+] Compiled $TEST_BINARY"

# Clean previous project
rm -rf "$PROJECT_DIR"
mkdir -p "$PROJECT_DIR"

echo "[*] Running Ghidra headless analysis ..."
"$GHIDRA_DIR/support/analyzeHeadless" \
    "$PROJECT_DIR" "$PROJECT_NAME" \
    -import "$TEST_BINARY" \
    -postScript test_uaf_finder.py \
    -scriptPath "$SCRIPT_DIR" \
    -deleteProject \
    2>&1 | tee "$SCRIPT_DIR/test_output.log"

echo ""
echo "[*] Full log saved to $SCRIPT_DIR/test_output.log"

# Check for PASS/FAIL in output
if grep -q "ALL TESTS PASSED" "$SCRIPT_DIR/test_output.log"; then
    echo "[+] ALL TESTS PASSED"
    exit 0
else
    echo "[-] SOME TESTS FAILED — see log above"
    exit 1
fi
