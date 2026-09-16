#!/bin/bash
# Run the decompilation cache tests through Ghidra's headless analyzer.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=ghidra_headless.sh
. "$SCRIPT_DIR/ghidra_headless.sh"
PROJECT_DIR="/tmp/ghidra_decomp_cache_test"
TEST_BINARY="$SCRIPT_DIR/uaf_test_binary"

[ -f "$TEST_BINARY" ] || gcc -O0 -g -fno-builtin -o "$TEST_BINARY" "$SCRIPT_DIR/uaf_test_cases.c"
rm -rf "$PROJECT_DIR"; mkdir -p "$PROJECT_DIR"
ghidra_headless "$PROJECT_DIR" DecompCacheTest \
    -import "$TEST_BINARY" -postScript test_decomp_cache.py \
    -scriptPath "$SCRIPT_DIR" -deleteProject 2>&1 | tee "$SCRIPT_DIR/decomp_cache_output.log"
grep -q "ALL TESTS PASSED" "$SCRIPT_DIR/decomp_cache_output.log" \
    && { echo "[+] ALL TESTS PASSED"; exit 0; } || { echo "[-] FAILURES"; exit 1; }
