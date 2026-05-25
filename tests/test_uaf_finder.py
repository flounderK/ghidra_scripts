#@runtime Jython
# Test harness for use_after_free_finder.py
# Run inside Ghidra (headless or interactive) against a binary
# compiled from uaf_test_cases.c.

import sys
import os
# Ensure the parent directory (repo root) is on the import path
_this_dir = os.path.dirname(os.path.abspath(sourceFile.absolutePath))
_repo_dir = os.path.dirname(_this_dir)
if _repo_dir not in sys.path:
    sys.path.insert(0, _repo_dir)

from __main__ import *
from use_after_free_finder import UseAfterFreeFinder

# Functions that MUST produce at least one finding
EXPECTED_POSITIVE = {
    "test_uaf_simple_read",
    "test_uaf_simple_write",
    "test_uaf_alias",
    "test_uaf_double_free",
    "test_uaf_conditional",
    "test_uaf_pass_to_func",
    "test_uaf_struct_field",
}

# Functions that must NOT produce findings
EXPECTED_NEGATIVE = {
    "test_no_uaf_normal",
    "test_no_uaf_reassign",
    "test_no_uaf_conditional_return",
    "main",
}


def run_tests():
    finder = UseAfterFreeFinder()
    finder.find_all_uaf()

    by_func = finder.get_findings_by_function()

    passes = 0
    fails = 0
    details = []

    # --- positive cases ---
    for name in sorted(EXPECTED_POSITIVE):
        if name in by_func:
            n = len(by_func[name])
            types = set(f.use_type for f in by_func[name])
            details.append("PASS  %s  (%d finding(s): %s)" %
                           (name, n, ", ".join(sorted(types))))
            passes += 1
        else:
            details.append("FAIL  %s  (expected finding, got none)" % name)
            fails += 1

    # --- negative cases ---
    for name in sorted(EXPECTED_NEGATIVE):
        if name in by_func:
            n = len(by_func[name])
            types = set(f.use_type for f in by_func[name])
            details.append("FAIL  %s  (expected none, got %d: %s)" %
                           (name, n, ", ".join(sorted(types))))
            for f in by_func[name]:
                details.append("        %s" % repr(f))
            fails += 1
        else:
            details.append("PASS  %s  (correctly no findings)" % name)
            passes += 1

    # --- unexpected functions ---
    all_expected = EXPECTED_POSITIVE | EXPECTED_NEGATIVE
    for name in sorted(by_func.keys()):
        if name not in all_expected:
            n = len(by_func[name])
            details.append("INFO  %s  (unexpected, %d finding(s))" %
                           (name, n))

    total = passes + fails
    print("\n===== UAF Finder Test Results =====")
    for line in details:
        print(line)
    print("\nPassed: %d / %d" % (passes, total))
    if fails:
        print("FAILED: %d / %d" % (fails, total))
    else:
        print("ALL TESTS PASSED")
    print("===================================\n")

    # Also dump raw findings for debugging
    print("--- Raw findings ---")
    finder.print_findings()

    return fails == 0


run_tests()
