#@runtime Jython
# Entry point for the ghidra_api test suite.
# Runs every module in tests/api_tests within a single Ghidra session --
# headless startup and auto-analysis dominate the runtime, so running each
# module in its own session would multiply the cost for no benefit.

import sys
import os

_this_dir = os.path.dirname(os.path.abspath(sourceFile.absolutePath))
_repo_dir = os.path.dirname(_this_dir)
for _path in (_repo_dir, _this_dir):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from __main__ import *
from ghidra_test_support import run_modules, report

# add a module here as each one gains tests
MODULES = [
    "test_call_ref_utils",
    "test_compat",
    "test_datatype_utils",
    "test_function_signature_utils",
    "test_graph_utils",
    "test_java_reflection_utils",
    "test_loopfinder",
    "test_pointer_utils",
    "test_raw_pcode_utils",
    "test_register_utils",
]

print("running %d ghidra_api test module(s) against %s"
      % (len(MODULES), currentProgram.getName()))
report(run_modules(MODULES, package="api_tests"))
