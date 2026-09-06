#@runtime Jython
# Verifies the decompilation cache against a real program.
# Run through Ghidra headless: see run_decomp_cache_tests.sh

import sys
import os
_this_dir = os.path.dirname(os.path.abspath(sourceFile.absolutePath))
_repo_dir = os.path.dirname(_this_dir)
if _repo_dir not in sys.path:
    sys.path.insert(0, _repo_dir)

from __main__ import *
from ghidra_api.decomp_utils import DecompUtils
from ghidra_api import decomp_cache
from ghidra_api.decomp_cache import CAUGHT_ERRORS

RESULTS = []


def check(name, condition, detail=""):
    RESULTS.append((name, bool(condition), detail))
    print("[%s] %s%s" % ("PASS" if condition else "FAIL", name,
                         (" -- " + detail) if detail else ""))


def counting_decomp_utils():
    """A DecompUtils that counts how many real decompilations it performs.

    Uses an isolated cache so each check measures its own decompilations
    rather than reusing another check's shared entries.
    """
    du = DecompUtils(use_shared_cache=False)
    counter = {"n": 0}
    original = du._decompile

    def counted(func, timeout):
        counter["n"] += 1
        return original(func, timeout)

    du._decompile = counted
    return du, counter


def internal_functions():
    return [f for f in currentProgram.getFunctionManager().getFunctions(True)
            if not f.isThunk() and not f.isExternal()]


def pick_functions():
    """A function that calls another local function, plus that callee."""
    internal = set(internal_functions())
    for func in sorted(internal, key=lambda f: str(f.getEntryPoint())):
        callees = [c for c in func.getCalledFunctions(monitor) if c in internal]
        if callees:
            return func, sorted(callees, key=lambda f: str(f.getEntryPoint()))[0]
    return None, None


def pick_param_function(preferred):
    """A function with at least one parameter, preferring @preferred."""
    if preferred is not None and preferred.getParameterCount() >= 1:
        return preferred
    for func in internal_functions():
        if func.getParameterCount() >= 1:
            return func
    return preferred


def transact(name, action):
    # CAUGHT_ERRORS, not Exception: Ghidra throws Java exceptions, which a
    # plain `except Exception` does not catch under Jython
    tx = currentProgram.startTransaction(name)
    try:
        action()
        currentProgram.endTransaction(tx, True)
    except CAUGHT_ERRORS:
        currentProgram.endTransaction(tx, False)
        raise


caller, callee = pick_functions()
param_func = pick_param_function(caller)
print("caller=%s callee=%s param_func=%s (%s params)"
      % (caller, callee, param_func,
         param_func.getParameterCount() if param_func else "n/a"))
if caller is None or callee is None:
    print("FAILED: could not find a local caller/callee pair in this binary")
    raise SystemExit(1)

# --- 1. repeated access decompiles once -------------------------------------
du, counter = counting_decomp_utils()
du.get_pcode_for_function(caller)
after_first = counter["n"]
du.get_pcode_for_function(caller)
du.get_high_function(caller)
du.get_function_prototype(caller)
check("repeated access reuses one decompilation",
      after_first == 1 and counter["n"] == 1,
      "first=%d total=%d" % (after_first, counter["n"]))

# --- 2. the parameter-varnode amplification is gone -------------------------
du2, counter2 = counting_decomp_utils()
du2.get_all_parameter_varnodes(param_func)
nparams = param_func.getParameterCount()
check("get_all_parameter_varnodes decompiles once, not once per parameter",
      counter2["n"] == 1,
      "%d params -> %d decompilations (uncached would be %d)"
      % (nparams, counter2["n"], nparams + 1))

# --- 3. results are equivalent to uncached ----------------------------------
uncached = DecompUtils(use_cache=False)
cached_ops = du.get_pcode_for_function(caller)
fresh_ops = uncached.get_pcode_for_function(caller)
check("cached result matches an uncached decompilation",
      cached_ops is not None and fresh_ops is not None
      and len(cached_ops) == len(fresh_ops),
      "cached=%s fresh=%s" % (len(cached_ops) if cached_ops else None,
                              len(fresh_ops) if fresh_ops else None))
uncached.close()

# --- 4. renaming a callee invalidates its caller ----------------------------
du3, counter3 = counting_decomp_utils()
du3.get_pcode_for_function(caller)
baseline = counter3["n"]
old_name = callee.getName()
transact("rename callee", lambda: callee.setName(old_name + "_renamed",
                                                 callee.getSymbol().getSource()))
du3.get_pcode_for_function(caller)
check("renaming a callee invalidates the caller",
      counter3["n"] == baseline + 1,
      "decompilations %d -> %d" % (baseline, counter3["n"]))

# --- 5. an unrelated cached function survives that change -------------------
others = [f for f in currentProgram.getFunctionManager().getFunctions(True)
          if f != caller and f != callee and not f.isThunk() and not f.isExternal()
          and callee not in f.getCalledFunctions(monitor)]
if others:
    du4, counter4 = counting_decomp_utils()
    unrelated = others[0]
    du4.get_pcode_for_function(unrelated)
    base4 = counter4["n"]
    transact("rename callee again",
             lambda: callee.setName(old_name + "_again", callee.getSymbol().getSource()))
    du4.get_pcode_for_function(unrelated)
    check("an unrelated function stays cached across that change",
          counter4["n"] == base4,
          "decompilations %d -> %d" % (base4, counter4["n"]))
    du4.close()
else:
    check("an unrelated function stays cached across that change", True, "skipped, no candidate")

# --- 6. renaming the function itself invalidates it -------------------------
du5, counter5 = counting_decomp_utils()
du5.get_pcode_for_function(caller)
base5 = counter5["n"]
caller_old = caller.getName()
transact("rename caller", lambda: caller.setName(caller_old + "_r",
                                                 caller.getSymbol().getSource()))
du5.get_pcode_for_function(caller)
check("renaming the function itself invalidates it",
      counter5["n"] == base5 + 1,
      "decompilations %d -> %d" % (base5, counter5["n"]))

# --- 7. fingerprint fallback when events are off ----------------------------
du6, counter6 = counting_decomp_utils()
du6.get_pcode_for_function(caller)
base6 = counter6["n"]
currentProgram.setEventsEnabled(False)
try:
    stats = du6.cache_stats()
    check("cache reports events inactive when they are disabled",
          stats["events_active"] is False, str(stats["events_active"]))
    du6.get_pcode_for_function(caller)
    unchanged_hits = counter6["n"] == base6
    transact("rename caller under no events",
             lambda: caller.setName(caller_old + "_r2", caller.getSymbol().getSource()))
    du6.get_pcode_for_function(caller)
    check("fingerprint revalidation catches a change with events disabled",
          unchanged_hits and counter6["n"] == base6 + 1,
          "unchanged_hit=%s decompilations %d -> %d"
          % (unchanged_hits, base6, counter6["n"]))
finally:
    currentProgram.setEventsEnabled(True)

# --- 8. stats and explicit invalidation -------------------------------------
# du has been listening throughout, so the renames above correctly evicted
# its entry; repopulate before asserting on entry count.
du.get_pcode_for_function(caller)
stats = du.cache_stats()
check("stats report hits, misses and entries",
      stats["hits"] > 0 and stats["misses"] > 0 and stats["entries"] > 0
      and stats["tracked_dependencies"] > 0, str(stats))
du.invalidate_cache()
check("invalidate() empties the cache", du.cache_stats()["entries"] == 0)
for d in (du, du2, du3, du5, du6):
    d.close()

# --- 9. one shared cache per program ----------------------------------------
decomp_cache.close_all_caches()
check("no shared caches after close_all_caches",
      decomp_cache.shared_cache_count() == 0,
      "count=%d" % decomp_cache.shared_cache_count())

first = DecompUtils()
second = DecompUtils()
check("separate DecompUtils instances share one cache and one listener",
      first._cache is second._cache and decomp_cache.shared_cache_count() == 1,
      "shared=%s count=%d" % (first._cache is second._cache,
                              decomp_cache.shared_cache_count()))

first.get_pcode_for_function(callee)
hits_before = second.cache_stats()["hits"]
second.get_pcode_for_function(callee)
check("a second instance reuses work the first one did",
      second.cache_stats()["hits"] == hits_before + 1,
      "hits %d -> %d" % (hits_before, second.cache_stats()["hits"]))

first.close()
check("closing one instance leaves the shared cache for the others",
      decomp_cache.shared_cache_count() == 1 and second.cache_stats() is not None,
      "count=%d" % decomp_cache.shared_cache_count())

isolated = DecompUtils(use_shared_cache=False)
check("use_shared_cache=False gives an isolated cache",
      isolated._cache is not second._cache
      and decomp_cache.shared_cache_count() == 1,
      "count=%d" % decomp_cache.shared_cache_count())
isolated.close()

second.close()
decomp_cache.close_all_caches()
check("close_all_caches tears down every shared cache",
      decomp_cache.shared_cache_count() == 0,
      "count=%d" % decomp_cache.shared_cache_count())

# --- 10. the three ways to opt out of caching --------------------------------
decomp_cache.close_all_caches()

# per instance
du_off = DecompUtils(use_cache=False)
off_counter = {"n": 0}
_orig_off = du_off._decompile


def _counted_off(func, timeout):
    off_counter["n"] += 1
    return _orig_off(func, timeout)


du_off._decompile = _counted_off
du_off.get_pcode_for_function(caller)
du_off.get_pcode_for_function(caller)
du_off.get_pcode_for_function(caller)
check("use_cache=False decompiles every time",
      off_counter["n"] == 3, "decompilations=%d" % off_counter["n"])
check("use_cache=False reports no cache stats", du_off.cache_stats() is None)
du_off.close()

# per call
du_fresh, counter_fresh = counting_decomp_utils()
du_fresh.get_pcode_for_function(caller)
base_fresh = counter_fresh["n"]
du_fresh.get_pcode_for_function(caller)
cached_hit = counter_fresh["n"] == base_fresh
du_fresh.get_pcode_for_function(caller, fresh=True)
check("fresh=True forces a decompilation past a valid cache entry",
      cached_hit and counter_fresh["n"] == base_fresh + 1,
      "cached_hit=%s decompilations %d -> %d"
      % (cached_hit, base_fresh, counter_fresh["n"]))
after_fresh = counter_fresh["n"]
du_fresh.get_pcode_for_function(caller)
check("the fresh result replaces the cached entry rather than bypassing it",
      counter_fresh["n"] == after_fresh, "decompilations=%d" % counter_fresh["n"])

# fresh=True must not reintroduce the per-parameter amplification
du_amp, counter_amp = counting_decomp_utils()
du_amp.get_all_parameter_varnodes(param_func, fresh=True)
check("fresh=True on get_all_parameter_varnodes still decompiles once",
      counter_amp["n"] == 1,
      "%d params -> %d decompilations" % (param_func.getParameterCount(),
                                          counter_amp["n"]))
du_amp.close()
du_fresh.close()

# process-wide
du_global, counter_global = counting_decomp_utils()
du_global.get_pcode_for_function(caller)
base_global = counter_global["n"]
previous = decomp_cache.set_caching_enabled(False)
try:
    check("set_caching_enabled(False) reports the previous setting",
          previous is True, str(previous))
    check("caching_enabled() reflects the switch",
          decomp_cache.caching_enabled() is False)
    du_global.get_pcode_for_function(caller)
    du_global.get_pcode_for_function(caller)
    check("caching disabled process-wide decompiles every time",
          counter_global["n"] == base_global + 2,
          "decompilations %d -> %d" % (base_global, counter_global["n"]))
    check("stats are unavailable while caching is disabled",
          du_global.cache_stats() is None)
    check("disabling tears down shared caches",
          decomp_cache.shared_cache_count() == 0,
          "count=%d" % decomp_cache.shared_cache_count())
finally:
    decomp_cache.set_caching_enabled(previous)
check("re-enabling restores caching", decomp_cache.caching_enabled() is True)

# an isolated cache keeps its listener through the global switch, so its
# entries are still valid afterwards and are served without decompiling
base_restored = counter_global["n"]
du_global.get_pcode_for_function(caller)
check("an isolated cache survives the global switch",
      counter_global["n"] == base_restored,
      "decompilations %d -> %d" % (base_restored, counter_global["n"]))

du_global.invalidate_cache()
du_global.get_pcode_for_function(caller)
after_miss = counter_global["n"]
du_global.get_pcode_for_function(caller)
check("caching works again after re-enabling",
      after_miss == base_restored + 1 and counter_global["n"] == after_miss,
      "miss then hit: %d -> %d -> %d"
      % (base_restored, after_miss, counter_global["n"]))
du_global.close()
decomp_cache.close_all_caches()

# --- 11. fingerprint revalidation actually validates -------------------------
# Entries cached while events were active must still carry a fingerprint,
# otherwise this path degenerates into "always invalidate".
decomp_cache.close_all_caches()
du_fp, counter_fp = counting_decomp_utils()
du_fp.get_pcode_for_function(caller)
base_fp = counter_fp["n"]
# must not be anything caller depends on -- its own callees are dependencies
caller_callees = set(caller.getCalledFunctions(monitor))
unrelated = None
for f in internal_functions():
    if f != caller and f not in caller_callees:
        unrelated = f
        break

memory = currentProgram.getMemory()
entry_addr = caller.getEntryPoint()
original_byte = memory.getByte(entry_addr)
currentProgram.setEventsEnabled(False)
try:
    if unrelated is not None:
        # move the modification number with a change caller does not depend on,
        # so the fast path is skipped and the fingerprint is really compared
        u_name = unrelated.getName()
        transact("rename unrelated",
                 lambda: unrelated.setName(u_name + "_u",
                                           unrelated.getSymbol().getSource()))
        du_fp.get_pcode_for_function(caller)
        check("fingerprint revalidation serves a hit when nothing relevant changed",
              counter_fp["n"] == base_fp,
              "decompilations %d -> %d" % (base_fp, counter_fp["n"]))
        check("a revalidation was actually performed",
              du_fp.cache_stats()["revalidations"] > 0,
              "revalidations=%d" % du_fp.cache_stats()["revalidations"])
    else:
        check("fingerprint revalidation serves a hit when nothing relevant changed",
              True, "skipped, no unrelated function")
        check("a revalidation was actually performed", True, "skipped")

    # the digest must be stable across calls and sensitive to content --
    # a non-deterministic checksum would silently make every revalidation miss
    check("body digest is deterministic",
          decomp_cache.body_digest(caller) == decomp_cache.body_digest(caller))
    if unrelated is not None:
        check("body digest distinguishes different bodies",
              decomp_cache.body_digest(caller) != decomp_cache.body_digest(unrelated))
    else:
        check("body digest distinguishes different bodies", True, "skipped")

    # Ghidra refuses to write over a defined instruction, so clear it first
    listing = currentProgram.getListing()

    def patch_entry_byte(value):
        listing.clearCodeUnits(entry_addr, entry_addr, False)
        memory.setByte(entry_addr, value)

    base_bytes = counter_fp["n"]
    try:
        transact("patch a body byte",
                 lambda: patch_entry_byte(original_byte ^ 0x01))
        du_fp.get_pcode_for_function(caller)
        check("fingerprint revalidation catches an instruction byte change",
              counter_fp["n"] == base_bytes + 1,
              "decompilations %d -> %d" % (base_bytes, counter_fp["n"]))
    except CAUGHT_ERRORS as exc:
        check("fingerprint revalidation catches an instruction byte change",
              False, "could not patch: %s" % exc)
    finally:
        try:
            transact("restore body byte",
                     lambda: patch_entry_byte(original_byte))
        except CAUGHT_ERRORS as exc:
            print("could not restore patched byte: %s" % exc)
finally:
    currentProgram.setEventsEnabled(True)
du_fp.invalidate_cache()
du_fp.close()
decomp_cache.close_all_caches()

print("")
failed = [n for n, ok, _ in RESULTS if not ok]
print("%d/%d checks passed" % (len(RESULTS) - len(failed), len(RESULTS)))
if failed:
    print("FAILED: %s" % ", ".join(failed))
else:
    print("ALL TESTS PASSED")
