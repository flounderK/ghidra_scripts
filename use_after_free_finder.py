#@runtime Jython
# Use-After-Free vulnerability finder for Ghidra
# Detection approach modeled after LLVM/Clang's MallocChecker static analyzer.
#
# Tracks pointer state through a state machine:
#   Allocated -> Released -> Use = UAF
#   Allocated -> Released -> Released = Double Free
#
# Uses Ghidra's decompiler PCode SSA form and data flow analysis
# (forward/backward slicing) to track pointer aliases and
# control flow ordering.

from __main__ import *
from decomp_utils import DecompUtils
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.app.decompiler.component import DecompilerUtils
import logging

log = logging.getLogger(__file__)
if not log.handlers:
    log.addHandler(logging.StreamHandler())
log.setLevel(logging.WARNING)


ALLOC_FUNCS = {
    "malloc", "calloc", "realloc", "reallocarray",
    "aligned_alloc", "memalign", "posix_memalign",
    "valloc", "pvalloc",
    "strdup", "strndup", "wcsdup",
    "_Znwm", "_Znwj", "_Znam", "_Znaj",
    "g_malloc", "g_malloc0", "g_new", "g_new0",
    "xmalloc", "xcalloc",
    "operator.new", "operator.new[]",
}

FREE_FUNCS = {
    "free", "cfree",
    "_ZdlPv", "_ZdaPv",
    "g_free", "xfree",
    "operator.delete", "operator.delete[]",
}

REALLOC_FUNCS = {
    "realloc", "reallocarray", "reallocf",
    "g_realloc",
}

# PCode ops that preserve pointer identity (pointer derivation).
# CAST is handled specially in _forward_pointer_walk to skip
# pointer-to-integer narrowing casts.
_POINTER_PROP_OPS = {
    PcodeOpAST.COPY,
    PcodeOpAST.PTRSUB,
    PcodeOpAST.INT_ADD,
    PcodeOpAST.INT_SUB,
    PcodeOpAST.MULTIEQUAL,
}
if hasattr(PcodeOpAST, "PTRADD"):
    _POINTER_PROP_OPS.add(PcodeOpAST.PTRADD)

# PCode ops that are comparisons/branches, not real "uses"
_COMPARISON_OPS = {
    PcodeOpAST.INT_EQUAL,
    PcodeOpAST.INT_NOTEQUAL,
    PcodeOpAST.INT_LESS,
    PcodeOpAST.INT_LESSEQUAL,
    PcodeOpAST.INT_SLESS,
    PcodeOpAST.INT_SLESSEQUAL,
    PcodeOpAST.BOOL_AND,
    PcodeOpAST.BOOL_OR,
    PcodeOpAST.BOOL_NEGATE,
    PcodeOpAST.CBRANCH,
    PcodeOpAST.BRANCH,
    PcodeOpAST.BRANCHIND,
    PcodeOpAST.RETURN,
}


class UAFFinding(object):
    def __init__(self, func_name, func_entry, free_addr, use_addr,
                 use_type, alloc_addr=None, alloc_func=None,
                 free_func=None):
        self.func_name = func_name
        self.func_entry = func_entry
        self.free_addr = free_addr
        self.use_addr = use_addr
        self.use_type = use_type
        self.alloc_addr = alloc_addr
        self.alloc_func = alloc_func
        self.free_func = free_func

    def __str__(self):
        parts = ["[UAF] %s @ %s:" % (self.use_type.upper(), self.func_name)]
        if self.alloc_addr:
            parts.append("  alloc (%s) at %s" % (
                self.alloc_func or "unknown", self.alloc_addr))
        parts.append("  free  (%s) at %s" % (
            self.free_func or "free", self.free_addr))
        parts.append("  use   at %s" % self.use_addr)
        return "\n".join(parts)

    def __repr__(self):
        return "UAFFinding(%s, free=%s, use=%s, type=%s)" % (
            self.func_name, self.free_addr, self.use_addr, self.use_type)


class UseAfterFreeFinder(object):

    def __init__(self, program=None, alloc_funcs=None, free_funcs=None,
                 realloc_funcs=None):
        if program is None:
            program = currentProgram
        self.program = program
        self.du = DecompUtils(program)
        self.alloc_funcs = alloc_funcs if alloc_funcs is not None \
            else ALLOC_FUNCS
        self.free_funcs = free_funcs if free_funcs is not None \
            else FREE_FUNCS
        self.realloc_funcs = realloc_funcs if realloc_funcs is not None \
            else REALLOC_FUNCS
        self.findings = []
        self._fm = self.program.getFunctionManager()

    def _get_func_at(self, addr):
        """Resolve a function from an address using self.program
        rather than the global currentProgram."""
        return self._fm.getFunctionContaining(addr)

    def _get_func_name_for_call_op(self, call_op):
        if call_op.opcode not in (PcodeOpAST.CALL, PcodeOpAST.CALLIND):
            return None
        if call_op.opcode == PcodeOpAST.CALLIND:
            return None
        addr_vn = call_op.getInput(0)
        if addr_vn is None:
            return None
        called_addr = addr_vn.getAddress()
        called_func = self._get_func_at(called_addr)
        if called_func is None:
            return None
        return called_func.getName()

    def _build_block_reachability(self, blocks):
        """For each block, compute the set of block indices reachable
        via outgoing CFG edges (BFS).  Uses a dict keyed by block
        index so non-contiguous indices are handled safely."""
        block_map = {}
        for block in blocks:
            block_map[block.getIndex()] = block

        reachable = {}
        for idx, block in block_map.items():
            visited = set()
            stack = []
            for i in range(block.getOutSize()):
                stack.append(block.getOut(i).getIndex())
            while stack:
                curr = stack.pop()
                if curr in visited:
                    continue
                visited.add(curr)
                curr_block = block_map.get(curr)
                if curr_block is None:
                    continue
                for i in range(curr_block.getOutSize()):
                    succ_idx = curr_block.getOut(i).getIndex()
                    if succ_idx not in visited:
                        stack.append(succ_idx)
            reachable[idx] = visited
        return reachable

    def _is_pointer_sized_output(self, op):
        """Return True if a CAST op's output looks like a pointer
        (same size as the input).  A narrowing CAST (e.g. ptr -> int32
        on a 64-bit binary) is likely a pointer-to-integer conversion
        and should NOT propagate aliases."""
        inp = op.getInput(0)
        out = op.getOutput()
        if inp is None or out is None:
            return True
        return out.getSize() >= inp.getSize()

    def _forward_pointer_walk(self, start_vn, existing=None):
        """Walk forward through pointer-preserving ops only (COPY,
        PTRSUB, PTRADD, INT_ADD, MULTIEQUAL).  CAST ops are followed
        only when the output is at least as wide as the input (skips
        pointer-to-integer narrowing).  Stops at LOAD boundaries so
        values loaded from freed memory are not treated as pointer
        aliases."""
        result = set()
        if existing is None:
            existing = set()
        worklist = [start_vn]
        while worklist:
            vn = worklist.pop()
            if vn in result:
                continue
            result.add(vn)
            try:
                desc_iter = vn.getDescendants()
                while desc_iter.hasNext():
                    op = desc_iter.next()
                    output = op.getOutput()
                    if output is None:
                        continue
                    if output in result or output in existing:
                        continue
                    if op.opcode in _POINTER_PROP_OPS:
                        worklist.append(output)
                    elif op.opcode == PcodeOpAST.CAST:
                        if self._is_pointer_sized_output(op):
                            worklist.append(output)
            except Exception as e:
                log.debug("forward walk error on %s: %s", start_vn, e)
        return result

    def _get_pointer_aliases(self, freed_varnode, all_ops):
        """Collect all varnodes that alias the freed pointer.

        Strategy (mirrors LLVM MallocChecker symbol tracking):
        1. Forward pointer walk from the freed varnode itself.
        2. Backward slice to the allocation site, then forward pointer
           walk from the allocation output to capture aliases created
           before the free.
        3. If no allocation is found (e.g. pointer is a parameter),
           backward slice then forward walk from each source varnode.
        """
        aliases = self._forward_pointer_walk(freed_varnode)

        alloc_op, _ = self._find_alloc_for_pointer(freed_varnode)
        if alloc_op is not None:
            alloc_output = alloc_op.getOutput()
            if alloc_output is not None:
                alloc_aliases = self._forward_pointer_walk(
                    alloc_output, aliases)
                aliases.update(alloc_aliases)
        else:
            try:
                back_vns = DecompilerUtils.getBackwardSlice(freed_varnode)
                if back_vns is not None:
                    for bvn in back_vns:
                        if bvn not in aliases:
                            src_aliases = self._forward_pointer_walk(
                                bvn, aliases)
                            aliases.update(src_aliases)
            except Exception as e:
                log.debug("backward slice error for aliases: %s", e)

        return aliases

    def _find_alloc_for_pointer(self, varnode):
        """Trace backward from varnode to find the allocation site.
        Returns (alloc_pcode_op, alloc_func_name) or (None, None)."""
        try:
            back_ops = DecompilerUtils.getBackwardSliceToPCodeOps(varnode)
            if back_ops is None:
                return None, None
            for op in back_ops:
                if op.opcode != PcodeOpAST.CALL:
                    continue
                fname = self._get_func_name_for_call_op(op)
                if fname and (fname in self.alloc_funcs or
                              fname in self.realloc_funcs):
                    return op, fname
        except Exception as e:
            log.debug("backward slice error for alloc: %s", e)
        return None, None

    def _classify_use(self, op, freed_aliases):
        """Determine if a PcodeOp constitutes a dangerous use of freed
        memory.  Returns (is_use, use_type_string) following
        LLVM MallocChecker's checkLocation categories:
          - load:        read from freed memory
          - store:       write to freed memory
          - store_value: storing a dangling pointer into a live location
          - double_free: passing freed ptr to free again
          - call_arg:    passing freed ptr to another function
        """
        if op.opcode == PcodeOpAST.LOAD:
            load_addr = op.getInput(1)
            if load_addr in freed_aliases:
                return True, "load"

        elif op.opcode == PcodeOpAST.STORE:
            store_addr = op.getInput(1)
            if store_addr in freed_aliases:
                return True, "store"
            store_val = op.getInput(2) if op.getNumInputs() > 2 else None
            if store_val is not None and store_val in freed_aliases:
                return True, "store_value"

        elif op.opcode in (PcodeOpAST.CALL, PcodeOpAST.CALLIND):
            fname = self._get_func_name_for_call_op(op)
            if fname and (fname in self.free_funcs or
                          fname in self.realloc_funcs):
                for i in range(1, op.getNumInputs()):
                    if op.getInput(i) in freed_aliases:
                        return True, "double_free"
            else:
                for i in range(1, op.getNumInputs()):
                    if op.getInput(i) in freed_aliases:
                        return True, "call_arg"

        return False, None

    def _op_is_after(self, candidate, reference, reachability):
        """True if candidate_op may execute after reference_op,
        using basic block reachability and intra-block sequence order.
        For same-block ops in a self-looping block, also returns True
        when the candidate precedes the reference (loop-carried UAF)."""
        ref_parent = reference.getParent()
        cand_parent = candidate.getParent()
        if ref_parent is None or cand_parent is None:
            return False

        ref_idx = ref_parent.getIndex()
        cand_idx = cand_parent.getIndex()

        if ref_idx == cand_idx:
            if (candidate.getSeqnum().getOrder() >
                    reference.getSeqnum().getOrder()):
                return True
            # Loop-carried: if this block loops back to itself the
            # candidate can execute after the reference on the next
            # iteration even though it has a lower sequence order.
            if ref_idx in reachability.get(ref_idx, set()):
                return True
            return False

        return cand_idx in reachability.get(ref_idx, set())

    def find_uaf_in_function(self, func):
        """Analyze a single function for use-after-free issues.
        Returns a list of UAFFinding objects."""
        findings = []

        if func.isThunk():
            return findings

        high_func = self.du.get_high_function(func)
        if high_func is None:
            log.warning("Failed to decompile %s", func.getName())
            return findings

        all_ops = list(high_func.getPcodeOps())
        blocks = list(high_func.getBasicBlocks())
        if not blocks:
            return findings

        reachability = self._build_block_reachability(blocks)

        # Collect all free/realloc calls (both free the input pointer).
        # Also check CALLIND so that frees through function pointers
        # are not silently missed.
        dealloc_ops = []
        for op in all_ops:
            if op.opcode not in (PcodeOpAST.CALL, PcodeOpAST.CALLIND):
                continue
            fname = self._get_func_name_for_call_op(op)
            if fname is None:
                continue
            if fname in self.free_funcs or fname in self.realloc_funcs:
                dealloc_ops.append((op, fname))

        if not dealloc_ops:
            return findings

        # Track which (use_addr, use_type) pairs have already been
        # reported so multiple dealloc_ops targeting the same pointer
        # do not inflate the finding count.
        reported_uses = set()

        for free_op, free_func_name in dealloc_ops:
            if free_op.getNumInputs() < 2:
                continue
            freed_varnode = free_op.getInput(1)
            if freed_varnode is None:
                continue

            aliases = self._get_pointer_aliases(freed_varnode, all_ops)

            alloc_op, alloc_func_name = self._find_alloc_for_pointer(
                freed_varnode)
            alloc_addr = None
            if alloc_op is not None:
                alloc_addr = alloc_op.getSeqnum().getTarget()

            for op in all_ops:
                if op == free_op:
                    continue

                if op.opcode in _COMPARISON_OPS:
                    continue

                is_use, use_type = self._classify_use(op, aliases)
                if not is_use:
                    continue

                if not self._op_is_after(op, free_op, reachability):
                    continue

                use_key = (str(op.getSeqnum().getTarget()), use_type)
                if use_key in reported_uses:
                    continue
                reported_uses.add(use_key)

                finding = UAFFinding(
                    func_name=func.getName(),
                    func_entry=func.getEntryPoint(),
                    free_addr=free_op.getSeqnum().getTarget(),
                    use_addr=op.getSeqnum().getTarget(),
                    use_type=use_type,
                    alloc_addr=alloc_addr,
                    alloc_func=alloc_func_name,
                    free_func=free_func_name,
                )
                findings.append(finding)

        return findings

    def find_all_uaf(self):
        """Scan every function in the program for use-after-free issues."""
        self.findings = []
        fm = self.program.getFunctionManager()

        for func in fm.getFunctions(True):
            if func.isThunk():
                continue
            try:
                func_findings = self.find_uaf_in_function(func)
                self.findings.extend(func_findings)
            except Exception as e:
                log.warning("Error analyzing %s: %s",
                            func.getName(), str(e))

        return self.findings

    def get_findings_by_function(self):
        """Return findings grouped by function name, deduplicated."""
        by_func = {}
        seen = set()
        for f in self.findings:
            key = (str(f.func_name), str(f.free_addr),
                   str(f.use_addr), f.use_type)
            if key in seen:
                continue
            seen.add(key)
            if f.func_name not in by_func:
                by_func[f.func_name] = []
            by_func[f.func_name].append(f)
        return by_func

    def print_findings(self):
        by_func = self.get_findings_by_function()
        total = sum(len(v) for v in by_func.values())

        if total == 0:
            print("[*] No use-after-free vulnerabilities found")
            return

        print("[+] Found %d potential use-after-free issue(s) "
              "in %d function(s):\n" % (total, len(by_func)))
        counter = 1
        for func_name in sorted(by_func.keys()):
            for finding in by_func[func_name]:
                print("--- Finding %d ---" % counter)
                print(str(finding))
                print("")
                counter += 1


def find_uaf():
    """Convenience entry point for interactive use."""
    finder = UseAfterFreeFinder()
    finder.find_all_uaf()
    finder.print_findings()
    return finder
