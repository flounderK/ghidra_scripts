#@runtime Jython
"""Tests for ghidra_api.loopfinder against the fixture's nested loops."""

from __main__ import *
from ghidra.program.model.block import BasicBlockModel

from ghidra_api import loopfinder as lf
from ghidra_test_support import get_function


def instruction_addresses(program, func):
    return [i.getAddress()
            for i in program.getListing().getInstructions(func.getBody(), True)]


class Context(object):
    def __init__(self):
        self.program = currentProgram
        self.model = BasicBlockModel(self.program)
        self.looping = get_function(self.program, "sum_inner_array")
        self.leaf = get_function(self.program, "leaf")
        self.countdown = get_function(self.program, "countdown")


def setup_module():
    return Context()


def test_fixture_functions_present(t, ctx):
    t.not_none("fixture has sum_inner_array", ctx.looping)
    t.not_none("fixture has leaf", ctx.leaf)


def test_is_addr_in_loop_detects_a_loop(t, ctx):
    in_loop = [a for a in instruction_addresses(ctx.program, ctx.looping)
               if lf.is_addr_in_loop(a, program=ctx.program)]
    t.check("a function with nested loops has addresses inside loops",
            len(in_loop) > 0,
            "%d of %d instructions"
            % (len(in_loop), len(instruction_addresses(ctx.program, ctx.looping))))


def test_is_addr_in_loop_on_straight_line_code(t, ctx):
    in_loop = [a for a in instruction_addresses(ctx.program, ctx.leaf)
               if lf.is_addr_in_loop(a, program=ctx.program)]
    t.equal("a straight-line function has no addresses in loops",
            [str(a) for a in in_loop], [])


def test_block_loops_to_self(t, ctx):
    blocks = list(ctx.model.getCodeBlocksContaining(ctx.looping.getBody(), monitor))
    t.check("the looping function has code blocks", len(blocks) > 0)
    results = [lf.block_loops_to_self(b) for b in blocks]
    t.check("block_loops_to_self returns booleans",
            all(isinstance(r, bool) for r in results))


def test_get_code_block_destinations(t, ctx):
    blocks = list(ctx.model.getCodeBlocksContaining(ctx.looping.getBody(), monitor))
    total = 0
    for block in blocks:
        total += len(list(lf.getCodeBlockDestinations(block)))
    t.check("blocks in a branching function have destinations", total > 0,
            "%d destinations across %d blocks" % (total, len(blocks)))


def test_loopfinder_builds_a_cfg(t, ctx):
    finder = lf.LoopFinder(program=ctx.program)
    graph = finder.createCFGForFunc(ctx.looping)
    t.not_none("a CFG is produced", graph)
    vertices = list(graph.getVertices())
    t.check("the CFG has multiple blocks for a looping function",
            len(vertices) > 1, "%d vertices" % len(vertices))
    t.check("the CFG has edges", len(list(graph.getEdges())) > 0)


def test_loopfinder_cfg_for_address_set(t, ctx):
    finder = lf.LoopFinder(program=ctx.program)
    graph = finder.createCFGForAddressSet(ctx.leaf.getBody())
    t.check("a CFG can be built from an arbitrary address set",
            len(list(graph.getVertices())) >= 1)
