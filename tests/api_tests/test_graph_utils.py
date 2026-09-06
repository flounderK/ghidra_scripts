#@runtime Jython
"""Tests for ghidra_api.graph_utils."""

from __main__ import *
from ghidra.program.model.block import BasicBlockModel

from ghidra_api import graph_utils as gu
from ghidra_test_support import get_function


class Context(object):
    def __init__(self):
        self.program = currentProgram
        self.model = BasicBlockModel(self.program)
        self.helper = gu.GraphBuildHelper(self.model, program=self.program)
        self.looping = get_function(self.program, "sum_inner_array")
        self.leaf = get_function(self.program, "leaf")


def setup_module():
    return Context()


def test_create_full_mem_addr_set(t, ctx):
    addr_set = gu.create_full_mem_addr_set()
    t.check("the address set is not empty", not addr_set.isEmpty())
    for block in ctx.program.getMemory().getBlocks():
        t.check("memory block %s is covered" % block.getName(),
                addr_set.contains(block.getStart()))
        break


def test_cfg_for_function_has_vertices(t, ctx):
    graph = ctx.helper.createCFGForFunc(ctx.looping)
    t.not_none("a graph is produced", graph)
    vertices = list(graph.getVertices())
    t.check("the graph has vertices", len(vertices) > 0, "%d vertices" % len(vertices))
    t.check("a function with loops has more than one block",
            len(vertices) > 1, "%d vertices" % len(vertices))
    t.check("the graph has edges", len(list(graph.getEdges())) > 0)


def test_cfg_for_straight_line_function(t, ctx):
    graph = ctx.helper.createCFGForFunc(ctx.leaf)
    t.check("a straight-line function still yields a graph",
            len(list(graph.getVertices())) >= 1)


def test_get_vertex_for_addr(t, ctx):
    graph = ctx.helper.createCFGForFunc(ctx.looping)
    entry = ctx.looping.getEntryPoint()
    vertex = gu.get_vertex_for_addr(entry, graph)
    t.not_none("a vertex is found for the entry point", vertex)
    if vertex is not None:
        t.check("the vertex's block contains the address",
                vertex.getCodeBlock().contains(entry))


def test_get_vertex_for_addr_outside_graph(t, ctx):
    graph = ctx.helper.createCFGForFunc(ctx.leaf)
    outside = ctx.looping.getEntryPoint()
    t.equal("an address outside the graph yields None",
            gu.get_vertex_for_addr(outside, graph), None)


def test_reachable_vertices(t, ctx):
    graph = ctx.helper.createCFGForFunc(ctx.looping)
    entry_vertex = gu.get_vertex_for_addr(ctx.looping.getEntryPoint(), graph)
    if entry_vertex is None:
        t.check("entry vertex located", False)
        return
    reachable = gu.reachable_vertices(graph, entry_vertex)
    t.check("other blocks are reachable from the entry block",
            len(list(reachable)) > 1, "%d reachable" % len(list(reachable)))


def test_print_graph_does_not_raise(t, ctx):
    gu.print_graph(ctx.helper.createCFGForFunc(ctx.leaf))
    t.check("printing a graph completes", True)
