from __main__ import *
from ghidra.program.model.block import BasicBlockModel, CodeBlockIterator, SimpleBlockModel
from ghidra.program.model.block import IsolatedEntrySubModel, MultEntSubModel, OverlapCodeSubModel, PartitionCodeSubModel
from ghidra.program.model.symbol import FlowType
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
from ghidra.program.model.block.graph import CodeBlockEdge, CodeBlockVertex
from ghidra.graph import GDirectedGraph, GraphFactory, GraphAlgorithms
from ghidra.program.model.address import AddressSet
import java


def create_full_mem_addr_set():
    existing_mem_addr_set = AddressSet()
    for m_block in getMemoryBlocks():
        existing_mem_addr_set.add(m_block.getAddressRange())
    return existing_mem_addr_set


class GraphBuildHelper(object):
    """
    Based on AbstractModularizationCmd.java
    """
    def __init__(self, model, program=None, monitor_inst=None):
        if program is None:
            program = currentProgram
        if monitor_inst is None:
            monitor_inst = monitor
        self.monitor = monitor_inst
        self.bbm = model

    def createCFG(self):
        return self.createCFGForAddressSet(create_full_mem_addr_set())

    def createCFGForFunc(self, func):
        """
        returns GDirectedGraph<CodeBlockVertex, CodeBlockEdge>
        """
        return self.createCFGForAddressSet(func.body)

    def createCFGForAddressSet(self, address_set):
        """
        returns GDirectedGraph<CodeBlockVertex, CodeBlockEdge>
        """
        self.validAddresses = address_set
        # Map<CodeBlock, CodeBlockVertex> instanceMap = new HashMap<>()
        instanceMap = {}
        # GDirectedGraph<CodeBlockVertex, CodeBlockEdge> graph = GraphFactory.createDirectedGraph()
        graph = GraphFactory.createDirectedGraph()
        # CodeBlockIterator codeBlocks = getCallGraphBlocks()
        codeBlocks = self.bbm.getCodeBlocksContaining(self.validAddresses, self.monitor)
        while codeBlocks.hasNext():
            block = codeBlocks.next()

            # CodeBlockVertex fromVertex = instanceMap.get(block)
            fromVertex = instanceMap.get(block)
            if fromVertex is None:
                fromVertex = CodeBlockVertex(block)
                instanceMap[block] = fromVertex
                graph.addVertex(fromVertex)

            # destinations section
            self.addEdgesForDestinations(graph, fromVertex, block, instanceMap)
        return graph

    def addEdgesForDestinations(self, graph, fromVertex, sourceBlock, instanceMap):
        """
        GDirectedGraph<CodeBlockVertex, CodeBlockEdge> graph,
        CodeBlockVertex fromVertex,
        CodeBlock sourceBlock,
        Map<CodeBlock, CodeBlockVertex> instanceMap
        """

        # CodeBlockReferenceIterator iterator = sourceBlock.getDestinations(monitor)
        iterator = sourceBlock.getDestinations(self.monitor)
        while iterator.hasNext():
            self.monitor.checkCancelled()

            # CodeBlockReference destination = iterator.next()
            destination = iterator.next()
            # CodeBlock targetBlock = getDestinationBlock(destination)
            targetBlock = self.getDestinationBlock(destination)
            if targetBlock is None:
                continue  # # no block found

            # CodeBlockVertex targetVertex = instanceMap.get(targetBlock)
            targetVertex = instanceMap.get(targetBlock)
            if targetVertex is None:
                targetVertex = CodeBlockVertex(targetBlock)
                instanceMap[targetBlock] = targetVertex

            graph.addVertex(targetVertex)
            graph.addEdge(CodeBlockEdge(fromVertex, targetVertex))

    def getDestinationBlock(self, destination):
        """
        CodeBlockReference destination
        returns CodeBlock
        """
        targetAddress = destination.getDestinationAddress()
        # CodeBlock targetBlock = self.bbm.getFirstCodeBlockContaining(targetAddress, monitor)
        targetBlock = self.bbm.getFirstCodeBlockContaining(targetAddress, self.monitor)
        if targetBlock is None:
            return None  # # no code found for call external?

        blockAddress = targetBlock.getFirstStartAddress()
        if self.skipAddress(blockAddress):
            return None

        return targetBlock

    def skipAddress(self, address):
        """
        Address address
        returns boolean
        """
        # if (processEntireProgram):
        #   return False
        return not self.validAddresses.contains(address)



def get_vertex_for_addr(addr, g):
    for vert in g.vertices:
        if not vert.codeBlock.contains(addr):
            continue
        return vert


def print_graph(g):
    out_stream = java.io.ByteArrayOutputStream()
    GraphAlgorithms.printGraph(g, java.io.PrintStream(out_stream))
    print(out_stream.toString())


def reachable_vertices(g, vert):
    return GraphAlgorithms.getDescendants(g, [vert])


def test():
    bbm_graph = GraphBuildHelper(BasicBlockModel(currentProgram)).createCFG()
    bbm_dom = GraphAlgorithms.findDominanceTree(bbm_graph, monitor)
    mult_ent_graph = GraphBuildHelper(MultEntSubModel(currentProgram)).createCFG()
    mult_ent_dom = GraphAlgorithms.findDominanceTree(mult_ent_graph, monitor)
