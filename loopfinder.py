
from __main__ import *
from ghidra.program.model.block import BasicBlockModel, CodeBlockIterator
from ghidra.program.model.symbol import FlowType
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
from ghidra.program.model.block.graph import CodeBlockEdge, CodeBlockVertex
from ghidra.graph import GDirectedGraph, GraphFactory, GraphAlgorithms
import ghidra.graph.algo
from ghidra.program.model.address import AddressSet

def block_loops_to_self(block, monitor_inst=None):
    """
    Check if a block jumps back to it self
    """
    if monitor_inst is None:
        monitor_inst = monitor
    block_iter = block.getDestinations(monitor_inst)
    while block_iter.hasNext():
        if monitor_inst.isCancelled():
            break
        block_ref = block_iter.next()
        flow_type = block_ref.getFlowType()
        # TODO: indirection might be valid here, check
        if flow_type.isCall() is True or flow_type.isIndirect() is True:
            continue
        next_block = block_ref.getDestinationBlock()
        if next_block is None:
            continue
        if next_block == block:
            return True
    return False


def is_addr_in_loop(addr, program=None, monitor_inst=None):
    """
    Check if an address is in a basic loop within the current function.
    Untested
    """
    if program is None:
        program = currentProgram
    if monitor_inst is None:
        monitor_inst = monitor
    bbm = BasicBlockModel(program)
    start_blocks = list(bbm.getCodeBlocksContaining(addr, monitor_inst))
    # leave early if any of the first blocks just jump to themselves
    if any([block_loops_to_self(b) for b in start_blocks]) is True:
        return True

    # do a DFS to find all blocks that lead up to the starting blocks
    to_visit = set(start_blocks)
    visited = set()
    while to_visit:
        if monitor_inst.isCancelled():
            break
        block = to_visit.pop()
        block_iter = block.getSources(monitor_inst)
        while block_iter.hasNext():
            if monitor_inst.isCancelled():
                break
            block_ref = block_iter.next()
            flow_type = block_ref.getFlowType()
            # TODO: indirection might be valid here, check
            if flow_type.isCall() is True or flow_type.isIndirect() is True:
                continue
            next_block = block_ref.getSourceBlock()
            if next_block is None:
                continue
            if next_block in visited:
                continue
            if next_block in to_visit:
                continue
            if next_block == block:
                continue
            to_visit.add(next_block)
        visited.add(block)

    back_blocks = visited

    # do a second DFS to get all of the blocks forward from the starting
    # blocks. Exits early if a block that leads to the start blocks is reached
    to_visit = set(start_blocks)
    visited = set()
    while to_visit:
        if monitor_inst.isCancelled():
            break
        block = to_visit.pop()
        block_iter = block.getDestinations(monitor_inst)
        while block_iter.hasNext():
            if monitor_inst.isCancelled():
                break
            block_ref = block_iter.next()
            flow_type = block_ref.getFlowType()
            if flow_type.isCall() is True or flow_type.isIndirect() is True:
                continue
            next_block = block_ref.getDestinationBlock()
            if next_block is None:
                continue
            # extra check to exit early for found loops to reduce total
            # iterations
            if next_block in back_blocks:
                return True
            if next_block in visited:
                continue
            if next_block in to_visit:
                continue
            if next_block == block:
                continue
            to_visit.add(next_block)
        visited.add(block)
    # fwd_blocks = visited
    return False


def getCodeBlockDestinations(block, monitor_inst=None):
    """
    Get destination code blocks for a given code block
    """
    if monitor_inst is None:
        monitor_inst = monitor
    all_dest_blocks = set()
    block_iter = block.getDestinations(monitor_inst)
    while block_iter.hasNext():
        if monitor_inst.isCancelled():
            break
        block_ref = block_iter.next()
        # flow_type = block_ref.getFlowType()
        # if flow_type.isCall() is True or flow_type.isIndirect() is True:
        #     continue
        dest_block = block_ref.getDestinationBlock()
        if dest_block is None:
            continue
        all_dest_blocks.add(dest_block)
    return all_dest_blocks


class Circuit(object):
    def __init__(self, edges, cfg):
        self.edges = set(edges)
        self.vertices = set(sum([[i.getStart(), i.getEnd()] for i in self.edges], []))
        self.cfg = cfg
        self.addr_set = self._getAddressSet()
        self.exit_edges = set()
        self.exit_vertices = set()
        self._findLoopExits()

    def _getAddressSet(self):
        addr_set = AddressSet()
        for v in self.vertices:
            for rang in v.getCodeBlock().getAddressRanges():
                addr_set.add(rang)
        return addr_set

    def _findLoopExits(self):
        """
        Find Vertices that can exit the circuit
        """
        self.exit_vertices = set()
        self.exit_edges = set()
        for v in self.vertices:
            has_exit = False
            # TODO: does this handle verts returning out of the function?
            # TODO: if not, use getCodeBlockDestinations
            for e in self.cfg.getOutEdges(v):
                if e not in self.edges:
                    self.exit_edges.add(e)
                    has_exit = True
            if has_exit is True:
                self.exit_vertices.add(v)


class CircuitCollection(object):
    """
    A simple class to hold loops and success status
    """
    def __init__(self, cfg=None):
        # this is false when the circuit finding takes too long
        # private boolean complete
        # private Set<E> allCircuits = new HashSet<>()
        # private Map<V, Set<E>> circuitsByVertex = new HashMap<>()
        self.complete = False
        # a series of sets, each set representing all of the edges in a loop
        self.allCircuits = set()
        self.circuitsByVertex = {}
        self.cfg = cfg
        # a set of Circuit objects
        self.circuitObjs = set()

    def clear(self):
        self.allCircuits = set()
        self.circuitsByVertex = {}

    def addCircuitEdges(self, edges):
        self.allCircuits.add(edges)
        circ = Circuit(edges, self.cfg)
        self.circuitObjs.add(circ)




class LoopFinder(object):
    """
    Based on AbstractModularizationCmd.java
    """
    def __init__(self, program=None, monitor_inst=None):
        if program is None:
            program = currentProgram
        if monitor_inst is None:
            monitor_inst = monitor
        self.monitor = monitor_inst
        self.bbm = BasicBlockModel(program)

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


def getDominanceGraph(visualGraph, forward):
    """
    VisualGraph<V, E> visualGraph,
                boolean forward
    returns GDirectedGraph<V, E>
    """
    # Set<V> sources
    sources = GraphAlgorithms.getSources(visualGraph)
    if len(sources) != 0:
        return visualGraph

    return None


class GraphPathHelper(object):
    """
    based on VisualGraphPathHighlighter.java, but without swing
    """
    def __init__(self, graph, program=None, monitor_inst=None):
        self.graph = graph
        if program is None:
            program = currentProgram
        if monitor_inst is None:
            monitor_inst = monitor
        self.program = program
        self.monitor = monitor_inst
        # Map<V, Set<E>>
        self.forwardScopedFlowEdgeCache = {}
        self.reverseScopedFlowEdgeCache = {}
        self.forwardFlowEdgeCache = {}

    def getForwardScopedFlowEdgesForVertexAsync(self, v):
        """
        returns Set<E>
        """
        if v is None:
            return None

        # Set<E> flowEdges = self.forwardScopedFlowEdgeCache.get(v)
        flowEdges = self.forwardScopedFlowEdgeCache.get(v)
        if flowEdges is None:
            flowEdges = self.findForwardScopedFlowAsync(v)
            self.forwardScopedFlowEdgeCache[v] = flowEdges
        # return Collections.unmodifiableSet(flowEdges)
        return flowEdges

    def getForwardFlowEdgesForVertexAsync(self, v):
        """
        returns Set<E>
        """
        return self.getFlowEdgesForVertexAsync(True, self.forwardFlowEdgeCache, v)

    def getReverseFlowEdgesForVertexAsync(self, v):
        """
        returns Set<E>
        """
        return self.getFlowEdgesForVertexAsync(False, self.reverseFlowEdgeCache, v)

    def getFlowEdgesForVertexAsync(self, isForward, cache, v):
        """
        boolean isForward, Map<V, Set<E>> cache, V v
        returns Set<E>
        """

        if v is None:
            return None

        # Set<E> flowEdges = cache.get(v)
        flowEdges = cache.get(v)
        if flowEdges is None:
            flowEdges = set()
            # Set<E> pathsToVertex
            pathsToVertex = GraphAlgorithms.getEdgesFrom(self.graph, v, isForward)
            # flowEdges.addAll(pathsToVertex)
            flowEdges = flowEdges.union(pathsToVertex)
            cache[v] = flowEdges
        # return Collections.unmodifiableSet(flowEdges)
        return flowEdges

    def getAllCircuitFlowEdgesAsync(self):
        """
        returns Set<E>
        """
        # # CompletableFuture<Circuits> future = lazyCreateCircuitFuture()
        # future = self.lazyCreateCircuitFuture()
        # # Circuits circuits = getAsync(future) # blocking operation
        # circuits = getAsync(future) # blocking operation
        circuits = self.calculateCircuitsAsync()
        if circuits is None:
            return set()  # can happen during dispose
        # return Collections.unmodifiableSet(circuits.allCircuits)
        return set(circuits.allCircuits)

    def getReverseScopedFlowEdgesForVertexAsync(self, v):
        """
        returns Set<E>
        """
        if v is None:
            return None

        # Set<E> flowEdges = self.reverseScopedFlowEdgeCache.get(v)
        flowEdges = self.reverseScopedFlowEdgeCache.get(v)
        if flowEdges is None:
            flowEdges = self.findReverseScopedFlowAsync(v)
            self.reverseScopedFlowEdgeCache[v] = flowEdges
        # return Collections.unmodifiableSet(flowEdges)
        return set(flowEdges)

    def getCircuitEdgesAsync(self, v):
        """
        returns Set<E>
        """

        if v is None:
            return None
        # # CompletableFuture<Circuits> future
        # future = self.lazyCreateCircuitFuture()
        # # Circuits circuits = getAsync(future) # blocking operation
        # circuits = getAsync(future) # blocking operation

        circuits = self.calculateCircuitsAsync()
        if circuits is None:
            return set()  # can happen during dispose
        # Set<E>
        circ_set = circuits.circuitsByVertex.get(v)
        if circ_set is None:
            return set()
        return set(circ_set)

    def calculateCircuitsAsync(self):
        """
        TaskMonitor monitor
        returns Circuits
        """

        # Circuits result = new Circuits()
        result = CircuitCollection(self.graph)

        self.monitor.setMessage("Finding all loops")
        # Set<Set<V>> strongs
        strongs = GraphAlgorithms.getStronglyConnectedComponents(self.graph)
        # Set<V> vertices
        for vertices in strongs:
            if self.monitor.isCancelled():
                return result

            # removed to allow self-looping blocks
            # if len(vertices) == 1:
            #     continue
            # GDirectedGraph<V, E> subGraph
            subGraph = GraphAlgorithms.createSubGraph(self.graph, vertices)
            # Collection<E> edges
            edges = subGraph.getEdges()
            if edges:
                result.addCircuitEdges(edges)
            # HashSet<E> asSet
            asSet = set(edges)
            # Collection<V> subVertices
            subVertices = subGraph.getVertices()
            # V v
            for v in subVertices:
                if self.monitor.isCancelled():
                    return result
                result.circuitsByVertex[v] = asSet

        result.complete = True
        return result

    def pathToEdgesAsync(self, path):
        """
        List<V> path
        returns List<E>
        """
        results = []
        # Iterator<V> it
        it = iter(path)
        from_v = it.next()
        while it.hasNext():
            to = it.next()
            e = self.graph.findEdge(from_v, to)
            results.append(e)
            from_v = to
        return results

    '''
    def findForwardScopedFlowAsync(self, v):
        """
        V v
        returns Set<E>
        """

        # CompletableFuture<ChkDominanceAlgorithm<V, E>> future = lazyCreateDominaceFuture()
        future = self.lazyCreateDominaceFuture()

        # GDirectedGraph<V, E> dominanceGraph = getDominanceGraph(self.graph, True)
        dominanceGraph = getDominanceGraph(self.graph, True)

        try:
            # ChkDominanceAlgorithm<V, E> dominanceAlgorithm = getAsync(future)
            dominanceAlgorithm = getAsync(future)

            if dominanceAlgorithm is not None: # null implies timeout
                # Set<V> dominated
                dominated = dominanceAlgorithm.getDominated(v)
                return GraphAlgorithms.retainEdges(self.graph, dominated)

        except:
            pass
            # handled below

        # use the empty set so we do not repeatedly attempt to calculate these paths
        return set()
    '''

    '''
    def findReverseScopedFlowAsync(self, v):
        """
        V v
        returns Set<E>
        """
        # CompletableFuture<ChkDominanceAlgorithm<V, E>> future = lazyCreatePostDominanceFuture()
        future = self.lazyCreatePostDominanceFuture()

        try:
            # ChkDominanceAlgorithm<V, E> postDominanceAlgorithm = getAsync(future)
            postDominanceAlgorithm = getAsync(future)

            if postDominanceAlgorithm is not None: # null implies timeout
                # Set<V> dominated
                dominated = postDominanceAlgorithm.getDominated(v)
                return GraphAlgorithms.retainEdges(self.graph, dominated)
        except:
            pass
            # handled below

        # use the empty set so we do not repeatedly attempt to calculate these paths
        return set()
    '''

    '''
    def calculatePathsBetweenVerticesAsync(self, V v1, V v2) {
        """
        V v1, V v2
        """
        if v1.equals(v2):
            return

        # CallbackAccumulator<List<V>> accumulator = new CallbackAccumulator<>(path -> {
        accumulator = new CallbackAccumulator<>(path -> {

            Collection<E> edges = pathToEdgesAsync(path)
            SystemUtilities.runSwingLater(() -> setInHoverPathOnSwing(edges))
        })

        TaskMonitor timeoutMonitor = TimeoutTaskMonitor.timeoutIn(ALGORITHM_TIMEOUT,
            TimeUnit.SECONDS, new TaskMonitorAdapter(true))

        try {
            GraphAlgorithms.findPaths(self.graph, v1, v2, accumulator, timeoutMonitor)
        }
        catch (ConcurrentModificationException e) {
            # TODO temp fix for 8.0.
            # This exception can happen when the current graph is being mutated off of the
            # Swing thread, such as when grouping and ungrouping.  For now, squash the
            # problem, as it is only a UI feature.   Post-"big graph branch merge", update
            # how we schedule this task in relation to background graph jobs (maybe just make
            # this task a job)
        }
        catch (CancelledException e) {
            SystemUtilities.runSwingLater(
                () -> setStatusTextSwing("Path computation halted by user or timeout.\n" +
                    "Paths shown in graph are not complete!"))
        }

    }
    '''

    '''
    def lazyCreateDominaceFuture(self):
        """
        returns CompletableFuture<ChkDominanceAlgorithm<V, E>>
        """

        # lazy-load
        if dominanceFuture is not None:
            return dominanceFuture

        # we use an executor to restrict thread usage by the Graph API
        # Executor executor = getGraphExecutor()
        executor = getGraphExecutor()
        dominanceFuture = CompletableFuture.supplyAsync(() -> {

            # this operation is fast enough that it shouldn't timeout, but just in case...
            TaskMonitor timeoutMonitor = TimeoutTaskMonitor.timeoutIn(ALGORITHM_TIMEOUT,
                TimeUnit.SECONDS, new TaskMonitorAdapter(true))

            GDirectedGraph<V, E> dominanceGraph = getDominanceGraph(self.graph, true)
            if (dominanceGraph is None:
                Msg.debug(this, "No sources found for graph cannot calculate dominance: " +
                    self.graph.getClass().getSimpleName())
                return null
            }

            try {
                # note: calling the constructor performs the work
                # return new ChkDominanceAlgorithm<>(dominanceGraph, timeoutMonitor)
                return ghidra.graph.algo.ChkDominanceAlgorithm(dominanceGraph, timeoutMonitor)
            }
            catch (CancelledException e) {
                # shouldn't happen
                Msg.debug(VisualGraphPathHighlighter.this,
                    "Domiance calculation timed-out for " + self.graph.getClass().getSimpleName())
            }
            return null
        }, executor)
        return dominanceFuture
    }
    '''


    '''
    private CompletableFuture<ChkDominanceAlgorithm<V, E>> lazyCreatePostDominanceFuture() {

        # lazy-load
        if (postDominanceFuture is not None:
            return postDominanceFuture
        }

        Executor executor = getGraphExecutor()
        postDominanceFuture = CompletableFuture.supplyAsync(() -> {

            # this operation is fast enough that it shouldn't timeout, but just in case...
            TaskMonitor timeoutMonitor = TimeoutTaskMonitor.timeoutIn(ALGORITHM_TIMEOUT,
                TimeUnit.SECONDS, new TaskMonitorAdapter(true))

            try {
                # note: calling the constructor performs the work
                return new ChkPostDominanceAlgorithm<>(self.graph, timeoutMonitor)
            }
            catch (CancelledException e) {
                # shouldn't happen
                Msg.debug(VisualGraphPathHighlighter.this,
                    "Post-domiance calculation timed-out for " + self.graph.getClass().getSimpleName())
            }
            return null
        }, executor)
        return postDominanceFuture
    }
    '''
