#@runtime Jython
"""
Dependency-tracking cache for decompiler results.

A function's decompilation can only change when one of the following happens,
so anything else can be served from cache:

  * the function itself changes (renamed, signature/parameter/return retyped)
  * a datatype used anywhere in the function changes
  * a global it accesses is renamed or retyped
  * the instructions in its body change
  * a function it calls has its signature changed

Each cached entry records the dependency keys it was built from, and a reverse
index maps a key back to every entry that depends on it. A callee's signature
change is handled by the same mechanism the function's own change is: callers
record ("func", callee_entry) as a dependency.

Invalidation is driven by Ghidra program events. Two properties keep it honest
when events cannot be trusted:

  * Program.getModificationNumber() is a sound fast path -- if it has not moved
    since an entry was cached then nothing in the program changed at all.
  * If the program is not sending events, entries are revalidated by
    fingerprint instead. Slower than events, still far cheaper than decompiling,
    and never stale.

One cache is shared per program (see get_shared_cache). Each cache installs a
program listener, so giving every DecompUtils its own would accumulate
listeners and cached results across repeated script runs in the GUI. Sharing
also means a second script reuses what the first one already decompiled.

Known limitation: callees reached only through indirect calls (CALLIND) cannot
be resolved statically, so a signature change to such a callee will not
invalidate its callers. Call invalidate() explicitly in that case.
"""

from __main__ import *
from ghidra.framework.model import DomainObjectListener
from ghidra.framework.model import DomainObjectClosedListener
from ._compat import get_bytes
import binascii
import logging
import threading
from collections import OrderedDict

try:
    # In Jython a Java exception is not a Python Exception, so a plain
    # `except Exception` silently fails to catch anything thrown by Ghidra.
    # Under CPython/PyGhidra the import fails and Java errors arrive as
    # ordinary Python exceptions.
    from java.lang import Exception as JavaException
    CAUGHT_ERRORS = (Exception, JavaException)
except:  # noqa: E722 - must not itself use `except Exception`
    CAUGHT_ERRORS = (Exception,)

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.WARNING)

DEFAULT_MAX_ENTRIES = 512
MAX_DATATYPE_DEPTH = 16
# Cap on how much of a function body is hashed for fingerprint revalidation
MAX_BODY_DIGEST_BYTES = 65536
# Ghidra rejects a non-positive queue period. The value is irrelevant to
# correctness because the queue is flushed explicitly before every lookup;
# it only bounds how long events sit if nothing flushes them.
EVENT_QUEUE_DELAY_MS = 100

# Event names are compared as strings so this does not depend on how Jython
# surfaces Java enum constants.
FUNCTION_EVENTS = frozenset([
    "FUNCTION_CHANGED", "FUNCTION_BODY_CHANGED",
    "FUNCTION_ADDED", "FUNCTION_REMOVED",
])
SYMBOL_EVENTS = frozenset([
    "SYMBOL_RENAMED", "SYMBOL_ADDED", "SYMBOL_REMOVED",
    "SYMBOL_DATA_CHANGED", "SYMBOL_ADDRESS_CHANGED", "SYMBOL_SCOPE_CHANGED",
])
DATATYPE_EVENTS = frozenset([
    "DATA_TYPE_CHANGED", "DATA_TYPE_REPLACED", "DATA_TYPE_REMOVED",
    "DATA_TYPE_RENAMED", "DATA_TYPE_MOVED", "DATA_TYPE_SETTING_CHANGED",
])
CODE_EVENTS = frozenset([
    "CODE_ADDED", "CODE_REMOVED", "CODE_REPLACED", "MEMORY_BYTES_CHANGED",
])


def iter_java(iterator):
    """Yield from a java.util.Iterator without relying on Jython's adapters."""
    if iterator is None:
        return
    while iterator.hasNext():
        yield iterator.next()


def func_key(func):
    return ("func", str(func.getEntryPoint()))


def global_key(address):
    return ("global", str(address))


def datatype_key(datatype):
    """A stable identity for a datatype.

    Built-in types have no UniversalID, so fall back to the path name.
    """
    if datatype is None:
        return None
    uid = datatype.getUniversalID()
    if uid is not None:
        return ("dt", str(uid))
    return ("dt", datatype.getPathName())


def expand_datatypes(datatype, into, depth=0):
    """Add @datatype and every datatype it is built from to the set @into.

    A change to a nested member changes the layout of everything containing
    it, so the whole closure has to be a dependency.
    """
    if datatype is None or depth > MAX_DATATYPE_DEPTH:
        return
    key = datatype_key(datatype)
    if key is None or key in into:
        return  # also breaks self-referential structs
    into.add(key)

    # Composite (struct/union), Pointer, Array, TypeDef and FunctionDefinition
    # each expose their constituents differently; duck-type rather than import
    # and isinstance-check five classes.
    components = getattr(datatype, "getComponents", None)
    if components is not None:
        for component in components():
            expand_datatypes(component.getDataType(), into, depth + 1)
    inner = getattr(datatype, "getDataType", None)
    if inner is not None:
        expand_datatypes(inner(), into, depth + 1)
    base = getattr(datatype, "getBaseDataType", None)
    if base is not None:
        expand_datatypes(base(), into, depth + 1)
    return_type = getattr(datatype, "getReturnType", None)
    if return_type is not None:
        expand_datatypes(return_type(), into, depth + 1)
    arguments = getattr(datatype, "getArguments", None)
    if arguments is not None:
        for arg in arguments():
            expand_datatypes(arg.getDataType(), into, depth + 1)


def called_functions(high_func, program):
    """The functions called directly by @high_func.

    Indirect calls (CALLIND) cannot be resolved statically and are skipped.
    """
    from ghidra.program.model.pcode import PcodeOpAST

    entries = set()
    if high_func is None:
        return entries
    func_mgr = program.getFunctionManager()
    for op in high_func.getPcodeOps():
        if op.getOpcode() != PcodeOpAST.CALL:
            continue
        target = op.getInput(0)
        if target is None or not target.isAddress():
            continue
        callee = func_mgr.getFunctionAt(target.getAddress())
        if callee is not None:
            entries.add(callee)
    return entries


def collect_dependencies(func, high_func):
    """The set of dependency keys a decompilation of @func was built from."""
    program = func.getProgram()
    keys = set([func_key(func)])
    datatypes = set()

    signature = func.getSignature()
    if signature is not None:
        expand_datatypes(signature.getReturnType(), datatypes)
        for arg in signature.getArguments():
            expand_datatypes(arg.getDataType(), datatypes)

    for callee in called_functions(high_func, program):
        keys.add(func_key(callee))
        callee_sig = callee.getSignature()
        if callee_sig is not None:
            expand_datatypes(callee_sig.getReturnType(), datatypes)
            for arg in callee_sig.getArguments():
                expand_datatypes(arg.getDataType(), datatypes)

    if high_func is not None:
        for symbol in iter_java(high_func.getGlobalSymbolMap().getSymbols()):
            expand_datatypes(symbol.getDataType(), datatypes)
            storage = symbol.getStorage()
            if storage is not None and storage.isMemoryStorage():
                keys.add(global_key(storage.getMinAddress()))
        for symbol in iter_java(high_func.getLocalSymbolMap().getSymbols()):
            expand_datatypes(symbol.getDataType(), datatypes)

    keys.update(datatypes)
    return keys


def datatype_digest(datatype, depth=0):
    """A short structural summary of a datatype, for fingerprint revalidation.

    Changes whenever the layout, member names or member types change.
    """
    if datatype is None:
        return "None"
    if depth > MAX_DATATYPE_DEPTH:
        return "..."
    parts = [datatype.getPathName(), str(datatype.getLength())]
    components = getattr(datatype, "getComponents", None)
    if components is not None:
        for component in components():
            parts.append("%s@%d:%s" % (component.getFieldName(),
                                       component.getOffset(),
                                       datatype_digest(component.getDataType(),
                                                       depth + 1)))
    return "|".join(parts)


def buffer_checksum(buf):
    """A deterministic checksum of a byte buffer.

    Deliberately not java.util.Arrays.hashCode: Jython does not reliably bind
    a jarray to the hashCode(byte[]) overload, and the Object[] overload
    hashes wrapper identity, so it returns a different value for identical
    bytes on every call.
    """
    to_string = getattr(buf, "tostring", None)
    raw = to_string() if to_string is not None else bytes(bytearray(buf))
    return binascii.crc32(raw) & 0xffffffff


def body_digest(func):
    """A digest of the bytes making up @func's body.

    Event-driven invalidation sees instruction edits directly through
    CODE_EVENTS; fingerprint revalidation has to look at the bytes, or an
    instruction change would go unnoticed.
    """
    program = func.getProgram()
    parts = []
    total = 0
    for address_range in iter_java(func.getBody().getAddressRanges()):
        if total >= MAX_BODY_DIGEST_BYTES:
            parts.append("truncated")
            break
        length = min(int(address_range.getLength()),
                     MAX_BODY_DIGEST_BYTES - total)
        if length <= 0:
            continue
        total += length
        start = address_range.getMinAddress()
        try:
            parts.append("%s:%d:%d" % (start, length,
                                       buffer_checksum(get_bytes(program, start, length))))
        except CAUGHT_ERRORS:
            # uninitialised or unreadable memory: fall back to the extent,
            # which still changes if the body is resized
            parts.append("%s:%d:?" % (start, length))
    return "|".join(parts) if parts else "empty"


def function_fingerprint(func, dependencies):
    """A value that changes whenever anything @func decompiles from changes."""
    program = func.getProgram()
    func_mgr = program.getFunctionManager()
    symbol_table = program.getSymbolTable()
    listing = program.getListing()
    addr_factory = program.getAddressFactory()
    parts = [func.getName(), func.getSignature().getPrototypeString(),
             body_digest(func)]

    for kind, value in sorted(dependencies):
        address = addr_factory.getAddress(value) if kind in ("func", "global") else None
        if kind == "func":
            # an unparseable address means the dependency cannot be checked,
            # so treat it as changed rather than silently ignoring it
            callee = func_mgr.getFunctionAt(address) if address is not None else None
            parts.append("f:%s:%s" % (
                value,
                "unresolved" if callee is None
                else callee.getSignature().getPrototypeString()))
        elif kind == "global":
            symbol = symbol_table.getPrimarySymbol(address) if address is not None else None
            data = listing.getDataAt(address) if address is not None else None
            parts.append("g:%s:%s:%s" % (
                value,
                "none" if symbol is None else symbol.getName(),
                "none" if data is None else datatype_digest(data.getDataType())))
        else:
            parts.append("d:%s" % value)
    return "\n".join(parts)


class CacheEntry(object):
    """One cached decompilation and the dependency keys it was built from."""

    __slots__ = ("func", "results", "dependencies", "modification_number",
                 "fingerprint", "body")

    def __init__(self, func, results, dependencies, modification_number,
                 fingerprint):
        self.func = func
        self.results = results
        self.dependencies = dependencies
        self.modification_number = modification_number
        self.fingerprint = fingerprint
        self.body = func.getBody()


class ProgramChangeListener(DomainObjectListener):
    """Translates program change events into cache invalidations."""

    def __init__(self, cache):
        self._cache = cache

    def domainObjectChanged(self, event):
        try:
            self._cache.handle_event(event)
        except CAUGHT_ERRORS:
            # A listener that raises would be dropped by Ghidra, silently
            # leaving the cache stale; drop everything instead.
            log.exception("decompilation cache listener failed; clearing cache")
            self._cache.invalidate()


def event_name(event_type):
    """The enum constant name, however Jython chooses to surface it."""
    attr = getattr(event_type, "name", None)
    if attr is None:
        return str(event_type)
    if callable(attr):
        try:
            return str(attr())
        except CAUGHT_ERRORS:
            return str(event_type)
    return str(attr)


def record_address(record):
    """The address a change record applies to, or None."""
    getter = getattr(record, "getStart", None)
    if getter is not None:
        address = getter()
        if address is not None:
            return address
    obj = getattr(record, "getObject", None)
    if obj is not None:
        target = obj()
        address_of = getattr(target, "getAddress", None)
        if address_of is not None:
            return address_of()
    return None


def record_datatype(record):
    """The datatype a change record applies to, or None if undeterminable."""
    for name in ("getObject", "getNewValue", "getOldValue"):
        getter = getattr(record, name, None)
        if getter is None:
            continue
        candidate = getter()
        if candidate is not None and hasattr(candidate, "getPathName"):
            return candidate
    return None


class DecompCache(object):
    """Caches decompiler results until one of their dependencies changes.

    The decompiler itself is injected as a callable, so this class holds no
    DecompInterface and can be exercised without one.
    """

    def __init__(self, program, max_entries=DEFAULT_MAX_ENTRIES, use_events=True):
        self._program = program
        self._max_entries = max_entries
        self._entries = OrderedDict()      # entry key -> CacheEntry
        self._dependents = {}              # dependency key -> set(entry key)
        self._listener = None
        self._queue_id = None
        # events can be delivered on another thread while a script is reading
        self._lock = threading.RLock()
        self.hits = 0
        self.misses = 0
        self.invalidations = 0
        self.revalidations = 0
        if use_events:
            self._install_listener()

    # -- event plumbing ----------------------------------------------------

    def _install_listener(self):
        """Register for change events, falling back to the shared queue.

        If neither registration works the cache must not believe it is being
        told about changes -- otherwise it would serve stale results forever.
        """
        listener = ProgramChangeListener(self)
        try:
            # A private queue keeps our invalidations off the shared queue and
            # lets us drain them synchronously.
            self._queue_id = self._program.createPrivateEventQueue(
                listener, EVENT_QUEUE_DELAY_MS)
            self._listener = listener
            return
        except CAUGHT_ERRORS:
            log.debug("private event queue unavailable, using shared listener")
            self._queue_id = None
        try:
            self._program.addListener(listener)
            self._listener = listener
        except CAUGHT_ERRORS:
            log.warning("could not register a change listener for %s; "
                        "falling back to fingerprint revalidation"
                        % self._program.getName())
            self._listener = None

    def _drain_events(self):
        """Deliver pending change events before answering a lookup.

        Ghidra batches notifications, so without this a lookup issued straight
        after a retype would be answered from a stale entry.
        """
        try:
            if self._queue_id is not None:
                self._program.flushPrivateEventQueue(self._queue_id)
            elif self._listener is not None:
                self._program.flushEvents()
        except CAUGHT_ERRORS:
            log.debug("could not flush program events")

    def events_active(self):
        """Whether event-driven invalidation can be trusted right now."""
        if self._listener is None:
            return False
        try:
            return bool(self._program.isSendingEvents())
        except CAUGHT_ERRORS:
            return False

    def close(self):
        """Detach from the program. Safe to call more than once."""
        if self._listener is None:
            return
        try:
            if self._queue_id is not None:
                self._program.removePrivateEventQueue(self._queue_id)
            else:
                self._program.removeListener(self._listener)
        except CAUGHT_ERRORS:
            log.debug("could not detach cache listener")
        self._listener = None
        self._queue_id = None

    # -- cache bookkeeping -------------------------------------------------

    def _link(self, key, entry):
        for dependency in entry.dependencies:
            self._dependents.setdefault(dependency, set()).add(key)

    def _unlink(self, key, entry):
        for dependency in entry.dependencies:
            dependents = self._dependents.get(dependency)
            if dependents is None:
                continue
            dependents.discard(key)
            if not dependents:
                # otherwise the reverse index grows without bound
                del self._dependents[dependency]

    def _drop(self, key):
        entry = self._entries.pop(key, None)
        if entry is not None:
            self._unlink(key, entry)
            self.invalidations += 1

    def _touch(self, key):
        # OrderedDict.move_to_end does not exist in Jython 2.7
        self._entries[key] = self._entries.pop(key)

    def _evict_if_needed(self):
        if self._max_entries is None:
            return
        while len(self._entries) > self._max_entries:
            key, entry = self._entries.popitem(last=False)
            self._unlink(key, entry)

    # -- invalidation ------------------------------------------------------

    def invalidate(self, func=None):
        """Drop one function's entry, or the whole cache when func is None."""
        with self._lock:
            self._invalidate(func)

    def _invalidate(self, func):
        if func is None:
            self.invalidations += len(self._entries)
            self._entries.clear()
            self._dependents.clear()
            return
        self._drop(func_key(func))

    def invalidate_key(self, key):
        """Drop every entry that depends on @key."""
        with self._lock:
            self._invalidate_key(key)

    def _invalidate_key(self, key):
        for entry_key in list(self._dependents.get(key, ())):
            self._drop(entry_key)

    def invalidate_datatype_dependents(self):
        """Drop every entry with any datatype dependency.

        Used when an event does not say which datatype changed -- erring
        towards a recompute rather than a stale answer.
        """
        with self._lock:
            for key in [k for k in self._dependents if k[0] == "dt"]:
                self._invalidate_key(key)

    def invalidate_range(self, start, end):
        """Drop every entry whose body overlaps [start, end].

        Linear in cache size, which is fine because instruction edits are rare.
        """
        with self._lock:
            self._invalidate_range(start, end)

    def _invalidate_range(self, start, end):
        for key in list(self._entries):
            entry = self._entries.get(key)
            if entry is None:
                continue
            try:
                overlaps = entry.body.intersects(start, end)
            except CAUGHT_ERRORS:
                overlaps = True
            if overlaps:
                self._drop(key)

    def handle_event(self, event):
        """Apply one DomainObjectChangedEvent to the cache."""
        with self._lock:
            self._handle_event(event)

    def _handle_event(self, event):
        for index in range(event.numRecords()):
            record = event.getChangeRecord(index)
            name = event_name(record.getEventType())
            if name in FUNCTION_EVENTS or name in SYMBOL_EVENTS:
                address = record_address(record)
                if address is None:
                    self._invalidate(None)
                    return
                # one address may be both a function entry and a global
                self._invalidate_key(("func", str(address)))
                self._invalidate_key(("global", str(address)))
            elif name in DATATYPE_EVENTS:
                datatype = record_datatype(record)
                key = datatype_key(datatype) if datatype is not None else None
                if key is None:
                    for dt_key in [k for k in self._dependents if k[0] == "dt"]:
                        self._invalidate_key(dt_key)
                else:
                    self._invalidate_key(key)
            elif name in CODE_EVENTS:
                start = getattr(record, "getStart", lambda: None)()
                end = getattr(record, "getEnd", lambda: None)()
                if start is None:
                    self._invalidate(None)
                    return
                self._invalidate_range(start, end if end is not None else start)

    # -- lookup ------------------------------------------------------------

    def _is_valid(self, entry):
        modification = self._program.getModificationNumber()
        if modification == entry.modification_number:
            # nothing in the program changed at all
            return True
        if self.events_active():
            # the listener already dropped anything stale, so surviving
            # entries are current as of this modification number
            entry.modification_number = modification
            return True
        # events are off; fall back to revalidating by fingerprint
        self.revalidations += 1
        if function_fingerprint(entry.func, entry.dependencies) == entry.fingerprint:
            entry.modification_number = modification
            return True
        return False

    def get(self, func, decompile):
        """Return cached results for @func, calling @decompile on a miss.

        A failed decompilation is cached like any other result, so a function
        the decompiler cannot handle is not retried on every access. Use
        fresh=True on the DecompUtils accessor to force another attempt.
        """
        if func.getProgram() is not self._program:
            return decompile()

        self._drain_events()
        key = func_key(func)
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None:
                if self._is_valid(entry):
                    self._touch(key)
                    self.hits += 1
                    return entry.results
                self._drop(key)

        # decompiling is slow, and holding the lock across it would stall the
        # thread delivering change events
        results = decompile()
        with self._lock:
            self.misses += 1
            self._store(key, func, results)
        return results

    def _store(self, key, func, results):
        high_func = None
        if results is not None:
            try:
                high_func = results.getHighFunction()
            except CAUGHT_ERRORS:
                high_func = None
        try:
            dependencies = collect_dependencies(func, high_func)
        except CAUGHT_ERRORS:
            log.exception("could not collect dependencies for %s; not caching"
                          % func.getName())
            return
        # Computed even while events are active: it cannot be reconstructed
        # later, so an entry stored without one could never be revalidated if
        # events were turned off afterwards -- it would just be discarded.
        try:
            fingerprint = function_fingerprint(func, dependencies)
        except CAUGHT_ERRORS:
            log.exception("could not fingerprint %s; not caching" % func.getName())
            return
        entry = CacheEntry(func, results, dependencies,
                           self._program.getModificationNumber(), fingerprint)
        self._entries[key] = entry
        self._link(key, entry)
        self._evict_if_needed()

    def stats(self):
        """Counters for hits, misses, invalidations and cache size."""
        with self._lock:
            return self._stats()

    def _stats(self):
        lookups = self.hits + self.misses
        return {
            "hits": self.hits,
            "misses": self.misses,
            "invalidations": self.invalidations,
            "revalidations": self.revalidations,
            "entries": len(self._entries),
            "tracked_dependencies": len(self._dependents),
            "hit_rate": (float(self.hits) / lookups) if lookups else 0.0,
            "events_active": self.events_active(),
        }


# --- per-program shared caches ---------------------------------------------
#
# A cache installs a listener on its program, so one cache per DecompUtils
# would leave a listener (and up to max_entries of held results) behind on
# every script run. Programs are keyed by identity and evicted when closed.

_SHARED_CACHES = {}
_CLOSE_LISTENERS = {}


class ProgramClosedListener(DomainObjectClosedListener):
    """Drops a program's shared cache when the program is closed."""

    def domainObjectClosed(self, domain_object):
        try:
            close_cache(domain_object)
        except CAUGHT_ERRORS:
            log.debug("could not close shared cache for a closed program")


def get_shared_cache(program, max_entries=DEFAULT_MAX_ENTRIES, use_events=True):
    """The cache for @program, creating it on first use.

    max_entries and use_events only apply to the call that creates the cache;
    later callers get the existing one. Pass use_shared_cache=False to
    DecompUtils for an isolated cache instead.
    """
    cache = _SHARED_CACHES.get(program)
    if cache is not None:
        return cache
    cache = DecompCache(program, max_entries=max_entries, use_events=use_events)
    _SHARED_CACHES[program] = cache
    try:
        listener = ProgramClosedListener()
        program.addCloseListener(listener)
        _CLOSE_LISTENERS[program] = listener
    except CAUGHT_ERRORS:
        # without this the cache is still correct, it just outlives the program
        log.debug("could not register close listener for shared cache")
    return cache


def close_cache(program):
    """Detach and drop @program's shared cache, if it has one."""
    cache = _SHARED_CACHES.pop(program, None)
    if cache is not None:
        cache.close()
    listener = _CLOSE_LISTENERS.pop(program, None)
    if listener is not None:
        try:
            program.removeCloseListener(listener)
        except CAUGHT_ERRORS:
            log.debug("could not remove close listener")


def close_all_caches():
    """Detach and drop every shared cache. Mainly for tests and teardown."""
    for program in list(_SHARED_CACHES):
        close_cache(program)


def shared_cache_count():
    """How many programs currently have a shared cache."""
    return len(_SHARED_CACHES)


# --- global kill switch -----------------------------------------------------
#
# Useful when you suspect the cache of handing back something stale: turn it
# off, rerun, and compare. Nothing has to be re-plumbed at the call sites.

_CACHING_ENABLED = True


def set_caching_enabled(enabled):
    """Turn decompilation caching on or off process-wide.

    Turning it off tears down existing shared caches and makes every
    DecompUtils decompile fresh, whatever it was constructed with. Returns
    the previous setting so a caller can restore it.
    """
    global _CACHING_ENABLED
    previous = _CACHING_ENABLED
    _CACHING_ENABLED = bool(enabled)
    if not _CACHING_ENABLED:
        close_all_caches()
    return previous


def caching_enabled():
    """Whether decompilation caching is enabled process-wide."""
    return _CACHING_ENABLED
