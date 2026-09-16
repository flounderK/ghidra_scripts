"""
Wrapper around Ghidra's built-in memory search service
(``ghidra.features.base.memsearch``), which is what the Search -> Memory
dialog drives.

Using the built-in service rather than pulling blocks out with getBytes() and
running Python regexes over them buys three things: chunked reads that do not
materialise a whole memory block at once, correct handling of gaps and
non-contiguous address sets, and the same alignment/code-unit filters the GUI
offers.

Two matchers are exposed:

  * :func:`ByteSearcher.find_bytes` -- an exact byte sequence with an optional
    per-byte mask, via ``MaskedByteSequenceByteMatcher``.
  * :func:`ByteSearcher.find_regex` -- a Java regular expression over bytes,
    via ``RegExByteMatcher``. Each byte is presented to the regex engine as the
    character ``byte & 0xff``, so a literal byte is written ``\\xHH`` and the
    full character-class syntax works on byte values.

:func:`ByteSearcher.find_any` searches for many exact byte sequences at once.
Each pass over memory re-reads it through the Program, so running one pass per
pattern is the expensive part of a large scan, not the matching. find_any
therefore folds batches of patterns into a single regex alternation (grouped by
first byte, so a non-matching alternative dies on its first comparison) and
attributes each hit back to the pattern that produced it.

Every pattern is capped at MAX_PATTERN_BYTES. That is not arbitrary: the
searcher walks memory in chunks and only lets a match run OVERLAP_SIZE (100)
bytes past the end of a chunk, so a longer pattern is silently missed whenever
it straddles a chunk boundary. Callers with a longer sequence should search a
prefix and confirm the rest by reading memory at the hit.
"""

from ghidra.features.base.memsearch.bytesource import ProgramByteSource
from ghidra.features.base.memsearch.bytesource import ProgramSearchRegion
from ghidra.features.base.memsearch.gui import SearchSettings
from ghidra.features.base.memsearch.matcher import MaskedByteSequenceByteMatcher
from ghidra.features.base.memsearch.matcher import RegExByteMatcher
from ghidra.features.base.memsearch.searcher import AlignmentFilter
from ghidra.features.base.memsearch.searcher import CodeUnitFilter
from ghidra.features.base.memsearch.searcher import MemorySearcher
from ghidra.program.model.address import AddressSet
from ghidra.util.datastruct import ListAccumulator

from ._compat import (CAUGHT_ERRORS, from_java_byte_array, resolve_monitor,
                      resolve_program, to_java_byte_array)

import logging
from collections import OrderedDict

log = logging.getLogger(__file__)
if not log.handlers:
    log.addHandler(logging.StreamHandler())
log.setLevel(logging.WARNING)

# MemorySearcher.OVERLAP_SIZE. A match must start inside the current chunk and
# may only extend this far into the next one.
MAX_PATTERN_BYTES = 100
DEFAULT_MATCH_LIMIT = 100000
# How many patterns to fold into one regex alternation. Larger batches mean
# fewer passes over memory but more alternatives tried at each byte offset.
DEFAULT_BATCH_SIZE = 64


def as_bytes(data):
    """Normalise bytes/bytearray/str to an immutable, hashable byte string."""
    return bytes(bytearray(data))


def escape_bytes(data):
    """Render a byte string as a Java regex matching it literally.

    Every byte becomes a ``\\xHH`` escape rather than being emitted raw, so
    bytes that are regex metacharacters cannot change what the pattern means.
    """
    return "".join("\\x%02x" % b for b in bytearray(data))


class SearchMatch(object):
    """One hit: where it was, the bytes there, and what matched."""

    __slots__ = ("address", "data", "pattern")

    def __init__(self, address, data, pattern=None):
        self.address = address
        self.data = data
        self.pattern = pattern

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        return "<SearchMatch %s %d bytes>" % (self.address, len(self.data))


class ByteSearcher(object):
    """Searches a program's memory using Ghidra's memory search service.

    @program: program to search. Defaults to currentProgram.
    @monitor: TaskMonitor used for progress and cancellation.
    @search_set: AddressSetView to restrict the search to. Defaults to every
                 loaded, initialised block -- the same default the GUI uses.
    @match_limit: stop after this many hits in a single pass.
    @alignment: only report matches whose address is a multiple of this.
    @chunk_size: bytes read per chunk; None uses the searcher's own default.
    """

    def __init__(self, program=None, monitor=None, search_set=None,
                 match_limit=DEFAULT_MATCH_LIMIT, alignment=1,
                 chunk_size=None):
        self.program = resolve_program(program)
        self.monitor = resolve_monitor(monitor)
        self.byte_source = ProgramByteSource(self.program)
        self.search_set = (search_set if search_set is not None
                           else default_search_set(self.program))
        self.match_limit = match_limit
        self.alignment = alignment
        self.chunk_size = chunk_size
        self._code_unit_filter = None

    def restrict_to_code_units(self, instructions=True, defined_data=True,
                               undefined_data=True):
        """Only report matches landing on the selected kinds of code unit.

        Constant tables normally live in undefined or defined data, so turning
        instructions off is a cheap way to drop hits inside code.
        """
        self._code_unit_filter = CodeUnitFilter(
            self.program, instructions, defined_data, undefined_data)
        return self

    def find_bytes(self, data, mask=None, limit=None):
        """Find every occurrence of an exact (optionally masked) byte sequence.

        @mask: per-byte mask applied to memory before comparing, same length as
               @data. A 0x00 mask byte matches any byte in that position.
        """
        data = as_bytes(data)
        _check_pattern_length(data)
        if mask is not None and len(mask) != len(data):
            raise ValueError("mask is %d bytes but pattern is %d"
                             % (len(mask), len(data)))
        matcher = MaskedByteSequenceByteMatcher(
            escape_bytes(data), to_java_byte_array(data),
            to_java_byte_array(mask) if mask is not None else None,
            SearchSettings())
        return self._run(matcher, limit)

    def find_regex(self, pattern, limit=None):
        """Find every match of a Java regex over bytes.

        Bytes reach the regex engine as ``byte & 0xff`` characters, so write a
        literal byte as ``\\xHH``. DOTALL is applied by Ghidra, so ``.`` also
        matches line-terminator bytes.
        """
        return self._run(RegExByteMatcher(pattern, SearchSettings()), limit)

    def find_any(self, patterns, batch_size=DEFAULT_BATCH_SIZE, limit=None):
        """Find every occurrence of any of @patterns in as few passes as possible.

        Returns SearchMatch objects whose ``pattern`` is the byte string that
        matched. Duplicate patterns are collapsed; where one pattern is a prefix
        of another the longer one is preferred, so callers that care about the
        shorter one should confirm it against the returned bytes.
        """
        unique = []
        seen = set()
        for pattern in patterns:
            pattern = as_bytes(pattern)
            if not pattern:
                raise ValueError("cannot search for an empty pattern")
            _check_pattern_length(pattern)
            if pattern in seen:
                continue
            seen.add(pattern)
            unique.append(pattern)

        matches = []
        for start in range(0, len(unique), batch_size):
            batch = unique[start:start + batch_size]
            if self.monitor.isCancelled():
                break
            for match in self.find_regex(_alternation(batch), limit=limit):
                match.pattern = match.data if match.data in seen else None
                matches.append(match)
        return matches

    def _run(self, matcher, limit):
        limit = self.match_limit if limit is None else limit
        if self.chunk_size is None:
            searcher = MemorySearcher(self.byte_source, matcher,
                                      self.search_set, limit)
        else:
            searcher = MemorySearcher(self.byte_source, matcher,
                                      self.search_set, limit, self.chunk_size)
        # MemorySearcher holds a single filter. Composing two Java Predicates
        # would mean calling Predicate.and(), whose name is a Python keyword
        # and is spelled differently under Jython and JPype, so at most one
        # filter goes to Java and alignment is applied here instead.
        align_in_python = False
        if self._code_unit_filter is not None:
            searcher.setMatchFilter(self._code_unit_filter)
            align_in_python = self.alignment > 1
        elif self.alignment > 1:
            searcher.setMatchFilter(AlignmentFilter(self.alignment))

        accumulator = ListAccumulator()
        completed = searcher.findAll(accumulator, self.monitor)
        if not completed and not self.monitor.isCancelled():
            log.warning("search stopped early -- match limit of %d reached",
                        limit)
        matches = [SearchMatch(m.getAddress(),
                               as_bytes(from_java_byte_array(m.getBytes())))
                   for m in accumulator]
        if align_in_python:
            # Note this trims after the match limit has been applied, so a run
            # of unaligned hits can crowd out aligned ones at the limit.
            matches = [m for m in matches
                       if m.address.getOffset() % self.alignment == 0]
        return matches


def default_search_set(program=None):
    """The address set Ghidra's memory search dialog searches by default.

    That is every loaded and initialised block; uninitialised blocks have no
    bytes to match and blocks such as Microsoft's ``tdb`` are mapped far
    outside the image.

    The regions are asked which of them are default rather than going through
    SearchSettings, whose own default is an empty region set that the GUI fills
    in from the byte source before searching -- calling getSearchAddresses() on
    a fresh SearchSettings returns nothing at all.
    """
    program = resolve_program(program)
    addresses = AddressSet()
    for region in ProgramSearchRegion.ALL:
        if region.isDefault():
            addresses.add(region.getAddresses(program))
    return addresses


def all_initialized_search_set(program=None):
    """Every initialised block, loaded or not."""
    program = resolve_program(program)
    return program.getMemory().getAllInitializedAddressSet()


def read_memory(address, length, program=None):
    """Read @length bytes at @address, returning fewer than asked at a block end.

    Returns a bytearray. Used to confirm a long sequence after searching for a
    prefix of it, where the tail may run off the end of a block.
    """
    program = resolve_program(program)
    memory = program.getMemory()
    buf = to_java_byte_array(bytearray(length))
    try:
        count = memory.getBytes(address, buf, 0, length)
    except CAUGHT_ERRORS:
        return bytearray()
    if count <= 0:
        return bytearray()
    return from_java_byte_array(buf)[:count]


def _check_pattern_length(data):
    if len(data) > MAX_PATTERN_BYTES:
        raise ValueError(
            "pattern is %d bytes; anything over %d can be missed where it "
            "crosses a search chunk boundary. Search a prefix and confirm the "
            "rest with read_memory()." % (len(data), MAX_PATTERN_BYTES))


def _alternation(patterns):
    """Fold exact byte patterns into one regex alternation.

    Patterns are grouped by their first byte so that a non-matching group is
    rejected on a single comparison, and longest-first within a group so that a
    pattern is never shadowed by a shorter pattern it extends.
    """
    groups = OrderedDict()
    for pattern in patterns:
        groups.setdefault(bytearray(pattern)[0], []).append(pattern)

    branches = []
    for first, group in groups.items():
        group = sorted(group, key=len, reverse=True)
        tails = [escape_bytes(bytearray(p)[1:]) for p in group]
        if len(tails) == 1:
            branches.append("\\x%02x%s" % (first, tails[0]))
        else:
            branches.append("\\x%02x(?:%s)" % (first, "|".join(tails)))
    return "(?:%s)" % "|".join(branches)


def createByteSearcher(program=None, **kwargs):
    return ByteSearcher(program=program, **kwargs)
