"""
Searching a program for the constants defined in crypto_const_utils.

Searching is two-stage. Ghidra's memory searcher only lets a match run 100
bytes past the end of a search chunk, so a 1KB CRC table cannot be searched for
directly. Each layout is therefore searched by a bounded prefix, and the full
sequence is confirmed by reading memory at the hit. That also yields how much
of the table is actually present, which distinguishes a real table from a
coincidental prefix and catches implementations embedding only part of one.

The three modules underneath this one each do one thing: crypto_const_utils
says what the constants are, const_encoding_utils says what they can look like
in memory, and byte_search_utils finds bytes.
"""

from ._compat import resolve_monitor, resolve_program
from .byte_search_utils import (ByteSearcher, MAX_PATTERN_BYTES, as_bytes,
                                read_memory)
from .const_encoding_utils import distinct_byte_count
from .crypto_const_utils import CATEGORIES, get_signatures

import logging

log = logging.getLogger(__file__)
if not log.handlers:
    log.addHandler(logging.StreamHandler())
log.setLevel(logging.WARNING)

# A probe has to stay under the searcher's chunk-overlap limit, and be long
# enough not to be a coincidence.
DEFAULT_PROBE_BYTES = 96
MIN_PROBE_BYTES = 8
MIN_PROBE_DISTINCT_BYTES = 4


class ConstMatch(object):
    """A constant found in memory, and how much of it is really there."""

    __slots__ = ("address", "signature", "encoding", "words_matched",
                 "byte_length")

    def __init__(self, address, signature, encoding, words_matched,
                 byte_length):
        self.address = address
        self.signature = signature
        self.encoding = encoding
        self.words_matched = words_matched
        self.byte_length = byte_length

    @property
    def name(self):
        return self.signature.name

    @property
    def category(self):
        return self.signature.category

    @property
    def word_count(self):
        return self.signature.word_count

    @property
    def is_complete(self):
        return self.words_matched >= self.word_count

    @property
    def layout(self):
        return self.encoding.label(self.signature.word_bits)

    def __repr__(self):
        return "<ConstMatch %s %s %s %d/%d>" % (
            self.address, self.name, self.layout, self.words_matched,
            self.word_count)

    def __str__(self):
        extent = ("%d words" % self.word_count if self.is_complete
                  else "%d of %d words" % (self.words_matched,
                                           self.word_count))
        return "%s  %-38s %-16s %s" % (self.address, self.name, self.layout,
                                       extent)


class CryptoConstScanner(object):
    """Scans a program's memory for the constants in :func:`get_signatures`.

    Each signature is expanded into every layout it could have in memory, a
    bounded prefix of each layout is searched for in as few passes as the
    searcher allows, and every hit is confirmed against the full sequence by
    reading memory. A hit that confirms only part of the sequence is still
    reported, with the extent, because an implementation may embed only the
    first rows of a table.

    @signatures: what to look for. Defaults to everything non-scalar.
    @probe_bytes: how much of each layout to search for.
    @min_words_matched: drop matches confirming fewer than this many words.
                        None keeps everything the probe found.
    """

    def __init__(self, program=None, monitor=None, signatures=None,
                 searcher=None, probe_bytes=DEFAULT_PROBE_BYTES,
                 min_probe_bytes=MIN_PROBE_BYTES, min_words_matched=None,
                 **searcher_kwargs):
        self.program = resolve_program(program)
        self.monitor = resolve_monitor(monitor)
        self.signatures = (list(signatures) if signatures is not None
                           else get_signatures())
        self.probe_bytes = min(probe_bytes, MAX_PATTERN_BYTES)
        self.min_probe_bytes = min_probe_bytes
        self.min_words_matched = min_words_matched
        self.searcher = searcher or ByteSearcher(
            program=self.program, monitor=self.monitor, **searcher_kwargs)
        self.matches = []
        self.skipped = []

    def build_probes(self):
        """Map each probe byte string to the candidates that could produce it.

        One probe can belong to several candidates: AES's Te tables all begin
        with the S-box value, and a constant's layouts can coincide. Verifying
        against memory is what separates them.
        """
        probes = {}
        self.skipped = []
        for signature in self.signatures:
            for encoding, data in signature.layouts():
                probe = as_bytes(data[:self.probe_bytes])
                if not self._probe_is_usable(probe):
                    self.skipped.append((signature, encoding, len(probe)))
                    continue
                probes.setdefault(probe, []).append(
                    (signature, encoding, as_bytes(data)))
        return probes

    def scan(self):
        """Search for every signature and return the confirmed matches."""
        probes = self.build_probes()
        log.info("searching for %d probes from %d signatures",
                 len(probes), len(self.signatures))

        found = self.searcher.find_any(list(probes.keys()))
        probe_lengths = sorted(set(len(p) for p in probes))

        # Keyed by (address, signature name) so that a constant matching under
        # several layouts is reported once, under whichever confirmed most.
        best = {}
        for hit in found:
            if self.monitor.isCancelled():
                break
            for length in probe_lengths:
                if length > len(hit.data):
                    continue
                # A probe that is a prefix of a longer one is shadowed inside
                # the regex alternation, so every prefix is re-checked here.
                for candidate in probes.get(hit.data[:length], ()):
                    self._record(best, hit.address, candidate)

        matches = _drop_contrived_layouts(best.values())
        matches.sort(key=lambda m: (m.category, m.name,
                                    m.address.getOffset()))
        if self.min_words_matched is not None:
            matches = [m for m in matches
                       if m.words_matched >= self.min_words_matched]
        self.matches = matches
        return matches

    def _record(self, best, address, candidate):
        signature, encoding, full = candidate
        words_matched, byte_length = self._verify(address, signature, full)
        if words_matched <= 0:
            return
        key = (address.getOffset(), signature.name)
        previous = best.get(key)
        if previous is None or words_matched > previous.words_matched:
            best[key] = ConstMatch(address, signature, encoding, words_matched,
                                   byte_length)

    def _verify(self, address, signature, full):
        """How much of @full is actually at @address.

        Returns (words confirmed, bytes confirmed). The sequence is compared
        element by element rather than byte by byte so that a table truncated
        part way through a word is not credited with that word.
        """
        actual = read_memory(address, len(full), program=self.program)
        bytes_per_word = len(full) // signature.word_count
        matched = 0
        limit = min(len(actual), len(full))
        while (matched + bytes_per_word) <= limit:
            start = matched
            end = matched + bytes_per_word
            if actual[start:end] != bytearray(full[start:end]):
                break
            matched = end
        return matched // bytes_per_word, matched

    def _probe_is_usable(self, probe):
        """Whether a probe is specific enough to be worth searching for.

        A short probe needs real variety to mean anything. A long one earns its
        keep from its length even when most of it is one repeated value, which
        is what a bignum's high limbs and a widened byte table both look like.
        """
        if len(probe) < self.min_probe_bytes:
            return False
        distinct = distinct_byte_count(probe)
        if distinct < 2:
            return False
        return distinct >= MIN_PROBE_DISTINCT_BYTES or len(probe) >= 24

    def matches_by_category(self):
        grouped = {}
        for match in self.matches:
            grouped.setdefault(match.category, []).append(match)
        return grouped

    def print_matches(self):
        if not self.matches:
            print("[*] No cryptographic or algorithmic constants found")
            return
        grouped = self.matches_by_category()
        complete = len([m for m in self.matches if m.is_complete])
        print("[+] Found %d constant(s), %d of them complete\n"
              % (len(self.matches), complete))
        for category in CATEGORIES:
            if category not in grouped:
                continue
            print("--- %s ---" % category)
            for match in grouped[category]:
                print("  %s" % match)
            print("")


def _layout_oddity(match):
    """How contrived a layout is, as a sort key. Lower is more ordinary."""
    encoding = match.encoding
    word_bits = match.signature.word_bits
    score = 0
    if encoding.element_bits != word_bits:
        score += 1
    if (encoding.element_bits < word_bits and
            encoding.big_endian != encoding.high_chunk_first):
        # Elements stored in the opposite order to their own byte order.
        score += 2
    if encoding.reversed_order:
        score += 1
    return score


def _drop_contrived_layouts(matches):
    """Collapse matches that are re-readings of the same bytes.

    AES's four T-tables are byte rotations of each other, so Te2 read normally
    and Te0 read with its 16-bit halves swapped are the same 1024 bytes. Both
    are true, but only one is what the code actually has. Where matches cover
    exactly the same bytes, the most ordinary layout wins.
    """
    groups = {}
    for match in matches:
        groups.setdefault((match.address.getOffset(), match.byte_length),
                          []).append(match)
    kept = []
    for group in groups.values():
        best_score = min(_layout_oddity(m) for m in group)
        kept.extend(m for m in group if _layout_oddity(m) == best_score)
    return kept


def createCryptoConstScanner(program=None, **kwargs):
    return CryptoConstScanner(program=program, **kwargs)


def scan_for_crypto_constants(program=None, **kwargs):
    """Convenience entry point: scan, print, and return the scanner."""
    scanner = CryptoConstScanner(program=program, **kwargs)
    scanner.scan()
    scanner.print_matches()
    return scanner
