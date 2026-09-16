"""Tests for ghidra_api.byte_search_utils, against the crypto fixture tables."""

from ghidra_api._compat import resolve_program

from ghidra_api import byte_search_utils as bs
from ghidra_test_support import global_address


class Context(object):
    def __init__(self):
        self.program = resolve_program(None)
        self.searcher = bs.ByteSearcher(program=self.program)
        self.sigma_address = global_address(self.program, "fx_chacha_sigma")
        self.sigma = b"expand 32-byte k"
        self.base64_address = global_address(self.program,
                                             "fx_base64_alphabet")


def setup_module():
    return Context()


def test_as_bytes_normalises(t, ctx):
    t.equal("a bytearray becomes an immutable byte string",
            bs.as_bytes(bytearray([1, 2, 3])), bs.as_bytes(b"\x01\x02\x03"))
    t.check("the result is hashable, so it can key a dict",
            bs.as_bytes(bytearray([1])) in {bs.as_bytes(b"\x01"): True})


def test_escape_bytes(t, ctx):
    t.equal("every byte becomes a hex escape",
            bs.escape_bytes(bytearray([0x00, 0x5c, 0xff])),
            "\\x00\\x5c\\xff")


def test_escape_bytes_neutralises_metacharacters(t, ctx):
    """0x5c is a backslash and 0x2e is '.'; spliced in raw they would change
    what the pattern means."""
    pattern = bs.escape_bytes(bytearray([0x2e, 0x5c, 0x2a]))
    t.equal("a literal dot, backslash and star", pattern, "\\x2e\\x5c\\x2a")


def test_default_search_set_is_loaded_memory(t, ctx):
    search_set = bs.default_search_set(ctx.program)
    t.not_none("there is a default search set", search_set)
    t.check("it is not empty", search_set.getNumAddresses() > 0)
    t.check("it contains the fixture data",
            search_set.contains(ctx.sigma_address))


def test_find_bytes_locates_a_known_constant(t, ctx):
    matches = ctx.searcher.find_bytes(ctx.sigma)
    addresses = [m.address for m in matches]
    t.contains("the ChaCha sigma string is found where the symbol says",
               addresses, ctx.sigma_address)
    t.check("every match is the length asked for",
            all(len(m) == len(ctx.sigma) for m in matches))


def test_find_bytes_returns_the_matched_bytes(t, ctx):
    matches = [m for m in ctx.searcher.find_bytes(ctx.sigma)
               if m.address == ctx.sigma_address]
    t.equal("exactly one match at the symbol", len(matches), 1)
    if matches:
        t.equal("the bytes come back", matches[0].data, bs.as_bytes(ctx.sigma))


def test_find_bytes_with_a_mask(t, ctx):
    """A zero mask byte matches anything in that position."""
    pattern = bytearray(ctx.sigma)
    pattern[0] = 0x00
    mask = bytearray([0xff] * len(pattern))
    mask[0] = 0x00
    matches = ctx.searcher.find_bytes(pattern, mask=mask)
    t.contains("the masked byte is ignored", [m.address for m in matches],
               ctx.sigma_address)


def test_find_bytes_rejects_a_mismatched_mask(t, ctx):
    t.raises("a mask of the wrong length is refused", ValueError,
             ctx.searcher.find_bytes, b"abcd", bytearray([0xff]))


def test_find_regex(t, ctx):
    pattern = bs.escape_bytes(b"expand ") + "[\\x31-\\x33]" + \
        bs.escape_bytes(b"2-byte k")
    matches = ctx.searcher.find_regex(pattern)
    t.contains("a character class over byte values matches",
               [m.address for m in matches], ctx.sigma_address)


def test_find_any_attributes_each_hit(t, ctx):
    patterns = [ctx.sigma, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"]
    matches = ctx.searcher.find_any(patterns)
    by_pattern = {}
    for match in matches:
        by_pattern.setdefault(match.pattern, []).append(match.address)
    t.contains("the sigma string was found",
               by_pattern.get(bs.as_bytes(ctx.sigma), []), ctx.sigma_address)
    t.contains("the base64 alphabet was found",
               by_pattern.get(bs.as_bytes(patterns[1]), []),
               ctx.base64_address)


def test_find_any_batches_without_losing_matches(t, ctx):
    """A batch size of one forces a pass per pattern; the results must not
    differ from folding them into a single alternation."""
    patterns = [ctx.sigma, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"]
    one_at_a_time = ctx.searcher.find_any(patterns, batch_size=1)
    together = ctx.searcher.find_any(patterns, batch_size=16)
    t.equal("the same matches either way",
            sorted(str(m.address) for m in one_at_a_time),
            sorted(str(m.address) for m in together))


def test_find_any_prefers_the_longer_of_two_overlapping_patterns(t, ctx):
    """Where one pattern is a prefix of another, the alternation must not let
    the short one shadow the long one."""
    short = b"expand 32"
    long_ = b"expand 32-byte k"
    matches = [m for m in ctx.searcher.find_any([short, long_])
               if m.address == ctx.sigma_address]
    t.equal("one match at the address", len(matches), 1)
    if matches:
        t.equal("it is the longer pattern", matches[0].pattern,
                bs.as_bytes(long_))


def test_find_any_rejects_an_empty_pattern(t, ctx):
    t.raises("an empty pattern is refused", ValueError,
             ctx.searcher.find_any, [b""])


def test_pattern_length_is_capped(t, ctx):
    """Anything longer than the chunk overlap can be missed, so it is refused
    rather than silently unreliable."""
    t.raises("an over-long pattern is refused", ValueError,
             ctx.searcher.find_bytes, b"\x00" * (bs.MAX_PATTERN_BYTES + 1))
    t.equal("the cap matches MemorySearcher's overlap", bs.MAX_PATTERN_BYTES,
            100)


def test_alignment_filter(t, ctx):
    """The sigma string is 16-byte aligned in the fixture, so a filter it fails
    must drop it."""
    aligned = bs.ByteSearcher(program=ctx.program, alignment=2)
    unaligned_only = bs.ByteSearcher(program=ctx.program, alignment=1)
    t.check("without a filter the match is present",
            ctx.sigma_address in
            [m.address for m in unaligned_only.find_bytes(ctx.sigma)])
    matches = [m.address for m in aligned.find_bytes(ctx.sigma)]
    expected = ctx.sigma_address.getOffset() % 2 == 0
    t.equal("the 2-byte alignment filter agrees with the address",
            ctx.sigma_address in matches, expected)


def test_match_limit_is_respected(t, ctx):
    """A pattern with many hits, capped low."""
    matches = ctx.searcher.find_bytes(b"\x00" * 8, limit=5)
    t.check("no more matches than the limit", len(matches) <= 5,
            "got %d" % len(matches))


def test_read_memory_round_trips(t, ctx):
    data = bs.read_memory(ctx.sigma_address, len(ctx.sigma),
                          program=ctx.program)
    t.equal("the bytes at the symbol are the sigma string",
            bs.as_bytes(data), bs.as_bytes(ctx.sigma))


def test_read_memory_on_unmapped_memory(t, ctx):
    """Reading somewhere with no bytes returns empty rather than throwing."""
    unmapped = ctx.program.getAddressFactory() \
        .getDefaultAddressSpace().getAddress(0x7ffffff0)
    t.equal("an unreadable address yields no bytes",
            len(bs.read_memory(unmapped, 16, program=ctx.program)), 0)


def test_create_byte_searcher(t, ctx):
    searcher = bs.createByteSearcher(program=ctx.program)
    t.not_none("the factory returns a searcher", searcher)
    t.equal("it defaults to the loaded memory set",
            searcher.search_set, bs.default_search_set(ctx.program))
