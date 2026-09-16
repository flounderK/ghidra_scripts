"""Tests for ghidra_api.const_encoding_utils.

Pure byte layout arithmetic, so none of this needs a program open.
"""


from ghidra_api import const_encoding_utils as ce


def _hex(data):
    return "".join("%02x" % b for b in bytearray(data))


def test_pack_int_endianness(t):
    t.equal("little endian u32", _hex(ce.pack_int(0x11223344, 4, False)),
            "44332211")
    t.equal("big endian u32", _hex(ce.pack_int(0x11223344, 4, True)),
            "11223344")


def test_pack_int_truncates_above_width(t):
    t.equal("a value wider than the field is truncated",
            _hex(ce.pack_int(0x11223344, 2, True)), "3344")


def test_pack_words_at_declared_width(t):
    words = [0x428a2f98, 0x71374491]
    t.equal("u32 big endian",
            _hex(ce.pack_words(words, 32, ce.Encoding(32, True))),
            "428a2f9871374491")
    t.equal("u32 little endian",
            _hex(ce.pack_words(words, 32, ce.Encoding(32, False))),
            "982f8a4291443771")


def test_pack_words_widened(t):
    """A byte table written as int[] in C lands as zero-extended u32s."""
    t.equal("u8 values widened to u32 little endian",
            _hex(ce.pack_words([0x63, 0x7c], 8, ce.Encoding(32, False))),
            "630000007c000000")
    t.equal("u8 values widened to u32 big endian",
            _hex(ce.pack_words([0x63, 0x7c], 8, ce.Encoding(32, True))),
            "000000630000007c")


def test_pack_words_split_matches_unsplit(t):
    """Splitting a word with the chunk order agreeing with the byte order
    produces exactly the bytes of the unsplit word, which is why
    enumerate_layouts can dedup them away."""
    words = [0x428a2f98d728ae22]
    unsplit_be = ce.pack_words(words, 64, ce.Encoding(64, True))
    split_be = ce.pack_words(words, 64, ce.Encoding(32, True, high_chunk_first=True))
    t.equal("big endian u32 chunks, high first, equal the u64", 
            _hex(split_be), _hex(unsplit_be))
    unsplit_le = ce.pack_words(words, 64, ce.Encoding(64, False))
    split_le = ce.pack_words(words, 64, ce.Encoding(32, False, high_chunk_first=False))
    t.equal("little endian u32 chunks, low first, equal the u64",
            _hex(split_le), _hex(unsplit_le))


def test_pack_words_word_swapped(t):
    """The layouts that are genuinely new: chunk order against byte order."""
    words = [0x428a2f98d728ae22]
    t.equal("little endian halves, most significant first",
            _hex(ce.pack_words(words, 64,
                               ce.Encoding(32, False, high_chunk_first=True))),
            "982f8a4222ae28d7")
    t.equal("big endian halves, least significant first",
            _hex(ce.pack_words(words, 64,
                               ce.Encoding(32, True, high_chunk_first=False))),
            "d728ae22428a2f98")


def test_pack_words_reversed_sequence(t):
    t.equal("the sequence itself runs backwards",
            _hex(ce.pack_words([0x1122, 0x3344], 16,
                               ce.Encoding(16, True, reversed_order=True))),
            "33441122")


def test_pack_words_rejects_unsupported_word_width(t):
    t.raises("a word width that is not 8/16/32/64 is refused", ValueError,
             ce.pack_words, [0x1234], 24, ce.Encoding(8, True))


def test_enumerate_layouts_dedups(t):
    layouts = ce.enumerate_layouts([0x428a2f98, 0x71374491], 32)
    rendered = [_hex(data) for _, data in layouts]
    t.equal("no two layouts produce the same bytes",
            len(rendered), len(set(rendered)))
    t.contains("the plain big endian layout is present", rendered,
               "428a2f9871374491")
    t.contains("the plain little endian layout is present", rendered,
               "982f8a4291443771")


def test_enumerate_layouts_prefers_the_simple_label(t):
    """Where layouts collapse, the surviving one is named at the declared width."""
    layouts = ce.enumerate_layouts([0x428a2f98, 0x71374491], 32)
    by_bytes = dict((_hex(data), enc.label(32)) for enc, data in layouts)
    t.equal("big endian u32 is not labelled as split u8 or u16",
            by_bytes.get("428a2f9871374491"), "u32be")


def test_enumerate_layouts_widening_is_optional(t):
    with_wide = ce.enumerate_layouts([1, 2, 3], 8)
    without = ce.enumerate_layouts([1, 2, 3], 8, include_widened=False)
    t.check("widening adds layouts", len(with_wide) > len(without),
            "%d vs %d" % (len(with_wide), len(without)))
    t.equal("without widening only the byte layout remains", len(without), 1)


def test_enumerate_layouts_reversal_is_optional(t):
    plain = ce.enumerate_layouts([0x1122, 0x3344], 16, include_widened=False)
    reversed_too = ce.enumerate_layouts([0x1122, 0x3344], 16,
                                        include_widened=False,
                                        include_reversed=True)
    t.check("reversal adds layouts", len(reversed_too) > len(plain),
            "%d vs %d" % (len(reversed_too), len(plain)))
    t.check("every reversed layout is labelled as such",
            any(enc.label(16).endswith(".rev") for enc, _ in reversed_too))


def test_encoding_labels(t):
    t.equal("byte elements have no endianness in their label",
            ce.Encoding(8, True).label(8), "u8")
    t.equal("plain u32 big endian", ce.Encoding(32, True).label(32), "u32be")
    t.equal("word-swapped layouts are called out",
            ce.Encoding(32, False, high_chunk_first=True).label(64),
            "u32le.hi-first")
    t.equal("an unsplit layout is not called out",
            ce.Encoding(32, False).label(32), "u32le")


def test_encoding_rejects_odd_widths(t):
    t.raises("an unsupported element width is refused", ValueError,
             ce.Encoding, 24, True)


def test_distinct_byte_count(t):
    t.equal("a run of one value", ce.distinct_byte_count(b"\xff" * 16), 1)
    t.equal("four distinct values",
            ce.distinct_byte_count(bytearray([1, 2, 3, 4, 1, 2])), 4)
