"""
Turning a logical sequence of constants into the byte sequences it can
actually appear as in a binary.

A constant such as the SHA-256 round table is defined as 64 32-bit words, but
the bytes in an image depend on choices the definition does not make:

  * byte order within an element -- big or little endian
  * element width -- the same 64-bit constant is stored as u64s on a 64-bit
    target and as pairs of u32s on a 32-bit one, and byte-oriented tables such
    as an S-box are routinely declared ``int[256]`` in C and so land as u32s
  * element order within a word, when a wide word is split into narrower
    elements. Splitting with the byte order and the element order agreeing
    produces exactly the same bytes as not splitting at all, so the only
    layouts that are genuinely new are the mixed ones: little-endian elements
    stored most-significant first, or big-endian elements stored
    least-significant first. Those show up in hand-rolled 64-bit arithmetic on
    32-bit targets.
  * sequence order -- a multi-limb bignum written most-significant-limb first
    in a specification is usually stored least-significant-limb first in code

:func:`enumerate_layouts` walks all of those and returns the distinct byte
sequences, labelled with the layout that produced each one. Layouts that
collapse onto the same bytes are reported once, under the simplest label.
"""

ELEMENT_BITS = (8, 16, 32, 64)
WORD_BITS = (8, 16, 32, 64)


class Encoding(object):
    """One way of laying a word sequence out in memory.

    @element_bits: width of each stored element.
    @big_endian: byte order within an element.
    @high_chunk_first: when a word is wider than an element and so is split,
                       whether the most significant chunk is stored first.
                       Meaningless, and forced True, otherwise.
    @reversed_order: whether the sequence itself runs backwards.
    """

    __slots__ = ("element_bits", "big_endian", "high_chunk_first",
                 "reversed_order")

    def __init__(self, element_bits, big_endian, high_chunk_first=True,
                 reversed_order=False):
        if element_bits not in ELEMENT_BITS:
            raise ValueError("unsupported element width %r" % (element_bits,))
        self.element_bits = element_bits
        self.big_endian = bool(big_endian)
        self.high_chunk_first = bool(high_chunk_first)
        self.reversed_order = bool(reversed_order)

    @property
    def element_bytes(self):
        return self.element_bits // 8

    def label(self, word_bits=None):
        """A short, sortable description, e.g. ``u32be`` or ``u16le.lo-first``."""
        # Byte order is meaningless for single-byte elements.
        text = ("u8" if self.element_bits == 8 else
                "u%d%s" % (self.element_bits,
                           "be" if self.big_endian else "le"))
        if word_bits is not None and self.element_bits < word_bits:
            # Only worth saying when it distinguishes this from the plain
            # unsplit layout, which is the case the dedup keeps under its own
            # label anyway.
            if self.big_endian != self.high_chunk_first:
                text += ".hi-first" if self.high_chunk_first else ".lo-first"
        if self.reversed_order:
            text += ".rev"
        return text

    def _key(self):
        return (self.element_bits, self.big_endian, self.high_chunk_first,
                self.reversed_order)

    def __eq__(self, other):
        return isinstance(other, Encoding) and self._key() == other._key()

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self._key())

    def __repr__(self):
        return "<Encoding %s>" % self.label()


def pack_int(value, nbytes, big_endian):
    """Pack a non-negative int into @nbytes, truncating anything above them."""
    out = bytearray()
    for i in range(nbytes):
        out.append((value >> (8 * i)) & 0xff)
    if big_endian:
        out.reverse()
    return out


def pack_words(words, word_bits, encoding):
    """Lay @words, each @word_bits wide, out as bytes according to @encoding."""
    if word_bits not in WORD_BITS:
        raise ValueError("unsupported word width %r" % (word_bits,))
    # Every supported width is a power of two multiple of 8, so a narrower
    # element always divides a wider word evenly.
    element_bits = encoding.element_bits

    sequence = list(words)
    if encoding.reversed_order:
        sequence.reverse()

    nbytes = encoding.element_bytes
    out = bytearray()
    if element_bits >= word_bits:
        # Each word occupies a whole element, zero-extended if it is wider.
        for word in sequence:
            out += pack_int(word, nbytes, encoding.big_endian)
        return out

    chunks_per_word = word_bits // element_bits
    mask = (1 << element_bits) - 1
    for word in sequence:
        chunks = [(word >> (element_bits * i)) & mask
                  for i in range(chunks_per_word)]
        if encoding.high_chunk_first:
            chunks.reverse()
        for chunk in chunks:
            out += pack_int(chunk, nbytes, encoding.big_endian)
    return out


def enumerate_layouts(words, word_bits, element_bits=ELEMENT_BITS,
                      include_reversed=False, include_widened=True):
    """Every distinct byte sequence @words can appear as.

    Returns a list of (Encoding, bytearray) in preference order: the layout
    that matches the declared word width first, then narrower elements, then
    wider ones. Layouts producing identical bytes are reported once, under the
    first -- and so simplest -- label that produced them.

    @include_widened: also consider elements wider than the declared word,
                      which is how byte tables written as ``int[]`` appear.
    @include_reversed: also consider the sequence stored backwards. Worth it
                       for bignum limbs, noise for a round-constant table.
    """
    sequences = []
    seen = set()
    for width in _ordered_widths(word_bits, element_bits, include_widened):
        chunk_orders = (True, False) if width < word_bits else (True,)
        for reversed_order in ((False, True) if include_reversed else (False,)):
            for big_endian in (True, False):
                for high_chunk_first in chunk_orders:
                    encoding = Encoding(width, big_endian, high_chunk_first,
                                        reversed_order)
                    data = pack_words(words, word_bits, encoding)
                    key = bytes(data)
                    if key in seen:
                        continue
                    seen.add(key)
                    sequences.append((encoding, data))
    return sequences


def _ordered_widths(word_bits, element_bits, include_widened):
    """Element widths to try, simplest interpretation first."""
    exact = [w for w in element_bits if w == word_bits]
    narrower = sorted((w for w in element_bits if w < word_bits), reverse=True)
    wider = sorted(w for w in element_bits if w > word_bits)
    return exact + narrower + (wider if include_widened else [])


def distinct_byte_count(data):
    """How many distinct byte values @data uses.

    A probe drawn from a widened byte table is mostly zero padding, so this is
    used to reject patterns too repetitive to mean anything.
    """
    return len(set(bytearray(data)))
