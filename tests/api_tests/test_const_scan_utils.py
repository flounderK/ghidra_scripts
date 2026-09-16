"""End-to-end tests for ghidra_api.const_scan_utils.

The fixture (tests/crypto_const_cases.c) deliberately stores the same constants
at different widths, byte orders and word orders, so these check not just that
a constant is found but that it is reported at the address and in the layout it
was actually compiled into.
"""

from ghidra_api._compat import resolve_program

from ghidra_api import const_scan_utils as cs
from ghidra_api import crypto_const_utils as cc
from ghidra_test_support import global_address


class Context(object):
    def __init__(self):
        self.program = resolve_program(None)
        self.scanner = cs.CryptoConstScanner(program=self.program)
        self.matches = self.scanner.scan()
        self.by_address = {}
        for match in self.matches:
            self.by_address.setdefault(match.address.getOffset(),
                                       []).append(match)

    def at(self, symbol):
        """Every match reported at the address of @symbol."""
        address = global_address(self.program, symbol)
        if address is None:
            return None
        return self.by_address.get(address.getOffset(), [])

    def expect(self, t, symbol, name, layout, complete=True):
        matches = self.at(symbol)
        if matches is None:
            t.check("%s is in the fixture binary" % symbol, False,
                    "symbol not found")
            return
        found = [m for m in matches if m.name == name]
        if not t.check("%s is reported as %s" % (symbol, name), bool(found),
                       "got %s" % ([m.name for m in matches] or "nothing")):
            return
        match = found[0]
        t.equal("%s is read as %s" % (symbol, layout), match.layout, layout)
        if complete:
            t.check("%s is confirmed in full" % symbol, match.is_complete,
                    "%d of %d words confirmed" % (match.words_matched,
                                                  match.word_count))


def setup_module():
    return Context()


def test_scan_found_something(t, ctx):
    t.check("the scan reports matches", len(ctx.matches) > 0,
            "found %d" % len(ctx.matches))


def test_little_endian_u32_table(t, ctx):
    ctx.expect(t, "fx_sha256_k_le", "SHA-256 round constants", "u32le")


def test_big_endian_u32_table(t, ctx):
    """The same table byte-swapped: found only if endianness is really tried."""
    ctx.expect(t, "fx_sha256_k_be", "SHA-256 round constants", "u32be")


def test_byte_table_as_bytes(t, ctx):
    ctx.expect(t, "fx_aes_sbox_u8", "AES S-box", "u8")


def test_byte_table_widened_to_u32(t, ctx):
    """An S-box declared int[256] in C, which is how many implementations
    write it."""
    ctx.expect(t, "fx_aes_sbox_u32", "AES S-box", "u32le")


def test_crc_table(t, ctx):
    ctx.expect(t, "fx_crc32_table", "CRC-32 table (reflected)", "u32le")


def test_md5_sine_table(t, ctx):
    ctx.expect(t, "fx_md5_t", "MD5 sine table", "u32le")


def test_blowfish_p_array(t, ctx):
    ctx.expect(t, "fx_blowfish_p", "Blowfish P-array", "u32le")


def test_des_sboxes(t, ctx):
    ctx.expect(t, "fx_des_sboxes", "DES S-boxes", "u8")


def test_u64_table(t, ctx):
    ctx.expect(t, "fx_sha512_iv", "SHA-512 initial state / BLAKE2b IV",
               "u64le")


def test_word_swapped_u64_table(t, ctx):
    """u64 constants split into u32 halves stored most significant first --
    the layout that only exists because splitting and byte order can disagree.
    """
    ctx.expect(t, "fx_sha512_iv_wordswapped",
               "SHA-512 initial state / BLAKE2b IV", "u32le.hi-first")


def test_reversed_bignum_limbs(t, ctx):
    """A 256-bit prime stored least-significant-limb first."""
    ctx.expect(t, "fx_secp256k1_p_le", "secp256k1 p", "u64le.rev")


def test_ascii_constants(t, ctx):
    ctx.expect(t, "fx_chacha_sigma", "Salsa20/ChaCha20 sigma", "u8")
    ctx.expect(t, "fx_base64_alphabet", "Base64 alphabet", "u8")


def test_matches_report_their_extent(t, ctx):
    for match in ctx.matches:
        t.check("%s at %s confirms at least one word"
                % (match.name, match.address), match.words_matched >= 1)
        t.check("%s at %s confirms no more than it has"
                % (match.name, match.address),
                match.words_matched <= match.word_count)


def test_probes_are_never_over_the_search_limit(t, ctx):
    for probe in ctx.scanner.build_probes():
        if len(probe) > cs.MAX_PATTERN_BYTES:
            t.check("a probe is within the search limit", False,
                    "%d bytes" % len(probe))
            return
    t.check("every probe is within the search limit", True)


def test_weak_probes_are_skipped(t, ctx):
    """A layout whose probe is a run of one byte would match everywhere."""
    signature = cc.ConstSignature("all zeroes test", [0, 0, 0, 0], 32, "hash")
    scanner = cs.CryptoConstScanner(program=ctx.program,
                                    signatures=[signature])
    probes = scanner.build_probes()
    t.equal("no probe survives", len(probes), 0)
    t.check("and the skip was recorded", len(scanner.skipped) > 0)


def test_short_probes_are_skipped(t, ctx):
    signature = cc.ConstSignature("too short test", [0x11223344], 32, "hash",
                                  element_bits=(32,), include_widened=False)
    scanner = cs.CryptoConstScanner(program=ctx.program,
                                    signatures=[signature])
    t.equal("a four-byte probe is not searched for",
            len(scanner.build_probes()), 0)


def test_aliased_t_table_layouts_are_collapsed(t, ctx):
    """AES's Te tables are byte rotations of each other, so Te2 read normally
    and Te0 read word-swapped are the same bytes. Only the ordinary reading
    should survive."""
    signatures = cc.get_signatures(names=["AES Te"])
    scanner = cs.CryptoConstScanner(program=ctx.program,
                                    signatures=signatures)
    for match in scanner.scan():
        t.check("%s at %s is not reported through a word-swapped layout"
                % (match.name, match.address),
                ".hi-first" not in match.layout and
                ".lo-first" not in match.layout)


def test_min_words_matched_filters(t, ctx):
    strict = cs.CryptoConstScanner(program=ctx.program,
                                   min_words_matched=1000)
    t.equal("demanding more words than any signature has leaves nothing",
            len(strict.scan()), 0)


def test_signature_selection_narrows_the_scan(t, ctx):
    scanner = cs.CryptoConstScanner(
        program=ctx.program, signatures=cc.get_signatures(categories=["curve"]))
    matches = scanner.scan()
    t.check("only curve constants come back",
            all(m.category == "curve" for m in matches))


def test_matches_by_category(t, ctx):
    grouped = ctx.scanner.matches_by_category()
    t.equal("grouping loses nothing",
            sum(len(v) for v in grouped.values()), len(ctx.matches))
    t.check("every group key is a known category",
            all(k in cc.CATEGORIES for k in grouped))


def test_match_rendering(t, ctx):
    if not ctx.matches:
        return
    match = ctx.matches[0]
    text = str(match)
    t.contains("the rendered match names the constant", text, match.name)
    t.contains("and the layout it was read as", text, match.layout)


def test_create_scanner(t, ctx):
    scanner = cs.createCryptoConstScanner(program=ctx.program)
    t.not_none("the factory returns a scanner", scanner)
    t.check("it defaults to the non-scalar signatures",
            len(scanner.signatures) == len(cc.get_signatures()))
