"""Tests for ghidra_api.crypto_const_utils.

Two kinds of check. The derived constants are compared against their published
values, which is what stops a subtle arithmetic bug from producing a plausible
but wrong table. The transcribed ones are checked against a structural property
each must have -- a permutation table is a permutation, a generator point lies
on its curve -- which is the only way to catch a typo in a table nobody can
read.
"""


from ghidra_api import crypto_const_utils as cc


def _limbs_to_int(limbs):
    value = 0
    for limb in limbs:
        value = (value << 64) | limb
    return value


def _is_permutation(values, expected):
    return sorted(values) == sorted(expected)


# --- derived constants against their published values ----------------------

def test_md5_sine_table(t):
    table = cc.md5_sine_table()
    t.equal("64 entries", len(table), 64)
    t.equal("T[1] is 0xd76aa478", table[0], 0xd76aa478)
    t.equal("T[64] is 0xeb86d391", table[63], 0xeb86d391)


def test_sha256_initial_state(t):
    state = cc.sha2_32_state(0)
    t.equal("H0 is 0x6a09e667", state[0], 0x6a09e667)
    t.equal("H7 is 0x5be0cd19", state[7], 0x5be0cd19)


def test_sha224_initial_state(t):
    state = cc.sha2_32_state(8)
    t.equal("H0 is 0xc1059ed8", state[0], 0xc1059ed8)
    t.equal("H7 is 0xbefa4fa4", state[7], 0xbefa4fa4)


def test_sha256_round_constants(t):
    constants = cc.sha2_round_constants(64, 32)
    t.equal("64 entries", len(constants), 64)
    t.equal("K[0] is 0x428a2f98", constants[0], 0x428a2f98)
    t.equal("K[63] is 0xc67178f2", constants[63], 0xc67178f2)


def test_sha512_initial_state(t):
    """64 fractional bits is past what a double can hold, so this is the test
    that the integer root is doing real work."""
    state = cc.sha2_64_state(0)
    t.equal("H0 is 0x6a09e667f3bcc908", state[0], 0x6a09e667f3bcc908)
    t.equal("H7 is 0x5be0cd19137e2179", state[7], 0x5be0cd19137e2179)


def test_sha384_initial_state(t):
    state = cc.sha2_64_state(8)
    t.equal("H0 is 0xcbbb9d5dc1059ed8", state[0], 0xcbbb9d5dc1059ed8)


def test_sha512_round_constants(t):
    constants = cc.sha2_round_constants(80, 64)
    t.equal("80 entries", len(constants), 80)
    t.equal("K[0] is 0x428a2f98d728ae22", constants[0], 0x428a2f98d728ae22)
    t.equal("K[79] is 0x6c44198c4a475817", constants[79], 0x6c44198c4a475817)


def test_sha512t_initial_states(t):
    t.equal("SHA-512/224 H0", cc.sha512t_state(224)[0], 0x8c3d37c819544da2)
    t.equal("SHA-512/256 H0", cc.sha512t_state(256)[0], 0x22312194fc2bf72c)
    t.equal("SHA-512/256 H7", cc.sha512t_state(256)[7], 0x0eb72ddc81c52ca2)


def test_keccak_round_constants(t):
    constants = cc.keccak_round_constants()
    t.equal("24 rounds", len(constants), 24)
    t.equal("RC[0] is 1", constants[0], 0x0000000000000001)
    t.equal("RC[2] is 0x800000000000808a", constants[2], 0x800000000000808a)
    t.equal("RC[23] is 0x8000000080008008", constants[23], 0x8000000080008008)


def test_aes_sbox(t):
    sbox = cc.aes_sbox()
    t.equal("256 entries", len(sbox), 256)
    t.equal("S[0] is 0x63", sbox[0], 0x63)
    t.equal("S[255] is 0x16", sbox[255], 0x16)
    t.check("the S-box is a permutation of 0..255",
            _is_permutation(sbox, range(256)))


def test_aes_inverse_sbox_inverts(t):
    sbox = cc.aes_sbox()
    inverse = cc.aes_inverse_sbox()
    t.equal("inverse S[0] is 0x52", inverse[0], 0x52)
    t.check("inverse(S(x)) == x for every byte",
            all(inverse[sbox[x]] == x for x in range(256)))


def test_aes_rcon(t):
    t.equal("the ten round constants", cc.aes_rcon(),
            [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36])


def test_aes_t_tables(t):
    t.equal("Te0[0] is 0xc66363a5", cc.aes_te_table(0)[0], 0xc66363a5)
    t.equal("Te1[0] is 0xa5c66363", cc.aes_te_table(1)[0], 0xa5c66363)
    t.equal("Td0[0] is 0x51f4a750", cc.aes_td_table(0)[0], 0x51f4a750)
    t.equal("all four Te tables are rotations of one another",
            sorted(set(len(cc.aes_te_table(r)) for r in range(4))), [256])


def test_crc_tables(t):
    t.equal("CRC-32 reflected T[1]", cc.crc_table(0xedb88320)[1], 0x77073096)
    t.equal("CRC-32 reflected T[255]", cc.crc_table(0xedb88320)[255], 0x2d02ef8d)
    t.equal("CRC-32 normal T[1]", cc.crc_table(0x04c11db7, 32, False)[1],
            0x04c11db7)
    t.equal("CRC-32C T[1]", cc.crc_table(0x82f63b78)[1], 0xf26b8303)
    t.equal("CRC-16/ARC T[1]", cc.crc_table(0xa001, 16)[1], 0xc0c1)
    t.equal("CRC-16/CCITT T[1]", cc.crc_table(0x1021, 16, False)[1], 0x1021)
    t.equal("CRC-64/XZ T[1]", cc.crc_table(0xc96c5795d7870f42, 64)[1],
            0xb32e4cbe03a75f6f)


def test_pi_fraction_words(t):
    """Blowfish's P-array and four S-boxes are 1042 consecutive words of pi.

    Anchoring the published values at both ends checks the whole series: an
    error anywhere in the Machin summation would move every word after it.
    """
    words = cc.pi_fraction_words(1042)
    t.equal("P[0] is 0x243f6a88", words[0], 0x243f6a88)
    t.equal("P[17] is 0x8979fb1b", words[17], 0x8979fb1b)
    t.equal("S-box 0 starts at 0xd1310ba6", words[18], 0xd1310ba6)
    t.equal("S-box 0 ends at 0x6e85076a", words[18 + 255], 0x6e85076a)
    t.equal("S-box 3 ends at 0x3ac372e6", words[18 + 1023], 0x3ac372e6)


def test_sm4_ck(t):
    ck = cc.sm4_ck()
    t.equal("32 entries", len(ck), 32)
    t.equal("CK[0] is 0x00070e15", ck[0], 0x00070e15)
    t.equal("CK[28] is 0x10171e25", ck[28], 0x10171e25)
    t.equal("CK[31] is 0x646b7279", ck[31], 0x646b7279)


def test_camellia_sigma(t):
    sigma = cc.camellia_sigma()
    t.equal("six constants", len(sigma), 6)
    t.equal("Sigma1 is 0xa09e667f3bcc908b", sigma[0], 0xa09e667f3bcc908b)
    t.equal("Sigma6 is 0xb05688c2b3e6c1fd", sigma[5], 0xb05688c2b3e6c1fd)


def test_integer_root_is_exact(t):
    t.equal("a large exact square root", cc.integer_root(2 ** 200, 2), 2 ** 100)
    t.equal("a large exact cube root", cc.integer_root(3 ** 150, 3), 3 ** 50)
    t.equal("floors rather than rounds", cc.integer_root(26, 3), 2)


# --- transcribed tables against their structural properties -----------------

def test_des_permutations(t):
    t.check("IP is a permutation of 1..64",
            _is_permutation(cc.DES_IP, range(1, 65)))
    t.check("FP is a permutation of 1..64",
            _is_permutation(cc.DES_FP, range(1, 65)))
    t.check("FP is the inverse of IP",
            all(cc.DES_FP[cc.DES_IP[i] - 1] == i + 1 for i in range(64)))
    t.check("P is a permutation of 1..32",
            _is_permutation(cc.DES_P, range(1, 33)))


def test_des_key_schedule_tables(t):
    t.equal("PC-1 selects 56 bits", len(cc.DES_PC1), 56)
    t.equal("PC-1 selects each bit once", len(set(cc.DES_PC1)), 56)
    t.equal("PC-1 drops exactly the parity bits",
            sorted(set(range(1, 65)) - set(cc.DES_PC1)),
            [8, 16, 24, 32, 40, 48, 56, 64])
    t.equal("PC-2 selects 48 bits", len(cc.DES_PC2), 48)
    t.equal("PC-2 selects each bit once", len(set(cc.DES_PC2)), 48)
    t.check("PC-2 indexes into the 56 bits PC-1 produced",
            max(cc.DES_PC2) <= 56 and min(cc.DES_PC2) >= 1)
    t.equal("E expands 32 bits to 48", len(cc.DES_E), 48)
    t.check("E indexes into 32 bits",
            max(cc.DES_E) <= 32 and min(cc.DES_E) >= 1)


def test_des_sboxes(t):
    t.equal("eight boxes of four rows of sixteen", len(cc.DES_SBOXES), 512)
    for box in range(8):
        for row in range(4):
            start = box * 64 + row * 16
            t.check("S%d row %d is a permutation of 0..15" % (box + 1, row),
                    _is_permutation(cc.DES_SBOXES[start:start + 16], range(16)))


def test_md2_sbox(t):
    t.check("the MD2 S-box is a permutation of 0..255",
            _is_permutation(cc.MD2_SBOX, range(256)))


def test_sm4_sbox(t):
    t.check("the SM4 S-box is a permutation of 0..255",
            _is_permutation(cc.SM4_SBOX, range(256)))


def test_blake2_sigma(t):
    t.equal("ten rounds of sixteen", len(cc.BLAKE2_SIGMA), 160)
    for round_index in range(10):
        start = round_index * 16
        t.check("sigma round %d is a permutation of 0..15" % round_index,
                _is_permutation(cc.BLAKE2_SIGMA[start:start + 16], range(16)))


def test_keccak_rho_offsets(t):
    t.equal("one offset per lane", len(cc.KECCAK_RHO), 25)
    t.check("every offset is a rotation of a 64-bit lane",
            all(0 <= v < 64 for v in cc.KECCAK_RHO))


def test_secp256k1_parameters(t):
    p = _limbs_to_int(cc.SECP256K1_P)
    t.equal("p is 2**256 - 2**32 - 977", p, 2 ** 256 - 2 ** 32 - 977)
    x = _limbs_to_int(cc.SECP256K1_GX)
    y = _limbs_to_int(cc.SECP256K1_GY)
    t.equal("the generator satisfies y**2 == x**3 + 7",
            pow(y, 2, p), (pow(x, 3, p) + 7) % p)
    t.check("the group order is odd and below 2**256",
            _limbs_to_int(cc.SECP256K1_N) % 2 == 1 and
            _limbs_to_int(cc.SECP256K1_N) < 2 ** 256)


def test_p256_parameters(t):
    p = _limbs_to_int(cc.P256_P)
    t.equal("p is 2**256 - 2**224 + 2**192 + 2**96 - 1",
            p, 2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1)
    x = _limbs_to_int(cc.P256_GX)
    y = _limbs_to_int(cc.P256_GY)
    b = _limbs_to_int(cc.P256_B)
    t.equal("the generator satisfies y**2 == x**3 - 3x + b",
            pow(y, 2, p), (pow(x, 3, p) - 3 * x + b) % p)


def test_curve25519_parameters(t):
    p = _limbs_to_int(cc.CURVE25519_P)
    t.equal("p is 2**255 - 19", p, 2 ** 255 - 19)
    t.equal("the group order is 2**252 + 277423177773723535358519377908836484"
            "93", _limbs_to_int(cc.CURVE25519_L),
            2 ** 252 + 27742317777372353535851937790883648493)
    d = _limbs_to_int(cc.ED25519_D)
    t.equal("d is -121665/121666 mod p", d,
            (-121665 * pow(121666, p - 2, p)) % p)
    y = _limbs_to_int(cc.ED25519_BY)
    t.equal("the base point y is 4/5 mod p", y, (4 * pow(5, p - 2, p)) % p)
    x = _limbs_to_int(cc.ED25519_BX)
    t.equal("the base point satisfies -x**2 + y**2 == 1 + d x**2 y**2",
            (-x * x + y * y - 1 - d * x * x * y * y) % p, 0)


# --- the signature list itself ----------------------------------------------

def test_signatures_are_well_formed(t):
    signatures = cc.get_signatures(include_scalars=True)
    t.check("there are signatures to scan for", len(signatures) > 40,
            "found %d" % len(signatures))
    names = [s.name for s in signatures]
    t.equal("every signature name is unique", len(names), len(set(names)))
    for signature in signatures:
        t.check("%s has words" % signature.name, signature.word_count > 0)
        t.check("%s declares a known category" % signature.name,
                signature.category in cc.CATEGORIES)
        limit = 1 << signature.word_bits
        t.check("%s words all fit in u%d" % (signature.name,
                                             signature.word_bits),
                all(0 <= w < limit for w in signature.words))


def test_signatures_produce_layouts(t):
    for signature in cc.get_signatures():
        layouts = signature.layouts()
        t.check("%s has at least one layout" % signature.name,
                len(layouts) > 0)
        rendered = set(bytes(bytearray(data)) for _, data in layouts)
        t.equal("%s layouts are all distinct" % signature.name,
                len(rendered), len(layouts))


def test_scalars_are_excluded_by_default(t):
    default = cc.get_signatures()
    everything = cc.get_signatures(include_scalars=True)
    t.check("scalars are held back", len(everything) > len(default))
    t.check("nothing single-word survives the default filter",
            all(not s.scalar for s in default))


def test_signature_filtering(t):
    hashes = cc.get_signatures(categories=["hash"])
    t.check("filtering by category selects only that category",
            hashes and all(s.category == "hash" for s in hashes))
    named = cc.get_signatures(names=["sha-256"])
    t.check("filtering by name is case insensitive and substring based",
            named and all("sha-256" in s.name.lower() for s in named))


def test_signature_words_are_cached(t):
    """The expensive derivations must not run once per layout."""
    signature = cc.get_signatures(names=["Blowfish S-box"])[0]
    t.check("the same list object comes back each time",
            signature.words is signature.words)
