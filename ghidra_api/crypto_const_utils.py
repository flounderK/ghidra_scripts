"""
The cryptographic, checksum, hash and algorithmic constants worth looking for
in a binary, and the arithmetic that produces them.

Most of these are *derived* rather than transcribed. A round table copied out
of an implementation is a table nobody can check; one computed from the
definition it came from ("the first 32 bits of the fractional part of the cube
root of the first 64 primes") is self-evidently the real thing, and a typo in
it becomes a broken derivation rather than a signature that silently never
matches. Where a constant has no closed form -- the DES permutation tables, the
MD2 and SM4 S-boxes, the curve parameters -- it is written out, and the test
suite checks each one against a structural property it must have: a permutation
table really is a permutation, a generator point really is on its curve.

This module is deliberately free of any Ghidra dependency. It is integer
arithmetic over integers, so it can be imported, tested and used to generate
fixtures without a program open, or indeed without Ghidra. const_scan_utils is
what searches a program for what is defined here.
"""

from .const_encoding_utils import enumerate_layouts

CATEGORIES = ("hash", "cipher", "checksum", "curve", "encoding", "algorithmic")


# ---------------------------------------------------------------------------
# derivations
# ---------------------------------------------------------------------------

def integer_root(value, degree):
    """Exact floor(value ** (1/degree)) by Newton's method.

    Integer arithmetic throughout: a double's 53-bit mantissa cannot represent
    the 64 fractional bits the SHA-512 constants are defined by.
    """
    if value == 0:
        return 0
    guess = 1 << ((value.bit_length() + degree - 1) // degree + 1)
    while True:
        nxt = ((degree - 1) * guess + value // guess ** (degree - 1)) // degree
        if nxt >= guess:
            return guess
        guess = nxt


def root_fraction_bits(value, degree, nbits):
    """The first @nbits of the fractional part of value ** (1/degree)."""
    return integer_root(value << (degree * nbits), degree) & ((1 << nbits) - 1)


def first_primes(count):
    primes = []
    candidate = 2
    while len(primes) < count:
        if all(candidate % p for p in primes if p * p <= candidate):
            primes.append(candidate)
        candidate += 1
    return primes


def pi_fraction_words(count):
    """The first @count 32-bit words of the fractional part of pi.

    Machin's formula in scaled integers. This is where Blowfish's P-array and
    S-boxes come from, which is why they are "nothing up my sleeve" numbers.
    """
    bits = count * 32
    # Guard bits absorb the truncation error accumulated by the series.
    scale = 1 << (bits + 64)

    def arctan_inverse(x):
        total = 0
        term = scale // x
        square = x * x
        divisor = 1
        sign = 1
        while term:
            total += sign * (term // divisor)
            term //= square
            divisor += 2
            sign = -sign
        return total

    pi = 16 * arctan_inverse(5) - 4 * arctan_inverse(239)
    fraction = (pi - 3 * scale) >> 64
    return [(fraction >> (bits - 32 * (i + 1))) & 0xffffffff
            for i in range(count)]


def md5_sine_table():
    """MD5's T table: floor(abs(sin(i+1)) * 2**32), i in 0..63.

    32 bits is inside a double's mantissa, so floating point is exact enough
    here in a way it is not for the 64-bit SHA-2 constants.
    """
    import math
    return [int(abs(math.sin(i + 1)) * (1 << 32)) & 0xffffffff
            for i in range(64)]


def sha2_32_state(prime_index):
    """SHA-224/256 initial state: frac(sqrt(p)) for 8 primes from @prime_index.

    SHA-256 uses primes 1..8 and takes the top 32 fractional bits; SHA-224 uses
    primes 9..16 and takes the *second* 32, which is the low half of the 64-bit
    value SHA-384 uses from the same primes.
    """
    primes = first_primes(prime_index + 8)[prime_index:]
    if prime_index == 0:
        return [root_fraction_bits(p, 2, 32) for p in primes]
    return [root_fraction_bits(p, 2, 64) & 0xffffffff for p in primes]


def sha2_64_state(prime_index):
    """SHA-384/512 initial state: frac(sqrt(p)), 64 bits, 8 primes."""
    primes = first_primes(prime_index + 8)[prime_index:]
    return [root_fraction_bits(p, 2, 64) for p in primes]


def sha2_round_constants(count, nbits):
    """SHA-2 round constants: frac(cbrt(p)) for the first @count primes."""
    return [root_fraction_bits(p, 3, nbits) for p in first_primes(count)]


def sha512t_state(t):
    """SHA-512/t initial state: SHA-512's, XORed with 0xa5a5... then rehashed.

    FIPS 180-4 section 5.3.6 defines it as SHA-512 of the string "SHA-512/t"
    run from that XORed state. Done here rather than transcribed so 224 and 256
    come from the same three lines.
    """
    state = [v ^ 0xa5a5a5a5a5a5a5a5 for v in sha2_64_state(0)]
    return _sha512_compress(state, _pad_message(b"SHA-512/%d" % t, 128, True))


def keccak_round_constants(rounds=24):
    """SHA-3 / Keccak-f[1600] round constants, from the 8-bit LFSR in FIPS 202."""
    constants = []
    lfsr = 0x01
    for _ in range(rounds):
        value = 0
        for j in range(7):
            if lfsr & 1:
                value ^= 1 << ((1 << j) - 1)
            lfsr = (((lfsr << 1) ^ 0x71) & 0xff if lfsr & 0x80
                    else (lfsr << 1) & 0xff)
        constants.append(value)
    return constants


def aes_sbox():
    """The AES S-box, from the GF(2**8) inverse and the affine transform."""
    def rotl8(x, n):
        return ((x << n) | (x >> (8 - n))) & 0xff

    sbox = [0] * 256
    sbox[0] = 0x63
    p = q = 1
    while True:
        # p walks the powers of 3; q walks the powers of 3 inverse, so q is
        # always the multiplicative inverse of p.
        p = p ^ ((p << 1) & 0xff) ^ (0x1b if p & 0x80 else 0)
        q ^= (q << 1) & 0xff
        q ^= (q << 2) & 0xff
        q ^= (q << 4) & 0xff
        if q & 0x80:
            q ^= 0x09
        sbox[p] = (q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4)
                   ^ 0x63) & 0xff
        if p == 1:
            return sbox


def aes_inverse_sbox():
    inverse = [0] * 256
    for index, value in enumerate(aes_sbox()):
        inverse[value] = index
    return inverse


def aes_rcon(count=10):
    """AES key-schedule round constants: successive doublings in GF(2**8)."""
    values = [1]
    for _ in range(count - 1):
        values.append(_xtime(values[-1]))
    return values


def aes_te_table(rotation=0):
    """An AES encryption T-table: [2s, s, s, 3s] per entry, rotated right.

    Te0..Te3 are byte rotations of one another; an implementation may embed any
    subset, so each rotation is searched separately.
    """
    table = []
    for value in aes_sbox():
        word = ((_xtime(value) << 24) | (value << 16) | (value << 8) |
                (_xtime(value) ^ value))
        table.append(_rotr32(word & 0xffffffff, 8 * rotation))
    return table


def aes_td_table(rotation=0):
    """An AES decryption T-table: [14s, 9s, 13s, 11s] over the inverse S-box."""
    table = []
    for value in aes_inverse_sbox():
        word = ((_gf_mul(value, 14) << 24) | (_gf_mul(value, 9) << 16) |
                (_gf_mul(value, 13) << 8) | _gf_mul(value, 11))
        table.append(_rotr32(word & 0xffffffff, 8 * rotation))
    return table


def crc_table(polynomial, width=32, reflected=True):
    """The byte-at-a-time CRC table for a polynomial.

    @reflected: whether the implementation shifts right (the polynomial is
                given reversed, as CRC-32's familiar 0xedb88320) or left (the
                polynomial is given in its normal form, 0x04c11db7).
    """
    mask = (1 << width) - 1
    top = 1 << (width - 1)
    table = []
    for index in range(256):
        if reflected:
            value = index
            for _ in range(8):
                value = (value >> 1) ^ (polynomial if value & 1 else 0)
        else:
            value = index << (width - 8)
            for _ in range(8):
                value = ((value << 1) ^ (polynomial if value & top else 0)) & mask
        table.append(value & mask)
    return table


def camellia_sigma():
    """Camellia's key-schedule constants.

    Drawn from the same well as the SHA-512 initial state -- the fractional
    part of the square root of the first six primes -- but starting one hex
    digit further in, so Sigma1 is 0xa09e667f3bcc908b where SHA-512's first
    word is 0x6a09e667f3bcc908.
    """
    return [root_fraction_bits(p, 2, 68) & 0xffffffffffffffff
            for p in first_primes(6)]


def sm4_ck():
    """SM4's key-expansion constants: ck[i][j] = (4i + j) * 7 mod 256."""
    return [sum(((4 * i + j) * 7 % 256) << (8 * (3 - j)) for j in range(4))
            for i in range(32)]


def _xtime(value):
    return ((value << 1) ^ 0x1b) & 0xff if value & 0x80 else (value << 1) & 0xff


def _gf_mul(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        b >>= 1
        a = _xtime(a)
    return result & 0xff


def _rotr32(value, bits):
    bits %= 32
    if bits == 0:
        return value
    return ((value >> bits) | (value << (32 - bits))) & 0xffffffff


def _pad_message(message, block_bytes, big_endian):
    """Merkle-Damgard padding, used only to derive the SHA-512/t states."""
    message = bytearray(message)
    length_bits = len(message) * 8
    message.append(0x80)
    while (len(message) + block_bytes // 8) % block_bytes:
        message.append(0)
    length_bytes = block_bytes // 8
    for i in range(length_bytes):
        shift = 8 * (length_bytes - 1 - i) if big_endian else 8 * i
        message.append((length_bits >> shift) & 0xff)
    return bytes(bytearray(message))


def _sha512_compress(state, message):
    mask = 0xffffffffffffffff
    constants = sha2_round_constants(80, 64)

    def rotr(x, n):
        return ((x >> n) | (x << (64 - n))) & mask

    state = list(state)
    for offset in range(0, len(message), 128):
        block = bytearray(message[offset:offset + 128])
        w = [0] * 80
        for i in range(16):
            w[i] = 0
            for j in range(8):
                w[i] = (w[i] << 8) | block[i * 8 + j]
        for i in range(16, 80):
            s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7)
            s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & mask
        a, b, c, d, e, f, g, h = state
        for i in range(80):
            s1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41)
            ch = (e & f) ^ (~e & mask & g)
            t1 = (h + s1 + ch + constants[i] + w[i]) & mask
            s0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (s0 + maj) & mask
            h, g, f, e, d, c, b, a = (g, f, e, (d + t1) & mask, c, b, a,
                                      (t1 + t2) & mask)
        state = [(x + y) & mask
                 for x, y in zip(state, (a, b, c, d, e, f, g, h))]
    return state


# ---------------------------------------------------------------------------
# tables with no closed form
#
# Each of these is checked against a structural invariant by the test suite --
# a permutation table is verified to be a permutation, a generator point to lie
# on its curve -- so a transcription error fails loudly instead of quietly
# producing a signature that never matches.
# ---------------------------------------------------------------------------

DES_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

DES_FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

DES_PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
           10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
           14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

DES_PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
           23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
           44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

DES_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
         12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

DES_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

# The eight DES S-boxes, laid out as they are in an implementation: four rows
# of sixteen per box, concatenated.
DES_SBOXES = [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,

    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,

    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,

    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,

    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,

    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,

    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,

    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]

MD2_SBOX = [
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19,
    98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
    30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,
    190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122,
    169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33,
    128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3,
    255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198,
    79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241,
    69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2,
    27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
    85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38,
    44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82,
    106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
    120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,
    242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10,
    49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20]

SM4_SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2,
    0x28, 0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
    0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4,
    0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa,
    0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
    0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2,
    0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b,
    0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2,
    0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30,
    0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
    0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45,
    0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41,
    0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
    0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a,
    0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e,
    0xd7, 0xcb, 0x39, 0x48]

# BLAKE2's message permutation, ten rounds of sixteen indices.
BLAKE2_SIGMA = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]

# Keccak-f[1600] rotation offsets, in lane order.
KECCAK_RHO = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
              41, 45, 15, 21, 8, 18, 2, 61, 56, 14]

SM3_IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
          0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]

# 256-bit values as 64-bit limbs, most significant first.
SECP256K1_P = [0xffffffffffffffff, 0xffffffffffffffff,
               0xffffffffffffffff, 0xfffffffefffffc2f]
SECP256K1_N = [0xffffffffffffffff, 0xfffffffffffffffe,
               0xbaaedce6af48a03b, 0xbfd25e8cd0364141]
SECP256K1_GX = [0x79be667ef9dcbbac, 0x55a06295ce870b07,
                0x029bfcdb2dce28d9, 0x59f2815b16f81798]
SECP256K1_GY = [0x483ada7726a3c465, 0x5da4fbfc0e1108a8,
                0xfd17b448a6855419, 0x9c47d08ffb10d4b8]

P256_P = [0xffffffff00000001, 0x0000000000000000,
          0x00000000ffffffff, 0xffffffffffffffff]
P256_N = [0xffffffff00000000, 0xffffffffffffffff,
          0xbce6faada7179e84, 0xf3b9cac2fc632551]
P256_B = [0x5ac635d8aa3a93e7, 0xb3ebbd55769886bc,
          0x651d06b0cc53b0f6, 0x3bce3c3e27d2604b]
P256_GX = [0x6b17d1f2e12c4247, 0xf8bce6e563a440f2,
           0x77037d812deb33a0, 0xf4a13945d898c296]
P256_GY = [0x4fe342e2fe1a7f9b, 0x8ee7eb4a7c0f9e16,
           0x2bce33576b315ece, 0xcbb6406837bf51f5]

CURVE25519_P = [0x7fffffffffffffff, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffed]
CURVE25519_L = [0x1000000000000000, 0x0000000000000000,
                0x14def9dea2f79cd6, 0x5812631a5cf5d3ed]
ED25519_D = [0x52036cee2b6ffe73, 0x8cc740797779e898,
             0x00700a4d4141d8ab, 0x75eb4dca135978a3]
ED25519_BX = [0x216936d3cd6e53fe, 0xc0a4e231fdd6dc5c,
              0x692cc7609525a7b2, 0xc9562d608f25d51a]
ED25519_BY = [0x6666666666666666, 0x6666666666666666,
              0x6666666666666666, 0x6666666666666658]


# ---------------------------------------------------------------------------
# signatures
# ---------------------------------------------------------------------------

class ConstSignature(object):
    """A named constant, as a sequence of fixed-width words.

    @words: the word sequence, or a zero-argument callable returning it. The
            expensive derivations are passed as callables so that importing
            this module does not compute a thousand digits of pi.
    @word_bits: the width the constant is *defined* at. What it is stored as is
                what enumerate_layouts works out.
    @category: one of CATEGORIES.
    @element_bits: restrict which stored element widths to consider. An ASCII
                   constant only ever appears as bytes, so it passes (8,).
    @include_widened: consider elements wider than the declared word, which is
                      how a byte table written as ``int[256]`` in C appears.
    @include_reversed: also consider the sequence stored backwards. Right for
                       bignum limbs, noise for a round-constant table.
    @scalar: a single value, which is far too short to search memory for
             usefully. Kept for reference and excluded from scans by default.
    """

    def __init__(self, name, words, word_bits, category, description="",
                 element_bits=None, include_widened=True,
                 include_reversed=False, scalar=False):
        if category not in CATEGORIES:
            raise ValueError("unknown category %r for %s" % (category, name))
        self.name = name
        self.word_bits = word_bits
        self.category = category
        self.description = description
        self.element_bits = element_bits
        self.include_widened = include_widened
        self.include_reversed = include_reversed
        self.scalar = scalar
        self._words = words
        self._resolved = None

    @property
    def words(self):
        if self._resolved is None:
            source = self._words
            self._resolved = list(source() if callable(source) else source)
        return self._resolved

    @property
    def word_count(self):
        return len(self.words)

    def layouts(self):
        """Every distinct byte sequence this constant can appear as."""
        kwargs = {"include_widened": self.include_widened,
                  "include_reversed": self.include_reversed}
        if self.element_bits is not None:
            kwargs["element_bits"] = self.element_bits
        return enumerate_layouts(self.words, self.word_bits, **kwargs)

    def __repr__(self):
        return "<ConstSignature %s (%d x u%d)>" % (self.name, self.word_count,
                                                   self.word_bits)


def _ascii(text):
    return list(bytearray(text.encode("ascii")))


def build_signatures():
    """Every signature this module knows about.

    Built on demand rather than at import: get_signatures() caches the result.
    """
    signatures = []

    def add(*args, **kwargs):
        signatures.append(ConstSignature(*args, **kwargs))

    def text(name, value, category, description=""):
        add(name, _ascii(value), 8, category, description,
            element_bits=(8,), include_widened=False)

    def bignum(name, limbs, category, description=""):
        add(name, limbs, 64, category, description, element_bits=(32, 64),
            include_widened=False, include_reversed=True)

    # -- hashes ------------------------------------------------------------
    add("MD4/MD5 initial state", [0x67452301, 0xefcdab89, 0x98badcfe,
                                  0x10325476], 32, "hash",
        "Also the first four words of SHA-1's initial state")
    add("MD5 sine table", md5_sine_table, 32, "hash",
        "floor(abs(sin(i+1)) * 2**32)")
    add("MD2 S-box", MD2_SBOX, 8, "hash", "Permutation built from digits of pi")
    add("SHA-1 initial state", [0x67452301, 0xefcdab89, 0x98badcfe,
                                0x10325476, 0xc3d2e1f0], 32, "hash")
    add("SHA-1 round constants", [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc,
                                  0xca62c1d6], 32, "hash",
        "frac(sqrt(2,3,5,10)) * 2**30")
    add("SHA-224 initial state", lambda: sha2_32_state(8), 32, "hash")
    add("SHA-256 initial state / BLAKE2s IV",
        lambda: sha2_32_state(0), 32, "hash",
        "frac(sqrt(p)) for the first 8 primes; BLAKE2s reuses it verbatim")
    add("SHA-256 round constants", lambda: sha2_round_constants(64, 32), 32,
        "hash", "frac(cbrt(p)) for the first 64 primes")
    add("SHA-384 initial state", lambda: sha2_64_state(8), 64, "hash")
    add("SHA-512 initial state / BLAKE2b IV",
        lambda: sha2_64_state(0), 64, "hash",
        "frac(sqrt(p)) for the first 8 primes; BLAKE2b reuses it verbatim")
    add("SHA-512/224 initial state", lambda: sha512t_state(224), 64, "hash")
    add("SHA-512/256 initial state", lambda: sha512t_state(256), 64, "hash")
    add("SHA-512 round constants", lambda: sha2_round_constants(80, 64), 64,
        "hash", "frac(cbrt(p)) for the first 80 primes")
    add("SHA-3/Keccak round constants", keccak_round_constants, 64, "hash")
    add("Keccak rho offsets", KECCAK_RHO, 8, "hash",
        "Lane rotation amounts for Keccak-f[1600]")
    add("BLAKE2 sigma", BLAKE2_SIGMA, 8, "hash",
        "Ten rounds of message permutation")
    add("SM3 initial state", SM3_IV, 32, "hash")

    # -- block and stream ciphers -----------------------------------------
    add("AES S-box", aes_sbox, 8, "cipher")
    add("AES inverse S-box", aes_inverse_sbox, 8, "cipher")
    add("AES Rcon", aes_rcon, 8, "cipher", "Key-schedule round constants")
    for rotation in range(4):
        add("AES Te%d table" % rotation,
            (lambda r: lambda: aes_te_table(r))(rotation), 32, "cipher",
            "Combined SubBytes/MixColumns encryption table")
        add("AES Td%d table" % rotation,
            (lambda r: lambda: aes_td_table(r))(rotation), 32, "cipher",
            "Combined InvSubBytes/InvMixColumns decryption table")
    add("Blowfish P-array", lambda: pi_fraction_words(18), 32, "cipher",
        "First 18 words of the fractional part of pi")
    add("Blowfish S-box 0", lambda: pi_fraction_words(274)[18:], 32, "cipher",
        "Words 19-274 of the fractional part of pi")
    add("DES initial permutation", DES_IP, 8, "cipher")
    add("DES final permutation", DES_FP, 8, "cipher")
    add("DES PC-1", DES_PC1, 8, "cipher", "Key permutation, drops parity bits")
    add("DES PC-2", DES_PC2, 8, "cipher", "Round-key compression permutation")
    add("DES expansion", DES_E, 8, "cipher")
    add("DES P permutation", DES_P, 8, "cipher")
    add("DES S-boxes", DES_SBOXES, 8, "cipher", "All eight, four rows each")
    add("SM4 S-box", SM4_SBOX, 8, "cipher")
    add("SM4 FK", [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc], 32,
        "cipher", "Key-expansion system parameters")
    add("SM4 CK", sm4_ck, 32, "cipher", "Key-expansion round constants")
    add("Camellia sigma", camellia_sigma, 64, "cipher")
    text("Salsa20/ChaCha20 sigma", "expand 32-byte k", "cipher",
         "256-bit key constant")
    text("Salsa20/ChaCha20 tau", "expand 16-byte k", "cipher",
         "128-bit key constant")

    # -- checksums ---------------------------------------------------------
    add("CRC-32 table (reflected)", lambda: crc_table(0xedb88320), 32,
        "checksum", "IEEE 802.3, as used by zlib, PNG and gzip")
    add("CRC-32 table (normal)",
        lambda: crc_table(0x04c11db7, 32, False), 32, "checksum",
        "MSB-first form of the same polynomial")
    add("CRC-32C table", lambda: crc_table(0x82f63b78), 32, "checksum",
        "Castagnoli, as used by iSCSI, ext4 and SSE4.2 CRC32")
    add("CRC-16/ARC table", lambda: crc_table(0xa001, 16), 16, "checksum",
        "IBM/ANSI, also Modbus")
    add("CRC-16/CCITT table", lambda: crc_table(0x1021, 16, False), 16,
        "checksum", "XMODEM and friends")
    add("CRC-16/CCITT table (reflected)", lambda: crc_table(0x8408, 16), 16,
        "checksum", "Kermit, X.25")
    add("CRC-64/ECMA-182 table",
        lambda: crc_table(0x42f0e1eba9ea3693, 64, False), 64, "checksum")
    add("CRC-64/XZ table", lambda: crc_table(0xc96c5795d7870f42, 64), 64,
        "checksum", "Reflected ECMA-182, as used by xz")

    # -- encodings ---------------------------------------------------------
    text("Base64 alphabet",
         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
         "encoding", "RFC 4648 standard alphabet")
    text("Base64url alphabet",
         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
         "encoding", "RFC 4648 URL and filename safe alphabet")
    text("Base32 alphabet", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "encoding")
    text("Base32hex alphabet", "0123456789ABCDEFGHIJKLMNOPQRSTUV", "encoding")

    # -- curve parameters --------------------------------------------------
    bignum("secp256k1 p", SECP256K1_P, "curve", "Field prime, 2**256-2**32-977")
    bignum("secp256k1 n", SECP256K1_N, "curve", "Group order")
    bignum("secp256k1 Gx", SECP256K1_GX, "curve", "Generator x")
    bignum("secp256k1 Gy", SECP256K1_GY, "curve", "Generator y")
    bignum("NIST P-256 p", P256_P, "curve", "Field prime")
    bignum("NIST P-256 n", P256_N, "curve", "Group order")
    bignum("NIST P-256 b", P256_B, "curve", "Curve coefficient")
    bignum("NIST P-256 Gx", P256_GX, "curve", "Generator x")
    bignum("NIST P-256 Gy", P256_GY, "curve", "Generator y")
    bignum("Curve25519 p", CURVE25519_P, "curve", "Field prime, 2**255-19")
    bignum("Curve25519 group order", CURVE25519_L, "curve",
           "2**252 + 27742317777372353535851937790883648493")
    bignum("Ed25519 d", ED25519_D, "curve", "Curve coefficient, -121665/121666")
    bignum("Ed25519 Bx", ED25519_BX, "curve", "Base point x")
    bignum("Ed25519 By", ED25519_BY, "curve", "Base point y, 4/5 mod p")

    # -- single scalars ----------------------------------------------------
    # Excluded from memory scans by default: four or eight bytes is far too
    # little to be meaningful as a byte pattern, and these mostly appear as
    # instruction immediates anyway. large_scalar_search.py and
    # find_unk_periphs.py are the right tools for those.
    def scalar(name, value, bits, description):
        add(name, [value], bits, "algorithmic", description, scalar=True)

    scalar("TEA/XTEA delta", 0x9e3779b9, 32, "Golden ratio, also Murmur/Skein")
    scalar("FNV-1 32-bit prime", 0x01000193, 32, "")
    scalar("FNV-1 32-bit offset basis", 0x811c9dc5, 32, "")
    scalar("FNV-1 64-bit prime", 0x00000100000001b3, 64, "")
    scalar("FNV-1 64-bit offset basis", 0xcbf29ce484222325, 64, "")
    scalar("xxHash32 prime 1", 0x9e3779b1, 32, "")
    scalar("xxHash64 prime 1", 0x9e3779b185ebca87, 64, "")
    scalar("MurmurHash3 c1", 0xcc9e2d51, 32, "")
    scalar("MurmurHash3 c2", 0x1b873593, 32, "")
    scalar("Adler-32 modulus", 65521, 32, "Largest prime below 2**16")
    scalar("MD5/SHA padding byte run", 0x80, 8, "Merkle-Damgard padding")

    return signatures


_SIGNATURE_CACHE = None


def get_signatures(categories=None, include_scalars=False, names=None):
    """The signature list, filtered.

    @categories: restrict to these CATEGORIES values.
    @names: restrict to signatures whose name contains one of these strings,
            matched case-insensitively.
    @include_scalars: include single-word constants, which are too short to
                      search memory for without drowning in false positives.
    """
    global _SIGNATURE_CACHE
    if _SIGNATURE_CACHE is None:
        _SIGNATURE_CACHE = build_signatures()

    selected = _SIGNATURE_CACHE
    if not include_scalars:
        selected = [s for s in selected if not s.scalar]
    if categories:
        wanted = set(categories)
        selected = [s for s in selected if s.category in wanted]
    if names:
        needles = [n.lower() for n in names]
        selected = [s for s in selected
                    if any(n in s.name.lower() for n in needles)]
    return selected
