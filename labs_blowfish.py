#!/usr/bin/env python3
"""
labs_blowfish.py — the cipher for LABS content files.

A LABS content file (.zmulti / .zpreset / .zconfig,
including .patches.zconfig and .presets.zconfig) is:

    [ 4-byte header: 00 08 00 00 ][ Blowfish-ECB ciphertext ]

Details that matter for byte-exact output:
  * Cipher    : Blowfish, ECB mode, 8-byte blocks.
  * Word order: LITTLE-ENDIAN within each 8-byte block (JUCE reads each block as
                two native-endian uint32s; macOS is little-endian). This is the
                non-obvious bit — the standard Blowfish test vectors are
                big-endian, but LABS files are little-endian.
  * Padding   : PKCS#7 with block size 8 (so plaintext always ends on an 8-byte
                boundary; if it's already a multiple of 8, a whole extra block
                of 0x08 is appended). The plugin strips this after decrypting.
  * Key       : a 64-byte value derived from the machine (MAC + other machine
                identifiers). Blowfish libraries cap keys at 56 bytes, therefore
                this Blowfish implementation is modified to accept 64 bytes.
"""
from mpmath import mp

MAGIC = b"\x00\x08\x00\x00"   # 4-byte file header
_MASK = 0xFFFFFFFF


# --- Blowfish initial tables, derived from the fractional hex digits of pi -----
def _pi_hex_words(nwords):
    bits = 32 * nwords
    mp.prec = bits + 64                      # a few guard bits
    frac = int((mp.pi - 3) * mp.mpf(2) ** bits)   # fractional part as a big int
    return [(frac >> (32 * (nwords - 1 - i))) & _MASK for i in range(nwords)]


_W = _pi_hex_words(18 + 4 * 256)
assert _W[0] == 0x243F6A88, "pi-table generation failed"
_P0 = _W[:18]
_S0 = [_W[18 + i * 256: 18 + (i + 1) * 256] for i in range(4)]


class Blowfish:
    """Standard Blowfish. Verified against the canonical all-zero test vector."""

    def __init__(self, key: bytes):
        assert len(key) > 0
        self.P = _P0[:]
        self.S = [b[:] for b in _S0]
        j = 0
        for i in range(18):
            d = 0
            for _ in range(4):
                d = ((d << 8) | key[j]) & _MASK
                j = (j + 1) % len(key)
            self.P[i] ^= d
        l = r = 0
        for i in range(0, 18, 2):
            l, r = self._enc(l, r); self.P[i] = l; self.P[i + 1] = r
        for bi in range(4):
            for k in range(0, 256, 2):
                l, r = self._enc(l, r); self.S[bi][k] = l; self.S[bi][k + 1] = r

    def _f(self, x):
        return ((((self.S[0][(x >> 24) & 0xFF] + self.S[1][(x >> 16) & 0xFF]) & _MASK)
                 ^ self.S[2][(x >> 8) & 0xFF]) + self.S[3][x & 0xFF]) & _MASK

    def _enc(self, l, r):
        for i in range(16):
            l ^= self.P[i]; r ^= self._f(l); l, r = r, l
        l, r = r, l
        r ^= self.P[16]; l ^= self.P[17]
        return l & _MASK, r & _MASK

    def _dec(self, l, r):
        for i in range(17, 1, -1):
            l ^= self.P[i]; r ^= self._f(l); l, r = r, l
        l, r = r, l
        r ^= self.P[1]; l ^= self.P[0]
        return l & _MASK, r & _MASK

    # ECB over a buffer that is a whole number of 8-byte blocks. LITTLE-ENDIAN.
    def decrypt_ecb(self, data: bytes) -> bytes:
        import struct
        out = bytearray()
        for i in range(0, len(data) - len(data) % 8, 8):
            l, r = struct.unpack("<II", data[i:i + 8])
            l, r = self._dec(l, r)
            out += struct.pack("<II", l, r)
        return bytes(out)

    def encrypt_ecb(self, data: bytes) -> bytes:
        import struct
        assert len(data) % 8 == 0, "encrypt_ecb needs a multiple of 8 bytes"
        out = bytearray()
        for i in range(0, len(data), 8):
            l, r = struct.unpack("<II", data[i:i + 8])
            l, r = self._enc(l, r)
            out += struct.pack("<II", l, r)
        return bytes(out)


# --- PKCS#7 padding (block size 8) --------------------------------------------
def pkcs7_pad(data: bytes) -> bytes:
    n = 8 - (len(data) % 8)          # 1..8 (a full block when already aligned)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 8 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data                       # not padded the way we expect; leave as-is


# --- Chunked file format -------------------------------------------------------
# A LABS file is NOT one ECB stream. The 4-byte header is a little-endian uint32
# giving the plaintext CHUNK size (always 2048 = 0x00000800, i.e. the bytes
# `00 08 00 00`). The plaintext is split into chunks of that many bytes; each
# chunk is PKCS#7-padded to a multiple of 8 and Blowfish-ECB-encrypted on its
# own; the encrypted chunks are concatenated after the header. So a full 2048-byte
# chunk becomes 2056 encrypted bytes (2048 + a full 0x08 pad block), and the
# final (short) chunk is padded to the next multiple of 8.
import struct as _struct

CHUNK = 2048  # plaintext bytes per chunk (what the plugin writes)


def _enc_chunk_len(chunk: int) -> int:
    """Encrypted size of one FULL plaintext chunk (chunk + its PKCS#7 padding)."""
    return chunk + (8 - (chunk % 8) if chunk % 8 else 8)


def decrypt_bytes(file_bytes: bytes, key: bytes) -> bytes:
    """LABS encrypted file bytes -> clean plaintext (JSON), all padding removed."""
    if file_bytes[:4] != MAGIC:
        raise ValueError("not a LABS encrypted file (missing 00 08 00 00 header)")
    chunk = _struct.unpack("<I", file_bytes[:4])[0]
    body = file_bytes[4:]
    bf = Blowfish(key)
    step = _enc_chunk_len(chunk)                          # encrypted full-chunk size
    out = bytearray()
    for i in range(0, len(body), step):
        seg = body[i:i + step]                            # last seg may be shorter
        out += pkcs7_unpad(bf.decrypt_ecb(seg))
    return bytes(out)


def encrypt_bytes(plaintext: bytes, key: bytes, chunk: int = CHUNK) -> bytes:
    """Clean plaintext (JSON) -> LABS encrypted file bytes (header + chunked cipher)."""
    bf = Blowfish(key)
    body = bytearray()
    for i in range(0, len(plaintext), chunk):
        piece = plaintext[i:i + chunk]
        body += bf.encrypt_ecb(pkcs7_pad(piece))
    return _struct.pack("<I", chunk) + bytes(body)


def is_encrypted(file_bytes: bytes) -> bool:
    return file_bytes[:4] == MAGIC
