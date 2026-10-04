#!/usr/bin/env python
"""Scan the WHOLE libsigner.so (not just .text) for known crypto constants.

The .text-only scan looked for constants materialised as mov/movk immediates.
A compiler can just as well keep an H/K array in .rodata and load it with ldr.
This scan closes that gap: it searches every byte of the file.

Also dumps the context around the two 16-byte .rodata constants (k1/k2).
"""
import struct, sys, io
from elftools.elf.elffile import ELFFile

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"

CONSTS = {
    # name -> list of 32-bit words
    "SHA1_H":   [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
    "MD5_H":    [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
    "SHA256_H": [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
    "SHA512_H": [0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b],
    "SHA1_K":   [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6],
    "SHA256_K": [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5],
    "MD5_K":    [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee],
    "CHACHA_MAGIC": [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574],
    "TEA_DELTA":    [0x9e3779b9],
    "XXH_PRIMES":   [0x9e3779b1, 0x85ebca6b, 0xc2b2ae35, 0x27d4eb2f, 0x165667b1],
    "MURMUR3":      [0xcc9e2d51, 0x1b873593],
    "SIPHASH_MAGIC": [0x736f6d65, 0x70736575],
    "AES_SBOX_HEAD":     [0x637c777b],
    "AES_INVSBOX_HEAD":  [0x52096ad5],
    "BLOWFISH_P_HEAD":   [0x243f6a88, 0x85a308d3],
    "AES_RCON":          [0x01000000, 0x02000000, 0x04000000, 0x08000000],
    "HMAC_PADS":         [0x36363636, 0x5c5c5c5c],
    "CRC32_POLY":        [0xedb88320],
    "RFC3394_IV":        [0xa6a6a6a6],
    "SM4_FK":            [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc],
}

K1 = bytes.fromhex("0123456789abcdeffedcba9876543210")
K2 = bytes.fromhex("f0e1d2c39979825aa1ebd96edcbc1b8f")


def main():
    data = open(SO, "rb").read()
    f = io.BytesIO(data)
    elf = ELFFile(f)
    # build offset -> "secname+delta" map (file offset, not vaddr)
    secs = []
    for s in elf.iter_sections():
        if s["sh_type"] in ("SHT_NOBITS", "SHT_NULL"):
            continue
        off, sz = s["sh_offset"], s["sh_size"]
        secs.append((off, off + sz, s.name))
    secs.sort()

    def where(off):
        for a, b, n in secs:
            if a <= off < b:
                return "%s+0x%x" % (n, off - a)
        return "?"

    out = io.open(__file__.replace(".py", ".txt"), "w", encoding="utf8")
    out.write("libsigner.so size=0x%x (%d bytes)\n\n" % (len(data), len(data)))

    out.write("=== known crypto constants, whole-file scan (little-endian) ===\n")
    for name, words in sorted(CONSTS.items()):
        hits = []
        for w in words:
            pat = struct.pack("<I", w)
            start = 0
            while True:
                i = data.find(pat, start)
                if i < 0:
                    break
                hits.append((i, w, where(i)))
                start = i + 1
        found = set(w for _, w, _ in hits)
        out.write("\n%-16s %d/%d words found\n" % (name, len(found), len(words)))
        for off, w, sec in hits[:24]:
            out.write("    0x%08x  %08x  %s\n" % (off, w, sec))
        if len(hits) > 24:
            out.write("    ... %d more\n" % (len(hits) - 24))

    out.write("\n\n=== the two 16-byte .rodata constants (k1 / k2) ===\n")
    for nm, k in (("k1", K1), ("k2", K2)):
        off = data.find(k)
        out.write("\n%s %s  at file offset 0x%x  (%s)\n" % (nm, k.hex(), off, where(off) if off >= 0 else "NOT FOUND"))
        if off < 0:
            continue
        lo = max(0, off - 0x120)
        hi = min(len(data), off + 0x140)
        chunk = data[lo:hi]
        for i in range(0, len(chunk), 16):
            row = chunk[i:i + 16]
            mark = "  <<<" if lo + i <= off < lo + i + 16 else ""
            out.write("  0x%08x  %-47s |%s|%s\n" % (
                lo + i, row.hex(),
                "".join(chr(c) if 32 <= c < 127 else "." for c in row), mark))

    out.write("\n\n=== is there an array of >=8 consecutive 'random-looking' dwords? ===\n")
    out.write("(heuristic: find 64-byte runs with 60+ distinct byte values,\n")
    out.write(" i.e. real K/H tables rather than code/strings)\n")
    n = 0
    for off in range(0, len(data) - 64, 16):
        row = data[off:off + 64]
        if len(set(row)) >= 58 and sum(1 for b in row if 32 <= b < 127) < 12:
            n += 1
            if n <= 40:
                out.write("  0x%08x %s  %s\n" % (off, where(off), row[:16].hex() + "..."))
    out.write("  total 64B high-entropy runs: %d\n" % n)
    out.close()
    print("wrote", __file__.replace(".py", ".txt"))


if __name__ == "__main__":
    main()
