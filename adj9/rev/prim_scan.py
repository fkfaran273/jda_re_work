#!/usr/bin/env python3
"""Fingerprint crypto primitives inside libsigner.so builds."""
import struct, sys, os, re

PRIMS = {
 "AES S-box":        bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"),
 "AES S-box mid":    bytes.fromhex("52edfec5481e2c33d0e0c6bfe8bc9d2c"),
 "AES InvS-box":     bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"),
 "AES Rcon":         bytes.fromhex("01020408102040801b36"),
 "ChaCha sigma":     b"expand 32-byte k",
 "ChaCha sigma2":    b"expand 16-byte k",
 "SHA256 K[0..3]":   struct.pack(">IIII", 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5),
 "SHA256 K[60..63]": struct.pack(">IIII", 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2),
 "SHA512 K[0..3]":   struct.pack(">QQQQ", 0x428a2f98d728ae22, 0x7137449123ef65cd,
                                 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc),
 "SHA1 init":        struct.pack(">IIIII", 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0),
 "MD5 init":         struct.pack(">IIII", 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476),
 "RC4-none":         b"",
 "TEA delta":        struct.pack(">I", 0x9e3779b9),
 "XTEA delta":       struct.pack(">I", 0x9e3779b9),
 "Blowfish P[0..1]": struct.pack(">QQ", 0x243f6a8885a308d3, 0x13198a2e03707344),
 "CRC32 poly":       struct.pack(">I", 0xedb88320),
 "Base64 alphabet":  b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
 "RSA65537":         struct.pack(">I", 65537),
}

def segs_of(d):
    is64 = d[4] == 2
    if is64:
        e_phoff, = struct.unpack_from("<Q", d, 0x20)
        e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
    else:
        e_phoff, = struct.unpack_from("<I", d, 0x1c)
        e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x2a)
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if is64:
            p_type, p_flags, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<IIQQQQQQ", d, o)
        else:
            p_type, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from("<IIIIIIII", d, o)
        if p_type == 1:
            out.append((p_vaddr, p_off, p_filesz))
    return out

files = sys.argv[1:]
for fn in files:
    d = open(fn, "rb").read()
    print("=== %s (%d bytes)" % (fn, len(d)))
    for name, sig in PRIMS.items():
        if not sig:
            continue
        hits = []
        i = d.find(sig)
        while i >= 0 and len(hits) < 4:
            hits.append(hex(i)); i = d.find(sig, i + 1)
        if hits:
            print("   %-18s %s" % (name, " ".join(hits)))
    # look for a 256-byte table that is a permutation 0..255 (RC4/serpent etc)
    print()
