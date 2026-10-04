"""Search .text for crypto constants materialised as mov/movk immediates
(O-LLVM constant-hiding: no tables in .rodata, so table scans miss them)."""
import os
import sys
from collections import defaultdict

import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF  # noqa: E402
from decryptors import LIB  # noqa: E402

SHA1_K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
SHA1_H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
SHA256_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]
SHA256_H = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
MD5_K = [0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A,
         0xA8304613, 0xFD469501, 0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
         0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821, 0xF61E2562, 0xC040B340,
         0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
         0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8,
         0x676F02D9, 0x8D2A4C8A, 0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
         0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70, 0x289B7EC6, 0xEAA127FA,
         0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
         0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92,
         0xFFEFF47D, 0x85845DD1, 0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
         0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391]
MD5_H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
MD5_S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4

GROUPS = {
    "SHA1_K": SHA1_K, "SHA1_H": SHA1_H,
    "SHA256_K": SHA256_K, "SHA256_H": SHA256_H,
    "MD5_K": MD5_K, "MD5_H": MD5_H,
}


def main():
    e = ELF(LIB)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    t = e.byname[".text"]
    off0 = e.vaddr_to_off(t["addr"])
    code = e.data[off0:off0 + t["size"]]

    # map 16-bit half -> (group, full value, which half)
    halfmap = defaultdict(list)
    for g, vals in GROUPS.items():
        for v in vals:
            halfmap[v & 0xFFFF].append((g, v, "lo"))
            halfmap[(v >> 16) & 0xFFFF].append((g, v, "hi"))

    hits = defaultdict(lambda: defaultdict(list))
    for i in md.disasm(code, t["addr"]):
        if i.mnemonic not in ("mov", "movk", "movz", "movn", "orr"):
            continue
        for op in i.operands:
            if op.type != capstone.arm64.ARM64_OP_IMM:
                continue
            imm = op.imm
            if imm > 0xFFFF:
                continue
            shift = (op.shift.value if op.shift.type else 0)
            for (g, v, h) in halfmap.get(imm, []):
                expected = 16 if h == "hi" else 0
                if shift == expected:
                    hits[g][v].append(i.address)

    print("=== crypto constants materialised in .text (mov/movk immediates) ===\n")
    for g, vals in GROUPS.items():
        got = hits[g]
        tot = sum(len(a) for a in got.values())
        print("%-10s : %d/%d distinct constants, %d sites" % (g, len(got), len(set(vals)), tot))
        for v in sorted(got, key=lambda x: -len(got[x]))[:8]:
            print("    0x%08x  %3d site(s)  first @ 0x%x" % (v, len(got[v]), got[v][0]))
        if got:
            alladdr = sorted(a for v in got for a in got[v])
            # cluster
            clusters = []
            cur = [alladdr[0]]
            for a in alladdr[1:]:
                if a - cur[-1] <= 0x4000:
                    cur.append(a)
                else:
                    clusters.append(cur)
                    cur = [a]
            clusters.append(cur)
            clusters.sort(key=len, reverse=True)
            print("    top clusters:")
            for c in clusters[:5]:
                print("      0x%x - 0x%x  (%d sites)" % (c[0], c[-1], len(c)))
        print()

    # MD5 shift amounts are too generic; skip. AES sbox would be 256 distinct bytes
    # -> look for a 256-byte bijective table anywhere in the file
    for sec in (".rodata", ".data.rel.ro", ".data", ".bss"):
        try:
            b = e.section_bytes(sec)
        except Exception:
            continue
        for i in range(0, max(0, len(b) - 256), 16):
            chunk = b[i:i + 256]
            if len(chunk) == 256 and len(set(chunk)) == 256:
                print("!! 256-byte bijection (possible AES S-box) in %s @ +0x%x" % (sec, i))


if __name__ == "__main__":
    main()
