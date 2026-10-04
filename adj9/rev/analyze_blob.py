"""analyze_blob.py - locate the pair-XOR rand words inside the emulated 208-B
blob; compare blob structure vs the captured device signing.
"""
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def blob_from_log(path):
    txt = open(path).read()
    m = re.search(r"blob\[(\d+)\]:\n((?:    .*\n)+)", txt)
    rows = []
    for line in m.group(2).splitlines():
        hexpart = line.strip().split("  ")[1]
        rows.append(hexpart.replace(" ", ""))
    return bytes.fromhex("".join(rows))


def ansi(seed):
    s = seed & 0xFFFFFFFF
    while True:
        s = (s * 1103515245 + 12345) & 0x7FFFFFFF
        yield s


def lrand48(seed):
    s = ((seed << 16) | 0x330E) & ((1 << 48) - 1)
    while True:
        s = (s * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        yield s >> 17


def main():
    blob = blob_from_log(os.path.join(HERE, "report2.log"))
    print("blob len:", len(blob))

    draws = [221894137, 2020092222, 618570655, 1956662508,
             1782110389, 490314570, 1679022779, 1354451928]
    # verify LCG: srand(1789240512), ansi
    g = ansi(1789240512)
    seq = [next(g) for _ in range(8)]
    print("ansi LCG srand(1789240512) first 8:", seq)
    print("match observed:", seq == draws)
    gl = lrand48(1789240512)
    print("lrand48 first 8:", [next(gl) for _ in range(8)])

    pairs = [draws[i] ^ draws[i + 1] for i in range(0, 8, 2)]
    print("pair-XOR units (u32):", [hex(p) for p in pairs])

    for i, p in enumerate(pairs):
        for off in range(0, len(blob) - 3):
            w = struct.unpack_from("<I", blob, off)[0]
            if w == p:
                print("  u%d = 0x%08x found LE at blob+0x%03x" % (i, p, off))
            if struct.pack(">I", p) == blob[off:off + 4]:
                print("  u%d = 0x%08x found BE at blob+0x%03x" % (i, p, off))


if __name__ == "__main__":
    main()
