"""commit2_extract.py — map the 3.62.0 VM program structures in snap_A/B/C.

Extracts:
  * every copy of the word-swapped claims buffer (swap4(claims)) with offsets
  * the full ~2.5-3 KB program structure starting at each c20 offset
  * the byte-exact A-vs-C diff map (claims-derived words inside the program)

    python commit2_extract.py
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "adj7_work"))

import adj7_signer as sg

HEAP = 0x9000000
C20 = bytes.fromhex("6cffea5110a9940910e85257b51dc608c577c522")
C32 = bytes.fromhex("095ccb389439543bf3bad2abc05e42aab2994c5a7c2084aeeb899e6d1ee1656b")
C20_C = bytes.fromhex("40be5d7051dc85a45bec0d823269547ed52d64de")
C32_C = bytes.fromhex("a8c5b456892afa100bb79c30b9aa5cf001ff667982fa436e80c8cab393fd1f65")
C20_OFFS = [0x900bb84, 0x900c574, 0x900cf84, 0x900db94]
C32_OFFS = [0x900be98, 0x900c888, 0x900d298, 0x900dea8]


def swapN(b, n):
    out = bytearray()
    for i in range(0, len(b) - len(b) % n, n):
        out += b[i:i + n][::-1]
    return bytes(out) + b[len(b) - len(b) % n:]


def find_all(snap, pat, lo=0, hi=None):
    out, i = [], lo
    hi = hi if hi is not None else len(snap)
    while True:
        i = snap.find(pat, i, hi + len(pat))
        if i == -1:
            return out
        out.append(i)
        i += 1


def diff_clusters(a, b, gap=4, lo=0, hi=None):
    hi = hi if hi is not None else min(len(a), len(b))
    d = [i for i in range(lo, hi) if a[i] != b[i]]
    if not d:
        return []
    out, st, prev = [], d[0], d[0]
    for x in d[1:]:
        if x - prev > gap:
            out.append((st, prev - st + 1))
            st = x
        prev = x
    out.append((st, prev - st + 1))
    return out


def main():
    snapA = open(os.path.join(HERE, "snap_A.bin"), "rb").read()
    snapB = open(os.path.join(HERE, "snap_B.bin"), "rb").read()
    snapC = open(os.path.join(HERE, "snap_C.bin"), "rb").read()
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(ROOT, "adj7_work", "adj7b_bodies.json")))}
    params = dict(bodies["0015"]["body_params_dict"])
    claims = sg.build_claims("session", params)
    claimsC = sg.build_claims("session", dict(params, app_version="9.9.9"))
    sw4, sw4c = swapN(claims, 4), swapN(claimsC, 4)
    sha0 = hashlib.sha256(b"").digest()

    print("claims len", len(claims))
    print("raw-claims copies in A:", [hex(HEAP + i) for i in find_all(snapA, claims)])
    print("sw4-claims copies in A:", [hex(HEAP + i) for i in find_all(snapA, sw4)])
    print("sw4-claims copies in C:", [hex(HEAP + i) for i in find_all(snapC, sw4c)])
    print("c20A copies:", [hex(HEAP + i) for i in find_all(snapA, C20)])
    print("c32A copies:", [hex(HEAP + i) for i in find_all(snapA, C32)])
    print("c20C copies:", [hex(HEAP + i) for i in find_all(snapC, C20_C)])
    print("c32C copies:", [hex(HEAP + i) for i in find_all(snapC, C32_C)])

    # ---- A vs C diff map over the whole snapshot ----
    print("\n=== A-vs-C diff clusters (gap<=4) ===")
    for st, ln in diff_clusters(snapA, snapC):
        rel = st - (C20_OFFS[0] - HEAP)
        tag = ""
        for base in C20_OFFS:
            r = st - (base - HEAP)
            if 0 <= r < 0xC00:
                tag = " prog@%#x+%#x" % (base, r)
        print("  %#x len %4d%s" % (HEAP + st, ln, tag))

    # ---- program structure extraction (structure 1) ----
    P0 = C20_OFFS[0] - HEAP
    print("\n=== program structure 1 @%#x (0x900bb74 head16 .. end of padding) ===" % C20_OFFS[0])
    print("head16[-16:0):", snapA[P0 - 16:P0].hex())
    print("c20 @+0:", snapA[P0:P0 + 20].hex())
    print("c20 C  :", snapC[P0:P0 + 20].hex())

    # hexdump structure 1 from head16 to 0x900bdff and from 0x900be00 to 0x900bf40
    def hd(lo, hi, step=32):
        o = lo - HEAP
        for a in range(lo, hi, step):
            r = a - (C20_OFFS[0])
            print("  %#x %+5d  %s  %s" % (
                a, a - C20_OFFS[0],
                snapA[a - HEAP:a - HEAP + step].hex(),
                "".join(chr(c) if 32 <= c < 127 else "." for c in snapA[a - HEAP:a - HEAP + step])))

    print("\n-- head .. claims region --")
    hd(0x900bb60, 0x900bd20)
    print("\n-- c32 region --")
    hd(0x900be60, 0x900bf00)

    # where does the padding after the in-structure claims end?
    o = 0x900bc0c - HEAP
    tail = snapA[o + 344:o + 344 + 48]
    print("\npadding after in-struct sw4-claims:", tail.hex())

    # A vs B: the 16-B time head before each c20
    print("\n=== A-vs-B diff clusters (structure region only) ===")
    for st, ln in diff_clusters(snapA, snapB, lo=0x900b600 - HEAP, hi=0x900f250 - HEAP):
        print("  %#x len %d  A %s B %s" % (HEAP + st, ln,
              snapA[st:st + ln].hex(), snapB[st:st + ln].hex()))

    # save the extracted program structures for the hunt script
    progA = snapA[P0 - 16:P0 + 0x9F0 - 16]
    progC = snapC[P0 - 16:P0 + 0x9F0 - 16]
    open(os.path.join(HERE, "commit2_progA.bin"), "wb").write(progA)
    open(os.path.join(HERE, "commit2_progC.bin"), "wb").write(progC)
    json.dump({
        "claims": claims.decode("latin1"),
        "claimsC": claimsC.decode("latin1"),
        "sw4": sw4.hex(), "sw4C": sw4c.hex(),
        "c20A": C20.hex(), "c32A": C32.hex(), "c20C": C20_C.hex(), "c32C": C32_C.hex(),
        "prog_offsets": {"c20": C20_OFFS, "c32": C32_OFFS},
    }, open(os.path.join(HERE, "commit2_ctx.json"), "w"))
    print("\nsaved commit2_progA.bin / commit2_progC.bin / commit2_ctx.json")


if __name__ == "__main__":
    main()
