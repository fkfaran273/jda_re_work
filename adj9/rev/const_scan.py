"""const_scan.py - are #0/#2/#4's dwords ROM constants inside libsigner.so?

#0 = [W0][C1][C2][C3][W1][C1][C2][C3] x8  (region_struct.log). If C1..C3 (and part
of #4) live in the .so as literals, then most of the "unknown region" is not
per-call data at all - only W0/W1 (#2, #4's varying part) need reproducing. This
scan searches the whole .so for each observed dword (LE and BE) and reports where
it sits (section + offset) plus the surrounding 32 bytes."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
E = ELF(SO)
d = E.data


def sec_of(off):
    for s in E.sections:
        if s["size"] and s["offset"] <= off < s["offset"] + s["size"]:
            return s["name"], s["addr"] + (off - s["offset"])
    return "?", None


SAMPLES = {
    "golden #0": "13271271db50f44cb63798ccdab7f51ab7d0992bdb50f44cb63798ccdab7f51a",
    "det[1] #0": "aa447d3c2ec65f51efdf3cd88c5688294d4f9e482ec65f51efdf3cd88c568829",
    "golden #4": "00100400041440008000c44088104c050025c852cc6e00b101e76c80427bf58e",
    "det[1] #4": "04000500800084409540410065400448714af5c887c875e8a2906389b08e8c8b",
    "golden #2": "fb1a8296",
    "det[1] #2": "7c933329",
}

# word-by-word: which individual dwords are ROM literals?
print("=== per-dword ROM search ===")
words = {}
for tag, hx in SAMPLES.items():
    b = bytes.fromhex(hx)
    ws = [b[i:i + 4] for i in range(0, len(b), 4)]
    words[tag] = ws
    for i, w in enumerate(ws):
        hits = []
        for pat, name in ((w, "LE"), (w[::-1], "BE")):
            pos = 0
            while True:
                j = d.find(pat, pos)
                if j < 0:
                    break
                sn, va = sec_of(j)
                hits.append((name, sn, j, va))
                pos = j + 1
                if len(hits) > 6:
                    break
        label = "%s.dw%d" % (tag, i)
        if hits:
            print("%-14s %s  %d hit(s): %s" % (label, w.hex(),
                                               len(hits),
                                               ", ".join("%s@%s" % (h[1], hex(h[2]))
                                                         for h in hits[:5])))
        else:
            print("%-14s %s  no ROM literal" % (label, w.hex()))

# does the CONSTANT TRIAD appear contiguously anywhere? (would prove a ROM record)
print("\n=== contiguous ROM search (whole observed runs) ===")
for tag, hx in SAMPLES.items():
    b = bytes.fromhex(hx)
    for run in (b, b[:16], b[4:16], b[16:32]):
        if len(run) < 8:
            continue
        j = d.find(run)
        if j >= 0:
            sn, va = sec_of(j)
            print("  %-12s run len=%d FOUND at %s+0x%x (%s)"
                  % (tag, len(run), sn, j, hex(j)))
            break
    else:
        print("  %-12s no contiguous ROM match" % tag)

# where does the .so keep big literal tables? list .data/.rodata/0x155 pages sizes
print("\n=== table-ish regions ===")
for sn in (".data", ".rodata", ".data.rel.ro", ".bss"):
    s = E.byname.get(sn)
    if s:
        print("  %-14s va=0x%-8x off=0x%-8x size=0x%x" % (sn, s["addr"], s["offset"],
                                                          s["size"]))
print("done")