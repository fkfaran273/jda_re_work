"""scan_s.py — inspect stream 0x5450001000 (the cipher's table RAM)."""
import sys, os, pickle
from collections import Counter, defaultdict
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "pure_signer"))
from pure_sign import KB as KB_REF, T as T_REF

kb55 = bytes(v ^ 0x55 for v in KB_REF)
t55 = bytes(v ^ 0x55 for v in T_REF)

def variants(ref, name):
    out = [(name, ref)]
    out.append((name + "^55", bytes(v ^ 0x55 for v in ref)))
    return out

def packings(b4):
    """yield transformed 4-byte views of a dword byte-string"""
    yield b4                                    # LE storage
    yield b4[::-1]                              # BE storage
    yield b4[2:4] + b4[0:2]                     # rev16-of-LE
    yield b4[1:3] + b4[0:1] + b4[3:4]           # rot8
    yield b4[3:4] + b4[0:3]                     # rot8 other

with open(os.path.join(HERE, "trace_q.pkl"), "rb") as f:
    d = pickle.load(f)

sva = 0x5450001000
offs = d["streams"][sva]
idxs = sorted(offs)
print("stream %x: %d entries, idx range %d..%d, dense=%s"
      % (sva, len(idxs), idxs[0], idxs[-1],
         all(idxs[i] == idxs[i - 1] + 1 for i in range(1, len(idxs)))))
vals = [offs[i] for i in idxs]
print("value width histogram (top):", Counter(
    "8b" if v < 256 else ("16b" if v < 65536 else ("24b" if v < 1 << 24 else "32b"))
    for v in vals).most_common(6))

byys = b"".join(v.to_bytes(4, "little") for v in vals)
byys_be = b"".join(v.to_bytes(4, "big") for v in vals)
print("LE-stream bytes: %d, max val %x" % (len(byys), max(vals)))

for name, ref in variants(T_REF, "T") + variants(KB_REF, "KB"):
    for end, bys in (("le", byys), ("be", byys_be)):
        pos = bys.find(ref)
        if pos >= 0:
            print("FOUND %s in stream as %s at byte %d (idx %d)"
                  % (name, end, pos, pos // 4))
        # 4-gram scan for fragmented presence
    hits = 0
    firsts = []
    for off in range(0, len(ref) - 3):
        g = ref[off:off + 4]
        for pk in packings(g):
            p = byys.find(pk)
            if p >= 0 and p % 4 == 0:
                hits += 1
                if len(firsts) < 4:
                    firsts.append((off, p, pk.hex()))
                break
    print("  %s: %d/237 dword-aligned 4-grams present; e.g. %s"
          % (name, hits, firsts))

# how do lenq reads at 0x1119f4 map to idxs? dump first 40 reads there
print("== lenq@1119f4 first 40 reads (pc, idx, ret):")
n = 0
for (p, s, i, ret) in d["lenqs"]:
    if p == 0x1119f4:
        print("   idx=%d ret=%02x" % (i, ret))
        n += 1
        if n >= 40:
            break

# who WRITES stream 0x5450001000 (emit events), first 30
print("== emits to %x first 30 (pc, idx, val):" % sva)
n = 0
for (p, s, i, v) in d["emits"]:
    if s == sva:
        print("   pc=%x idx=%d val=%x" % (p, i, v))
        n += 1
        if n >= 30:
            break
