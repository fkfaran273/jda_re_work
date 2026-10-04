"""Map every descriptor field -> the body word ranges it can move.

Baseline = corpus row 4 (self-consistent, blob known).  One field changed at
a time; the diff over the 44 body words is the field's reach.
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as M

a = json.load(open(os.path.join(HERE, "all_signings.json")))
p = json.load(open(os.path.join(HERE, "pair_h3.json")))
ORDER = M.VA_ORDER
R, P = 4, 4

def raw(r, ov=None):
    ov = ov or {}
    d = {}
    for bi in ORDER:
        hx = r.get("d%d" % bi, "")
        d[bi] = ov[bi] if bi in ov else bytes.fromhex(hx)
    return d

def descs(d):
    return [(len(d[bi]) // 4, 0, d[bi][:(len(d[bi]) // 4) * 4]) for bi in ORDER]

def mint(d, second):
    blob, info = M.finex_mint(descs(d), second, max_steps=60_000_000)
    return list(struct.unpack(">48I", blob))

base_d = raw(a[R])
tgt = list(struct.unpack(">48I", bytes.fromhex(p[P]["blob"])))
second = int(p[P]["second"])
got = mint(base_d, second)
print("BASELINE match %d/48" % (48 - sum(1 for j in range(48) if got[j] != tgt[j])), flush=True)
BASE_BODY = got[4:]

def ranges(idxs):
    if not idxs:
        return "-"
    res, s, prev = [], idxs[0], None
    for k in idxs:
        if prev is not None and k != prev + 1:
            res.append((s, prev)); s = k
        prev = k
    res.append((s, prev))
    return ",".join("%d" % a if a == b else "%d-%d" % (a, b) for a, b in res)

def flip_byte(buf, off=0):
    b = bytearray(buf); b[off] ^= 0x01
    return bytes(b)

TESTS = []
TESTS.append(("d10 claims (byte 0 of 360)", {10: flip_byte(base_d[10], 0)}))
TESTS.append(("d10 claims (byte 200)", {10: flip_byte(base_d[10], 200)}))
TESTS.append(("d7  =len(d10)", {7: struct.pack(">I", 361)}))
TESTS.append(("d9  cert SHA-1", {9: flip_byte(base_d[9], 0)}))
TESTS.append(("d8  16-B constants", {8: flip_byte(base_d[8], 0)}))
TESTS.append(("d5  zero word", {5: struct.pack(">I", 1)}))
TESTS.append(("d6  zero word", {6: struct.pack(">I", 1)}))
TESTS.append(("d0  region word0 (W0)", {0: flip_byte(base_d[0], 0)}))
TESTS.append(("d0  region word1 (X)", {0: flip_byte(base_d[0], 4)}))
TESTS.append(("d0  region word2 (cycle)", {0: flip_byte(base_d[0], 8)}))
TESTS.append(("d0  region word3 (cycle)", {0: flip_byte(base_d[0], 12)}))
TESTS.append(("d0  region word35 (cycle tail)", {0: flip_byte(base_d[0], 140)}))
TESTS.append(("d2  seed word", {2: flip_byte(base_d[2], 0)}))
TESTS.append(("d4  region word0", {4: flip_byte(base_d[4], 0)}))
TESTS.append(("d4  region word7", {4: flip_byte(base_d[4], 28)}))

for tag, ov in TESTS:
    d = dict(base_d); d.update(ov)
    b = mint(d, second)[4:]
    diff = [j for j in range(44) if b[j] != BASE_BODY[j]]
    hdiff = (len(diff) and True)
    print("%-32s -> body words changed: %2d/44  [%s]%s"
          % (tag, len(diff), ranges(diff) if diff else "-",
             "" if len(diff) == 44 else "   <<< PARTIAL REACH"), flush=True)
