"""app_fin3.py - decode the FRESH capture (app_dump.json) end to end.

Steps:
 1. segment the emit plane by the pos-0 rule (slice 122);
 2. find the segment that holds a 48-word blob + the descriptor roles
    (#0 36w, #9 5w, #8 4w, #4 8w, #2 1w, #7 1w, #10 90..97w);
 3. invert the blob header with the Random3 law -> signing second;
 4. feed the descriptors (va_order) into FinEx and require BYTE-EXACT.
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from fin_vm2 import FinEx
from header_gen import make_header, Random3
ORDER = json.load(open(os.path.join(HERE, "adj9_material.json")))["va_order"]

d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
print("nemit=%d nlenq=%d nblobs=%d" % (d["nemit"], d["nlenq"], len(d.get("blobs", []))))


def segment(rows):
    segs, cur = [], {}
    for st, n, v in rows:
        if n == 0 and st in cur and cur[st]:
            segs.append(cur)
            cur = {}
        cur.setdefault(st, {})[n] = v
    segs.append(cur)
    return segs


segs = segment([(st, n, v) for st, n, v in d["emits"]])
print("segments: %d" % len(segs))

CONST9 = "fad0f10d60f93c17937b2f1eb6c09691ae7d74bd"
CONST8 = "bffffffffffffd1f0007000000000000"


def b(vs):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in vs)


def words_of(hexs):
    raw = bytes.fromhex(hexs)
    return [int.from_bytes(raw[j:j+4], "big") for j in range(0, len(raw), 4)]


best = None
for k, seg in enumerate(segs):
    byc = {}
    for st, m in seg.items():
        byc.setdefault(len(m), []).append([m[i] for i in sorted(m)])
    have = {c: (len(byc.get(c, [])) > 0) for c in (36, 48, 8, 5, 4, 1)}
    if not all(have.values()):
        continue
    # blob candidate = 48-word stream whose first 4 words match Random3(s) for
    # some second around the record; invert by brute force over a window.
    for vs in byc[48]:
        hdr = b(vs[:4])
        sec = None
        for s in range(1789000000, 1791000000):
            if make_header(s) == hdr:
                sec = s
                break
        if sec is None:
            continue
        best = (k, seg, vs, sec)
        break
    if best:
        break

if not best:
    print("no segment with an inverted header found")
    raise SystemExit(1)

k, seg, blob48, sec = best
print("segment %d  blob second=%d (header law)" % (k, sec))
byc = {}
for st, m in seg.items():
    byc.setdefault(len(m), []).append([m[i] for i in sorted(m)])
print("  stream sizes:", sorted(len(v) for v in seg.values()))


def pick(cnt, pred=None):
    out = [vs for vs in byc.get(cnt, []) if pred is None or pred(vs)]
    return out


z0 = pick(36)
z4 = pick(8)
z9 = pick(5)
z8 = pick(4)
z2 = [vs[0] for vs in pick(1)]
z10 = pick(97) or pick(96) or pick(90) or pick(84)
print("  #0 cands=%d #4=%d #9=%d #8=%d #10=%s" %
      (len(z0), len(z4), len(z9), len(z8), [len(v) for v in z10]))
if not (z0 and z4 and z9 and z8 and z10):
    print("  !! missing a role -- dumping all singles: %s" % [("%08x" % x) for x in z2])
    raise SystemExit(1)

# #9 must equal the constant; #8 too (both session+click constants so far)
z9v = [v for v in z9 if b(v[:5]) == bytes.fromhex(CONST9)] or z9
z8v = [v for v in z8 if b(v[:4]) == bytes.fromhex(CONST8)] or z8
d7 = None
for x in z2:
    if x in (360, 387, 388, 502, 503, 504, 529, 530, 532, 246, 248):
        d7 = x
d2c = [x for x in z2 if x not in (360, 387, 388, 502, 503, 504, 529, 530, 532,
                                  246, 248, 0, 0x19, 0xc0, 0x18, 0x10, 0x20)]
print("  #7 cand=%s  #2 cands=%s" % (["%x" % x for x in z2], ["%08x" % x for x in d2c]))
d2 = max(d2c, key=lambda x: bin(x).count("1")) if d2c else 0
claims = z10[0]
d7 = len(b(claims))  # exact claims length = the descriptor's own size in bytes
unp = d7
while unp > 0 and b(claims)[unp - 1] == 0:
    unp -= 1
print("  #10 = %d B  (unpadded %d)" % (d7, unp))


def run(nm, d9b, d8b, d7v):
    by = {0: (36, b(z0[0])), 9: (5, d9b), 8: (4, d8b),
          4: (8, b(z4[0])), 2: (1, struct.pack(">I", d2)),
          7: (1, struct.pack(">I", d7v)), 10: (len(claims), b(claims)),
          5: (1, b"\x00" * 4), 6: (1, b"\x00" * 4), 1: (0, b""), 3: (0, b"")}
    ex = FinEx(sec, [(by[i][0], 0, by[i][1]) for i in ORDER])
    st = ex.run(max_steps=25_000_000)
    out = {}
    for (s_, n, v) in ex.emit_trace:
        out[(s_, n)] = v
    hdr = struct.unpack(">4I", make_header(sec))
    stream = None
    for (s_, n) in out:
        if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
            stream = s_
            break
    got = b""
    if stream is not None:
        got = b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48))
    want = b(blob48)
    diff = sum(1 for j in range(48) if got[j*4:j*4+4] != want[j*4:j*4+4]) if got else 48
    print("  %-32s status=%-10s steps=%-9d %s" %
          (nm, st, ex.steps, "BYTE-EXACT" if got == want else "diff %d/48" % diff))
    return got == want


ok = run("#9=CONST9 #8=CONST8 #7=%d" % unp, bytes.fromhex(CONST9),
         bytes.fromhex(CONST8), unp)
print("RESULT:", "BYTE-EXACT" if ok else "MISMATCH")

# persist the row for the corpus
row = {"src": "app_dump.json (capture run7, app's own signing)", "second": sec,
       "blob": b(blob48).hex(), "d0": b(z0[0]).hex(),
       "d9": CONST9, "d8": CONST8, "d4": b(z4[0]).hex(),
       "d2": "%08x" % d2, "d7": "%08x" % unp, "d10": b(claims).hex(),
       "d5": "00000000", "d6": "00000000"}
out = os.path.join(HERE, "app_signings.json")
old = json.load(open(out, encoding="utf-8")) if os.path.exists(out) else []
old = [r for r in old if r.get("second") != sec] + [row]
json.dump(old, open(out, "w"), indent=1)
print("saved row (second=%d) into app_signings.json (%d rows)" % (sec, len(old)))
