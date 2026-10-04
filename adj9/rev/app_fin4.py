"""app_fin4.py - FinEx byte-exact test on the FRESH run7 signing (seg27).

Descriptors (from seg27_probe.log):
  #0 = 36w fdda97ce...  #4 = 8w 00010201...  #9 = CONST9
  #8 = CONST8  #2 = cd9d3a91  #7 = 0x183 (387 unpadded)
  #10 = 97w click claims (388 B padded, 387 unpadded)
second = 1789914579 (header law). Expect: exit-clean + BYTE-EXACT.
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from fin_vm2 import FinEx
from header_gen import make_header
ORDER = json.load(open(os.path.join(HERE, "adj9_material.json")))["va_order"]
SEC = 1789914579
CONST9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
CONST8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))


def segment(rows):
    segs, cur = [], {}
    for st, n, v in rows:
        if n == 0 and st in cur and cur[st]:
            segs.append(cur)
            cur = {}
        cur.setdefault(st, {})[n] = v
    segs.append(cur)
    return segs


def b(vs):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in vs)


segs = segment([(st, n, v) for st, n, v in d["emits"]])
seg = segs[27]
byc = {}
for st, m in seg.items():
    byc.setdefault(len(m), []).append([m[i] for i in sorted(m)])
z0, z4, z9 = byc[36][0], byc[8][0], None
for vs in byc[5]:
    if b(vs[:5]) == CONST9:
        z9 = vs
        break
z8 = [vs for vs in byc[4] if b(vs[:4]) == CONST8][0]
blob = [vs for vs in byc[48] if b(vs[:4]) == make_header(SEC)][0]
claims = byc[97][0]
unp = 387
print("roles: #0=%s #4=%s #9=%s singles=%s claims=%dB" %
      (" ".join("%08x" % v for v in z0[:2]),
       " ".join("%08x" % v for v in z4[:2]),
       "CONST9" if z9 else "MISSING",
       ["%08x" % byc[1][i][0] for i in range(len(byc[1]))],
       len(b(claims))))
by = {0: (36, b(z0)), 9: (5, b(z9)), 8: (4, b(z8)),
      4: (8, b(z4)), 2: (1, struct.pack(">I", 0xcd9d3a91)),
      7: (1, struct.pack(">I", unp)), 10: (97, b(claims)),
      5: (1, b"\x00" * 4), 6: (1, b"\x00" * 4), 1: (0, b""), 3: (0, b"")}
ex = FinEx(SEC, [(by[i][0], 0, by[i][1]) for i in ORDER])
st = ex.run(max_steps=25_000_000)
out = {}
for (s_, n, v) in ex.emit_trace:
    out[(s_, n)] = v
hdr = struct.unpack(">4I", make_header(SEC))
stream = None
for (s_, n) in out:
    if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
        stream = s_
        break
got = b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48)) if stream is not None else b""
want = b(blob)
diff = sum(1 for j in range(48) if got[j*4:j*4+4] != want[j*4:j*4+4]) if got else 48
print("status=%s steps=%d %s" % (st, ex.steps, "BYTE-EXACT" if got == want else "diff %d/48" % diff))
row = {"src": "app_dump.json (capture run7, app's own CLICK signing)", "second": SEC,
       "blob": want.hex(), "d0": b(z0).hex(), "d9": CONST9.hex(), "d8": CONST8.hex(),
       "d4": b(z4).hex(), "d2": "cd9d3a91", "d7": "%08x" % unp, "d10": b(claims).hex(),
       "d5": "00000000", "d6": "00000000", "kind": "click"}
outp = os.path.join(HERE, "app_signings.json")
old = json.load(open(outp, encoding="utf-8")) if os.path.exists(outp) else []
old = [r for r in old if r.get("second") != SEC] + [row]
json.dump(old, open(outp, "w"), indent=1)
print("saved click row (second=%d) into app_signings.json (%d rows)" % (SEC, len(old)))
