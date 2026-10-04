"""rec_scan.py - is the 658-slot stream a length-prefixed RECORD TABLE (i.e. the
serialized descriptor plane the builder hands to the VM)?

Look for [len_B][len_dw] pairs with len_B == 4*len_dw, and for records whose
content matches known shapes (#0 36 dwords with a 16-byte tile, #4 8 dwords
rising density, #10 = claims, the 192-byte blob, ...).
"""
import base64
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)

d = json.load(open(os.path.join(HERE, "wh_out.json"), encoding="utf-8"))
blob = base64.b64decode(d["blobB64"])
blob_be = [struct.unpack(">I", blob[i:i + 4])[0] for i in range(0, 192, 4)]
print("blob BE words:", ["%08x" % x for x in blob_be[:8]])


def plane(rows):
    S = {}
    for st, n, v in rows:
        S.setdefault(st, {})[n] = v
    return dict((st, [S[st][k] for k in sorted(S[st])]) for st in S)


for nm, rows in (("EMIT", d["emits"]), ("LENQ", d["lenq"])):
    pl = plane(rows)
    big = max(pl.items(), key=lambda kv: len(kv[1]))
    st, vs = big
    print()
    print("=== %s 658-stream %s : first 24 slots ===" % (nm, str(st)[-8:]))
    print("   ", ["%08x" % x for x in vs[:24]])
    # find the blob inside
    for i in range(len(vs) - 48):
        if vs[i:i + 4] == blob_be[:4]:
            print("   blob starts at slot %d (preceded by %s)" %
                  (i, ["%08x" % x for x in vs[max(0, i - 4):i]]))
    # length-prefixed records: len_B, len_dw with len_B == 4*len_dw
    print("   --- candidate [len_B][len_dw] records ---")
    n = 0
    for i in range(len(vs) - 2):
        lb, ld = vs[i], vs[i + 1]
        if lb == 4 * ld and 1 <= ld <= 400:
            print("      slot %-4d len_B=%-6d len_dw=%-4d next=%s" %
                  (i, lb, ld, ["%08x" % x for x in vs[i + 2:i + 6]]))
            n += 1
            if n > 25:
                break
    if n == 0:
        print("      none")
    # where do the singles / other streams appear inside?
    for other, ovals in pl.items():
        if other == st or len(ovals) != 1:
            continue
        w = ovals[0]
        hits = [i for i, x in enumerate(vs) if x == w]
        print("   single %08x appears at slots %s" % (w, hits[:6]))