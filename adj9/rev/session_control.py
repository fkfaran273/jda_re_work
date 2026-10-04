"""session_control.py - control: feed app_signings row0 (SESSION, second
1789903463, the slice-127 2/2 BYTE-EXACT row) into FinEx from the SAVED
descriptors (app_dump.json has since been overwritten by the run7 click
capture, so app_fin2.py can no longer test it).

Expect: exit-clean steps=9871985 BYTE-EXACT.
If this fails, the FinEx environment/code changed and the click failure
proves nothing. If it passes, FinEx is fine and the click inputs are wrong.
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from fin_vm2 import FinEx
from header_gen import make_header
ORDER = json.load(open(os.path.join(HERE, "adj9_material.json")))["va_order"]
row = [r for r in json.load(open(os.path.join(HERE, "app_signings.json")))
       if r["second"] == 1789903463][0]
SEC = row["second"]
print("row: second=%d d2=%s d7=%s d10=%dB" % (SEC, row["d2"], row["d7"], len(row["d10"]) // 2))


def bx(h):
    return bytes.fromhex(h)


by = {0: (36, bx(row["d0"])), 9: (5, bx(row["d9"])), 8: (4, bx(row["d8"])),
      4: (8, bx(row["d4"])), 2: (1, bx(row["d2"])), 7: (1, bx(row["d7"])),
      10: (len(bx(row["d10"])) // 4, bx(row["d10"])),
      5: (1, bx(row["d5"])), 6: (1, bx(row["d6"])),
      1: (0, b""), 3: (0, b"")}
print("d10 len_dw=%d" % (len(bx(row["d10"])) // 4))
ex = FinEx(SEC, [(by[i][0], 0, by[i][1]) for i in ORDER])
st = ex.run(max_steps=25_000_000)
out = {}
for (s_, n, v) in ex.emit_trace:
    out[(s_, n)] = v
HDR = struct.unpack(">4I", make_header(SEC))
stream = None
for (s_, n) in out:
    if tuple(out.get((s_, k), 0) for k in range(4)) == HDR:
        stream = s_
        break
WANT = bx(row["blob"])
got = (b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48))
       if stream is not None else b"")
diff = (sum(1 for j in range(48) if got[j*4:j*4+4] != WANT[j*4:j*4+4]) if got else 48)
print("status=%s steps=%d %s" % (st, ex.steps, "BYTE-EXACT" if got == WANT else "diff %d/48" % diff))
if got != WANT:
    pos = [j for j in range(48) if got[j*4:j*4+4] != WANT[j*4:j*4+4]][:50]
    print("mismatch word positions:", pos)
