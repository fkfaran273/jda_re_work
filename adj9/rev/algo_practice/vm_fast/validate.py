"""validate.py — byte-exactness gate for the fast VM.

  1-3. the three creditsea GOLD signings (desc10_58.GOLD, second=1790694158/9/66)
  4.   one penti corpus row

Every blob is minted with the SAME descriptor-rebuild path as
creditsea/testbed.py (build_descs + region_parts), once with the reference
fin_vm2.FinEx and once with the fast one, and compared against each other and
against the gold hex.  Exit code 0 iff all rows are byte-exact.
"""
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(HERE))
CS = os.path.join(REV, "creditsea")
for p in (HERE, REV, CS):
    if p not in sys.path:
        sys.path.insert(0, p)

import testbed as TB           # noqa: E402
import desc10_58 as LAW        # noqa: E402
import fin_vm2                 # noqa: E402
from fin_vm2_fast import FinEx as FastEx, prepare   # noqa: E402

SINK = TB.SINK


def mint(cls, second, descs, max_steps=60_000_000):
    ex = cls(int(second), descs)
    status = ex.run(max_steps=max_steps)
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    bys = {}
    for ((sva, n), v) in last.items():
        bys.setdefault(sva, {})[n] = v
    m = bys.get(SINK)
    if m is None:
        return None, status, ex
    blob = b"".join(struct.pack(">I", m.get(k, 0)) for k in range(48))
    return blob, status, ex


def creditsea_rows():
    rows = []
    for s in TB.mine_log():
        kind = s["val"].get("activity_kind", "session")
        dec = TB.decode(s["blob"])
        d0, d4, d2, pfx = TB.region_parts(dec, s["second"])
        raw, _pad = LAW.claims_for_law_58(s["val"], kind)
        descs = TB.build_descs(s["second"], raw, d0, d4, d2)
        rows.append({"label": "creditsea/%s" % kind, "second": s["second"],
                     "descs": descs, "gold": s["blob"]})
    return rows


PENTI_PAIRS = (1, 2)     # genuine_signings.json pairs the reference reproduces
                         # byte-exact (pair 0, a penti *session*, does not: the
                         # 5.7.0 session claims are not in desc10_58's law, so
                         # the reference itself only matches 48/192 there).


def penti_rows():
    import json
    g = json.load(open(os.path.join(CS, "genuine_signings.json"), encoding="utf-8"))
    rows = []
    for i in PENTI_PAIRS:
        p = g["pairs"][i]
        sign = p["sign"]
        second = p["nsig_ts"] // 1000
        blob = bytes.fromhex(p["nsig"])
        kind = sign["map"].get("activity_kind", "session")
        dec = TB.decode(blob)
        d0, d4, d2, pfx = TB.region_parts(dec, second)
        raw, _pad = LAW.claims_for_law_58(sign["map"], kind)
        descs = TB.build_descs(second, raw, d0, d4, d2)
        rows.append({"label": "penti[%d]/%s" % (i, kind), "second": second,
                     "descs": descs, "gold": blob})
    return rows


def main(dopenti=True):
    t0 = time.time()
    prepare(verbose=True)
    print("prepare %.2fs\n" % (time.time() - t0))
    rows = creditsea_rows()
    if dopenti:
        rows.extend(penti_rows())
    ok = True
    print("%-24s %9s %10s %10s  %s"
          % ("row", "2nd", "ref s", "fast s", "result"))
    for r in rows:
        tr0 = time.time()
        b_ref, st_ref, ex_ref = mint(fin_vm2.FinEx, r["second"], r["descs"])
        t_ref = time.time() - tr0
        tf0 = time.time()
        b_fast, st_fast, ex_fast = mint(FastEx, r["second"], r["descs"])
        t_fast = time.time() - tf0
        same = b_ref == b_fast
        gold_ok = (b_fast == r["gold"]) if r.get("gold") else False
        nref = (sum(1 for i in range(192) if b_ref[i] == r["gold"][i])) if r.get("gold") else 0
        ok &= same and gold_ok
        print("%-24s %9d %10.2f %10.2f  ref==fast:%-4s gold:%-14s"
              "  steps %d/%d  status %s/%s"
              % (r["label"], r["second"], t_ref, t_fast,
                 "OK" if same else "FAIL",
                 ("OK" if gold_ok else "FAIL %d/192" % nref),
                 ex_ref.steps, ex_fast.steps, st_ref, st_fast))
    nok = 0
    for r in rows:
        b, _s, _e = mint(FastEx, r["second"], r["descs"])
        if b == r["gold"]:
            nok += 1
    print("GATE RESULT: %d/%d blobs byte-exact vs gold  ->  %s"
          % (nok, len(rows), "PASS" if nok == len(rows) else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(dopenti="--nopenti" not in sys.argv))
