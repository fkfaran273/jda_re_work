"""make_fresh.py — craft a fresh-session signature offline.

Reuses whcap session's #0/#4(H)/#9/#8/#2/#5/#6/#1/#3 verbatim, swaps fresh
created_at/sent_at into #10 (same lengths!), recomputes #7, runs FinEx
with seed=fresh second, extracts F0[0..48) blob. Then submits.
"""
import base64
import datetime
import json
import struct
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, ".")
from fin_vm2 import FinEx

D = json.load(open("fin_descs.json"))
BASE = {d["build_idx"]: d for d in D["descs"]}
PARAMS = json.load(open("whcap_params.json"))


def fresh_ts():
    now = datetime.datetime.now(datetime.timezone.utc)
    return (int(now.timestamp()),
            now.strftime("%Y-%m-%dT%H:%M:%S.000Z+0200"),
            now.strftime("%Y-%m-%dT%H:%M:%S.060Z+0200"))


def swap_ts(raw: bytes, old: bytes, new: bytes) -> bytes:
    assert len(old) == len(new), (len(old), len(new))
    assert raw.count(old) >= 1, old
    return raw.replace(old, new)


def main():
    sec, created, sent = fresh_ts()
    print("fresh second:", sec, created)
    d10 = bytes.fromhex(BASE[10]["data_hex"])
    d10 = swap_ts(d10, b"2026-09-12T21:15:11.678Z+0200", created.encode())
    if d10.count(b"2026-09-12T21:15:11.738Z+0200"):
        d10 = swap_ts(d10, b"2026-09-12T21:15:11.738Z+0200", sent.encode())
    assert len(d10) % 4 == 0
    L10 = len(d10) // 4
    w0_10 = (L10 << 2) | 0
    print("#10 dwords:", L10, "w0:", hex(w0_10))
    order = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
    by = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"]))
          for d in D["descs"]}
    by[10] = (L10, d10)
    by[7] = (1, struct.pack(">I", w0_10))
    descs = [(by[i][0], 0, by[i][1]) for i in order]
    ex = FinEx(sec, descs)
    import time
    t0 = time.time()
    status = ex.run(max_steps=20_000_000)
    print("status=%s steps=%d nrand=%d (%.1fs)" %
          (status, ex.steps, ex.nrand, time.time() - t0))
    slotmap = {0x5500000000 + 0x1000 * i: "F%d" % i for i in range(16)}
    f0 = []
    for (sva, n, v) in ex.emit_trace:
        pass
    # collect F0 last-write window like fin_mapcmp
    from collections import defaultdict
    sinks = defaultdict(dict)
    for (sva, n, v) in ex.emit_trace:
        sinks[sva][n] = v
    f0va = 0x5500000000
    am = sinks.get(f0va, {})
    if len(am) < 48:
        print("F0 short:", len(am), "sinks:", len(sinks))
        return
    blob = b"".join(struct.pack(">I", am.get(i, 0)) for i in range(48))
    print("blob:", blob.hex()[:64], "...")
    json.dump({"second": sec, "created": created, "sent": sent,
               "blob_hex": blob.hex(),
               "params": dict(PARAMS, created_at=created, sent_at=sent)},
              open("fresh_sig.json", "w"), indent=1)
    print("saved fresh_sig.json")


if __name__ == "__main__":
    main()
