"""pair_fix.py — SOUND pairing of all_signings rows to nsign blobs.

Method: FinEx's body depends ONLY on the descriptors (the second seeds the
header draws). So for each row, run the VM with any second and compare the
176-byte body to each captured nsign blob's body. A byte-equal body is a
sound pairing (no timing guesses, no index order).

Then: second = nsign_ts // 1000 (header law; verified against golden).
Output: pair_fixed.json with (i, blob, ts, second) for every matched row —
the clean dataset every keystream/plaintext probe needs.
"""
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx

ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]


def build_descs(row):
    by = {}
    for k in ("d0", "d9", "d8", "d4", "d2", "d7", "d10", "d5", "d6"):
        v = row[k]
        if isinstance(v, str):
            by[int(k[1:])] = (len(v) // 8, bytes.fromhex(v))
    by[1] = (0, b"")
    by[3] = (0, b"")
    return [(by[i][0], 0, by[i][1]) for i in ORDER if i in by]


def body_of(descs, second=1789240512):
    ex = FinEx(second, descs)
    st = ex.run(max_steps=20_000_000)
    out = {}
    for (s, n, v) in ex.emit_trace:
        out[(s, n)] = v
    blob = b"".join(struct.pack(">I", out.get((0x5500000000, k), 0))
                    for k in range(48))
    return st, blob


def main():
    log = open(os.path.join(HERE, "..", "device", "adj9_wh4.log"),
               encoding="utf-8", errors="replace").read()
    nsigns = []
    for m in re.finditer(r"ts=(\d+)[^\n]*?blob=([0-9a-f]{384})", log):
        nsigns.append((int(m.group(1)), m.group(2)))
    # also the 'nsign blob=' style used elsewhere
    if not nsigns:
        for m in re.finditer(r"blob=([0-9a-f]{384})", log):
            nsigns.append((None, m.group(1)))
    print("nsign blobs found:", len(nsigns))

    S = json.load(open(os.path.join(HERE, "all_signings.json")))
    A = json.load(open(os.path.join(HERE, "app_signings.json")))

    out = []
    for i, row in enumerate(S):
        descs = build_descs(row)
        st, blob = body_of(descs)
        body = blob[16:]
        match = None
        for ts, nh in nsigns:
            if bytes.fromhex(nh)[16:] == body:
                match = (ts, nh[:16])
                break
        print("row %2d: st=%s body=%s… match=%s" %
              (i, st, body[:8].hex(), match), flush=True)
        out.append({"i": i, "src": row.get("src"),
                    "second": (match[0] // 1000) if match and match[0] else None,
                    "nsign_ts": match[0] if match else None,
                    "blob_head": match[1] if match else None,
                    "d2": row["d2"], "d0": row["d0"][:16],
                    "d4": row["d4"]})
    for j, row in enumerate(A):
        descs = build_descs(row)
        st, blob = body_of(descs)
        print("app %d: st=%s body=%s… (blob known: %s)"
              % (j, st, blob[16:24].hex(), row.get("blob", "?")[:16]
                 if row.get("blob") else "n/a"), flush=True)
        out.append({"i": "app%d" % j, "second": row.get("second"),
                    "d2": row["d2"], "d0": row["d0"][:16], "d4": row["d4"]})

    json.dump(out, open(os.path.join(HERE, "pair_fixed.json"), "w"), indent=1)
    print("saved pair_fixed.json")


if __name__ == "__main__":
    main()
