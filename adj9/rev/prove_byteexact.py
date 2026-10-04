"""prove_byteexact.py — reproducible proof that a real device adj9 blob is
reproduced 48/48 (all 192 bytes) offline from the captured descriptor plane
and the signing second.

Model (proven this session; see SESSION_FINDINGS_SIGNATURE_GATE.md §2-§3,§7):
  VM seed   = the SIGNING SECOND (srand(time) -> 8 rand() -> 4 pair-XOR header
              words; refutes "seed = the /dev/urandom value S")
  body      = FinEx(seed=second, descriptors in VA_ORDER)
  header    = make_header(second), emitted as stream words 0..3
  body      = stream words 4..47
  region    = #0/#2/#4, device-materialized (NOT reliably region(S,0))

Inputs (produced by device/foldhook_native.js + collect_spawn.py and the
LSPosed module's adj9_capture.log):
  device/rows_full.json  -- per-signing S, second, and ALL 11 descriptors
  device/nblob_<sec>.hex -- the 192-byte blob for that signing (from the module)

Usage:  python prove_byteexact.py
"""
import os
import struct
import sys
import json
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "adj9_tool"))
sys.path.insert(0, HERE)

from fin_vm2 import FinEx
from header_gen import make_header

VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
BLOB_WORDS = 48


def run_finex(seed, descs, target):
    ex = FinEx(int(seed), descs)
    status = ex.run(max_steps=12_000_000)
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    bys = defaultdict(dict)
    for (sva, n), v in last.items():
        bys[sva][n] = v
    tgt = [struct.unpack_from(">I", target, 4 * j)[0] for j in range(len(target) // 4)]
    best, bs = -1, None
    for sva, m in bys.items():
        c = sum(1 for j, v in enumerate(tgt) if m.get(j) == v)
        if c > best:
            best, bs = c, sva
    m = bys[bs]
    diff = [j for j in range(len(tgt)) if m.get(j) != tgt[j]]
    return status, ex.steps, best, len(tgt), diff, bs


def descs_from_captured(rec):
    by = {}
    for did_s, d in rec["desc"].items():
        did = int(did_s)
        data = bytes.fromhex(d["hex"]) if d["hex"] else b""
        n = len(data) // 4
        by[did] = (n, 0, data[: n * 4])
    return [by[i] for i in VA_ORDER]


def main():
    rows = json.load(open(os.path.join(HERE, "..", "device", "rows_full.json")))["rows"]
    # map header-second -> blob
    blobs = {}
    for r in rows:
        p = os.path.join(HERE, "..", "device", "nblob_%d.hex" % r["second"])
        if os.path.exists(p):
            blobs[r["second"]] = bytes.fromhex(open(p).read().strip())

    proven = 0
    for rec in rows:
        sec = rec["second"]
        if sec not in blobs:
            print("row S=0x%08x sec=%d : no module blob captured (skip)" % (rec["S"], sec))
            continue
        blob = blobs[sec]
        assert blob[:16] == make_header(sec), "header law broken"
        st, iters, best, tot, diff, sink = run_finex(sec, descs_from_captured(rec), blob)
        ok = (best == tot)
        print("row S=0x%08x sec=%d d10=%dB : status=%s match=%d/%d diff=%s %s"
              % (rec["S"], sec, rec["d10_len"], st, best, tot, diff,
                 "  <<< 192-BYTE BYTE-EXACT" if ok else ""))
        if ok:
            proven += 1
    print("\nbyte-exact reproductions: %d" % proven)


if __name__ == "__main__":
    main()
