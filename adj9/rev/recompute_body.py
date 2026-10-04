"""recompute_body.py — full 44/44 body recompute attempt for the ALIGNED
session (vm_full.json ↔ blob 40cbb9e2…, second 1789207344).

Feeds the LIVE-captured field values (vm_full.json fieldloop records) into
rev/vm_final.py's executor, runs the VM from 0x100094, and reports
convergence vs the placeholder baseline (exit-clean 1253, nrand 0):
  metrics = steps, dispatch values, gateway hits (0x128eec), nrand,
  OUTPUT[0..4) header vs Random3(1789207344), OUTPUT[4..48) vs target body.

Usage: python recompute_body.py
"""
import json
import re
import struct
import sys

sys.path.insert(0, ".")
from vm_final import Ex  # the executor (spawn heap mode not needed here)

SESSION_SECOND = 1789207344
TARGET = json.load(open("target_body.json"))
TGT_BODY = [int(x, 16) for x in TARGET["body_dwords_hex"]]
TGT_HDR = [int(TARGET["blob"][8 * i:8 * i + 8], 16) for i in range(4)]


def live_field_values():
    """Live last-emit dword per descriptor pass, from vm_full fieldloop records.

    The 0x100114 hook fires once per descriptor; x3 = the descriptor's LAST
    emitted dword (BE), x1 = its sink. Round 1 = records 1..11, round 2 = next.
    Descriptor order (live, slice 78): #0,#9,#8,#4,#2,#7,#10,#5,#6,#1,#3.
    """
    d = json.load(open("../device/vm_full.json"))
    fl = [r for r in d if r.get("tag") == "fieldloop"]
    rounds = []
    for r in fl:
        if r.get("x2") == "0xb":            # x2=0xb marks a VM-call boundary
            rounds.append([])
        elif rounds:
            try:
                rounds[-1].append((r.get("x1"), int(r.get("x2"), 16),
                                   int(r.get("x3"), 16) & 0xFFFFFFFF))
            except (TypeError, ValueError):
                pass
    return rounds


def build_descriptors(round1):
    """11 descriptors; len/tag per slice 23, data from live last-emits +
    known constants. Descriptor word = (len_dw << 2) | tag."""
    H = bytes.fromhex(json.load(open("../device/triples_tail7.json"))["sess_H"])
    CERT = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
    # descriptor order as passed: [#0,#9,#8,#4,#2,#7,#10,#5,#6,#1,#3]
    # live last-dwords:            [?, cert-tail, ?, ?, ?, H-w, 0x168, 0,0, -, -]
    last = {i: v for i, (_, j, v) in enumerate(round1)}
    core = bytearray(144)
    core[140:144] = struct.pack(">I", 0)          # placeholder tail
    descs = [
        (36, 0, bytes(core)),                                        # #0 gate
        (5, 0, CERT),                                                # #9
        (4, 0, struct.pack(">I", last.get(2, 0))),                   # #8
        (8, 0, H),                                                   # #4
        (1, 0, struct.pack(">I", 0)),                                # #2
        (1, 0, struct.pack(">I", last.get(5, 0))),                   # #7
        (1, 0, struct.pack(">I", last.get(6, 0))),                   # #10 len word
        (1, 0, b"\0" * 4),                                           # #5
        (1, 0, b"\0" * 4),                                           # #6
        (0, 0, b""),                                                 # #1
        (0, 0, b""),                                                 # #3
    ]
    return descs


def run(descs, seed):
    ex = Ex(seed, descs)
    ex.R["x19"] = 0xBBBB0000
    ex.R["x20"] = 0xAAAA0000
    ex.R["x26"] = len(descs)
    ex.R["x22"] = 0
    ex.R["x23"] = 0
    ex.R["x27"] = 0
    status = ex.run()
    return ex, status


def main():
    rounds = live_field_values()
    print("live fieldloop rounds:", len(rounds),
          "round-1 records:", len(rounds[0]) if rounds else 0)
    descs = build_descriptors(rounds[0] if rounds else [])
    ex, status = run(descs, SESSION_SECOND)
    print("status:", status, "steps:", ex.steps, "nrand:", ex.nrand)
    print("emit trace events:", len(ex.emit_trace))
    # collect the EMIT trace -> output stream (last-write-wins per sink)
    from collections import defaultdict
    sinks = defaultdict(dict)
    for (s, n, v) in ex.emit_trace:
        sinks[s][n] = v
    for s, am in sinks.items():
        mx = max(am)
        arr = [am.get(i, 0) for i in range(mx + 1)]
        m_hdr = sum(1 for a, b in zip(arr[:4], TGT_HDR) if a == b)
        m_body = sum(1 for a, b in zip(arr[4:48], TGT_BODY) if a == b)
        best = 0
        for st in range(0, max(1, mx - 43)):
            w = arr[st:st + 44]
            best = max(best, sum(1 for a, b in zip(w, TGT_BODY) if a == b))
        print("sink %x: %d dwords, hdr %d/4, body@4 %d/44, best-window %d/44"
              % (s, mx + 1, m_hdr, m_body, best))
        if m_body + m_hdr > 0 or best > 4:
            print("   arr[:12]:", " ".join("%08x" % v for v in arr[:12]))
    print("hdr  :", " ".join("%08x" % v for v in TGT_HDR))
    print("body :", " ".join("%08x" % v for v in TGT_BODY[:8]))
    print("\nconvergence monitors (slices 31-51):")
    print("  dispatch values, gateway pc 0x128eec, nrand>0, MAIN dword count")
    print("  target: nrand=8, gateway hit, 48 dwords, writer clean")


if __name__ == "__main__":
    main()
