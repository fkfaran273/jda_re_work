"""probe_runs.py — dependence mapping for the 17 unknown dwords.

Each run: build a synthetic signing (dump_streams construction), execute the
VM once, then extract:
  - block9  = the 9 PRE-whitening sink words 11..19 (the block source),
    identified inside the emit_trace by matching the block composition
  - digest8 = sink final words 40..47 (never whitened)
  - the region words (d0/d2/d4 from F.py) for law fitting
Writes one JSON per run into algo_practice/probes/.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(HERE)
sys.path.insert(0, REV)

import F as FP                      # noqa: E402
from fin_vm2 import FinEx           # noqa: E402
from whiten_decoder import whiten_body_inverse  # noqa: E402
from header_gen import make_header  # noqa: E402

D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")

BASE_CLAIMS = {
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
    "android_uuid": "1b06322b-9070-4bdc-a231-2199bef3f3f5",
    "api_level": "31", "app_token": "jut9tib0eeps",
    "app_version": "3.14.0", "created_at": "2026-09-25T18:35:08.025Z+0530",
    "device_name": "moto g42", "device_type": "phone",
    "environment": "production",
    "gps_adid": "7cc81be0-60a0-4342-a878-eb5ee4f2634a",
    "gps_adid_src": "service", "hardware_name": "S2SE32.28-28-4",
    "initiating_package_name": "com.android.vending",
    "installed_at": "2026-09-14T17:52:12.431Z+0530",
    "os_build": "S2SE32.28-28-4", "os_name": "android", "os_version": "12",
    "package_name": "com.penti.app",
    "session_count": "1", "store_name_from_system": "com.android.vending",
    "tracking_enabled": "1", "updated_at": "2026-09-24T20:36:30.448Z+0530",
    "activity_kind": "session", "client_sdk": "android5.7.0",
    "adj_signing_id": "1500000", "headers_id": "10",
    "native_version": "5.0.0",
}


def build_descs(claims):
    from desc10_law import build_desc10
    raw = build_desc10(claims, "session").encode("latin1")
    padded = raw + b"\x00" * (-len(raw) % 4)
    return padded, len(raw)


def run_one(tag, sec, seed, claims):
    padded, unpadded = build_descs(claims)
    d0w, d2w, d4w = FP.region(seed, 0, 0, head=(0x2B, 0x48))
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
          2: (1, 0, struct.pack(">I", d2w)),
          7: (1, 0, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, b"\x00\x00\x00\x00"), 6: (1, 0, b"\x00\x00\x00\x00"),
          1: (0, 0, b""), 3: (0, 0, b"")}
    descs = [by[i] for i in [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]]

    ex = FinEx(sec, descs)
    status = ex.run(max_steps=40_000_000)

    # sink final words via last-write
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    sink = 0x5500000000
    blob_words = [last[(sink, n)] for n in range(48)]
    blob = b"".join(struct.pack(">I", w) for w in blob_words)
    assert blob[:16] == make_header(sec), "header law broken"

    # writes per index (ordered) for the sink
    writes = {}
    for (sva, n, v) in ex.emit_trace:
        if (sva & 0xFFFFFFFFFFFF) == sink:
            writes.setdefault(n & 0xFFFFFFFF, []).append(v & 0xFFFFFFFF)

    # the block: decode our own blob
    rec = whiten_body_inverse(blob[16:160], blob[:16])
    block = rec[46:78]
    # pre-whitening words 11..19: find among the writes by composition
    w12_18 = {}
    for n in range(12, 19):
        tgt = int.from_bytes(block[4 * (n - 12) + 2: 4 * (n - 12) + 6], "big")
        cands = [v for v in writes.get(n, []) if v == tgt]
        w12_18[n] = cands
    w11 = [v for v in writes.get(11, [])
           if (v & 0xFFFF) == int.from_bytes(block[0:2], "big")]
    w19 = [v for v in writes.get(19, [])
           if (v >> 16) & 0xFFFF == int.from_bytes(block[30:32], "big")]
    block9 = {}
    for n in range(11, 20):
        pool = {11: w11, 19: w19}.get(n) or w12_18.get(n, [])
        block9[n] = ["%08x" % v for v in pool]

    digest8 = ["%08x" % last[(sink, n)] for n in range(40, 48)]
    out = {
        "tag": tag, "sec": sec, "seed": seed,
        "status": status, "steps": ex.steps,
        "block_hex": block.hex(), "digest_hex": b"".join(
            struct.pack(">I", last[(sink, n)]) for n in range(40, 48)).hex(),
        "block9_candidates": block9,
        "sink_writes_8_20": {str(n): ["%08x" % v for v in writes.get(n, [])]
                             for n in range(8, 21)},
        "d0": ["%08x" % w for w in d0w], "d2": "%08x" % d2w,
        "d4": ["%08x" % w for w in d4w],
        "digest8": digest8,
    }
    path = os.path.join(HERE, "probes", "run_%s.json" % tag)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(out, open(path, "w"), indent=1)
    print("[%s] sec=%d seed=%08x st=%s block9_ok=%s" %
          (tag, sec, seed, status,
           all(len(v) == 1 for v in block9.values())), flush=True)
    return out


RUNS = [
    ("r0_base", 1790625704, 0xA6DA5D2B, {}),
    ("r1_sec1", 1790625705, 0xA6DA5D2B, {}),
    ("r2_seed", 1790625704, 0x11223344, {}),
    ("r3_claim", 1790625704, 0xA6DA5D2B, {"app_version": "3.14.1"}),
    ("r4_seed2", 1790625704, 0x55667788, {}),
    ("r5_sec2", 1790625706, 0xA6DA5D2B, {}),
]

if __name__ == "__main__":
    for tag, sec, seed, tweak in RUNS:
        claims = dict(BASE_CLAIMS)
        claims.update(tweak)
        run_one(tag, sec, seed, claims)
    print("all runs done")
