"""make_sig.py — craft a complete adj9 signature offline in Python.

Claims (fresh) + harvested H + chosen #0 + merge/workhorse emulator +
Random3 header -> 192B blob. See slices 78-80.
"""
import datetime
import json
import random
import struct
import sys

sys.path.insert(0, ".")
from vm_final import Ex

SESSION_SECOND = None  # set to now at runtime
CERT = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")

# Harvested H (replay). Replace with any captured 32B H.
H_HARVEST = None


def load_harvest():
    t = json.load(open("..\\device\\triples_tail7.json"))
    return bytes.fromhex(t["sess_H"])


def fetch_block(now_str):
    """#10 content: packed fetch claims (fetch order, 4B BE words)."""
    parts = [
        b"KlcAG2cbAAsKSl1KVi0FGiJbDHMI",          # adj_verification
        b"415606ad-7002-479b-b691-305aace409ba",  # android_uuid (stable)
        b"31",                                     # api_level
        b"jut9tib0eeps",                           # app_token
        b"3.13.9",                                 # app_version
        now_str.encode(),                          # created_at
        b"moto g42", b"phone", b"production",
        b"f476b3d4-e0b1-4707-bc43-6153d17f7f8c",  # gps_adid (stable)
    ]
    raw = b"".join(parts)
    pad = (-len(raw)) % 4
    return raw + b"\0" * pad


def build_descriptors(fresh_ts, H, d0dword35):
    now_str = datetime.datetime.fromtimestamp(
        fresh_ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z+0200")
    fetch = fetch_block(now_str)
    L10 = len(fetch) // 4
    w0_10 = (L10 << 2) | 0
    core = bytearray(144)
    core[140:144] = struct.pack(">I", d0dword35)   # only anchored #0 word
    descs = [
        (36, 0, bytes(core)),                                # #0 chosen
        (5, 0, CERT),                                        # #9
        (4, 0, struct.pack(">I", 0) * 3 + struct.pack(">I", 0)),  # #8 (d3=0)
        (8, 0, H),                                           # #4
        (1, 0, struct.pack(">I", 0)),                        # #2 (unknown)
        (1, 0, struct.pack(">I", w0_10)),                    # #7 = #10 w0
        (L10, 0, fetch),                                     # #10
        (1, 0, b"\0" * 4),                                   # #5
        (1, 0, b"\0" * 4),                                   # #6
        (0, 0, b""),                                         # #1
        (0, 0, b""),                                         # #3
    ]
    return descs, now_str


def run(descs, seed):
    ex = Ex(seed, descs)
    status = ex.run()
    return ex, status


def main():
    import time
    fresh_ts = int(time.time())
    H = load_harvest()
    d0dword35 = random.getrandbits(32)
    descs, now_str = build_descriptors(fresh_ts, H, d0dword35)
    print("claims ts:", now_str, "d0dword35:", hex(d0dword35))
    ex, status = run(descs, fresh_ts)
    print("status:", status, "steps:", ex.steps, "nrand:", ex.nrand)
    from collections import defaultdict
    sinks = defaultdict(dict)
    for (s, n, v) in ex.emit_trace:
        sinks[s][n] = v
    for s, am in sorted(sinks.items()):
        if not am:
            continue
        mx = max(am)
        if mx > 4096:
            print("sink %x: wild max %d, skipped" % (s, mx))
            continue
        arr = [am.get(i, 0) for i in range(mx + 1)]
        print("sink %x: %d dwords, head: %s" %
              (s, mx + 1, " ".join("%08x" % v for v in arr[:8])))
    json.dump({"second": fresh_ts, "now_str": now_str,
               "d0dword35": hex(d0dword35),
               "sinks": {hex(s): am for s, am in sinks.items()}},
              open("made_sig.json", "w"))
    print("saved made_sig.json")


if __name__ == "__main__":
    main()
