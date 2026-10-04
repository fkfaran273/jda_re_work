"""dump_streams.py — one controlled FinEx run; locate the block source.

Builds a known synthetic signing (same construction as diff_test), runs the
VM once, then:
  - finds the sink stream (header match) -> blob words 0-47
  - decodes the blob -> record -> the 32-B block
  - searches EVERY stream for the unaligned 9-dword window that equals the
    block  (stream[11] bytes 2:4 || stream[12:19] || stream[19] bytes 0:2)
  - saves all streams + the emit_trace entries that wrote the block words
Output: algo_practice/streams_sample0.json
"""
import base64
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(HERE)
sys.path.insert(0, REV)
sys.path.insert(0, REV)

import F as FP                      # noqa: E402
from fin_vm2 import FinEx           # noqa: E402
from whiten_decoder import whiten_body_inverse  # noqa: E402

SEC = 1790625704
SEED = 0xA6DA5D2B
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")


def build_descs():
    val = {
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
    from desc10_law import build_desc10
    raw = build_desc10(val, "session").encode("latin1")
    padded = raw + b"\x00" * (-len(raw) % 4)
    d0w, d2w, d4w = FP.region(SEED, 0, 0, head=(0x2B, 0x48))
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
          2: (1, 0, struct.pack(">I", d2w)),
          7: (1, 0, struct.pack(">I", len(raw))),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, b"\x00\x00\x00\x00"), 6: (1, 0, b"\x00\x00\x00\x00"),
          1: (0, 0, b""), 3: (0, 0, b"")}
    return [by[i] for i in [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]]


def main():
    descs = build_descs()
    ex = FinEx(SEC, descs)
    status = ex.run(max_steps=40_000_000)
    print("status=%s steps=%d nrand=%d streams=%d"
          % (status, ex.steps, ex.nrand, len(ex.streams)))

    # replicate finex_mint's stream reconstruction from emit_trace
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    bys = {}
    for ((sva, n), v) in last.items():
        bys.setdefault(sva, {})[n] = v
    print("emit streams: %d" % len(bys))

    from header_gen import make_header
    hdr = struct.unpack(">4I", make_header(SEC))
    sink_va, blob_words = None, None
    streams = {}
    for sva, wdict in bys.items():
        maxn = max(wdict)
        words = [wdict.get(k, 0) for k in range(maxn + 1)]
        streams[sva] = words
        if len(words) >= 4 and tuple(words[:4]) == hdr:
            sink_va, blob_words = sva, words[:48]
    print("sink va=%s words=%d" % (hex(sink_va) if sink_va is not None else None,
                                   len(blob_words) if blob_words else 0))
    blob = b"".join(struct.pack(">I", w) for w in blob_words)

    rec = whiten_body_inverse(blob[16:160], blob[:16])
    block = rec[46:78]
    print("block: %s" % block.hex())

    # search every stream for the unaligned window == block
    hits = []
    for va, words in streams.items():
        if len(words) < 20:
            continue
        w = [x & 0xFFFFFFFF for x in words]
        window = (struct.pack(">I", w[11])[2:]
                  + b"".join(struct.pack(">I", w[n]) for n in range(12, 19))
                  + struct.pack(">I", w[19])[:2])
        if window == block:
            hits.append(va)
            print("BLOCK SOURCE: stream va=%s (words 11..19)" % hex(va))
    if not hits:
        print("no stream matches the unaligned window — trying aligned 8")
        for va, words in streams.items():
            w = [x & 0xFFFFFFFF for x in words]
            for off in range(0, min(24, len(w) - 8)):
                seg = b"".join(struct.pack(">I", w[n])
                               for n in range(off, off + 8))
                if block[:16] == seg or block[16:] == seg:
                    print("  partial: va=%s off=%d" % (hex(va), off))

    # emit_trace entries that wrote words 11..19 on the source stream
    trace = []
    if hits:
        for (sva, n, v) in ex.emit_trace:
            if (sva & 0xFFFFFFFFFFFF) in hits and 8 <= (n & 0xFFFFFFFF) <= 20:
                trace.append([sva, n & 0xFFFFFFFF, v & 0xFFFFFFFF])

    out = {
        "sec": SEC, "seed": SEED, "status": status, "steps": ex.steps,
        "sink_va": sink_va, "blob_hex": blob.hex(),
        "block_hex": block.hex(),
        "block_source_streams": [hex(h) for h in hits],
        "emit_trace_block": trace,
        "full_emit_trace": [[sva, n & 0xFFFFFFFF, v & 0xFFFFFFFF]
                            for (sva, n, v) in ex.emit_trace],
        "streams": {hex(va): [w & 0xFFFFFFFF for w in words]
                    for va, words in streams.items()},
    }
    path = os.path.join(HERE, "streams_sample0.json")
    json.dump(out, open(path, "w"), indent=1)
    print("saved %s" % path)


if __name__ == "__main__":
    main()
