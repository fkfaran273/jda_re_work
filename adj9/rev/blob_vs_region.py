"""blob_vs_region.py - what does the 192-B blob actually CONTAIN?

Compares the blob bytes against the region descriptors for the same signing, to
establish exactly what the server can extract/verify from the blob.
"""
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))

for fname in ("app_signings5.json", "app_signings4.json", "app_signings3.json"):
    path = os.path.join(HERE, fname)
    if not os.path.exists(path):
        continue
    a = json.load(open(path, encoding="utf-8"))
    row = a[0] if isinstance(a, list) else a
    blob = bytes.fromhex(row["blob"])
    d0 = bytes.fromhex(row["d0"])
    d4 = bytes.fromhex(row["d4"])
    d2 = bytes.fromhex(row["d2"])
    d10 = bytes.fromhex(row["d10"])
    print("=== %s (sec=%s) ===" % (fname, row["second"]))
    print("blob %dB" % len(blob))
    for i in range(0, min(192, len(blob)), 16):
        print("  %3d  %s" % (i, blob[i:i + 16].hex()))
    print()
    print("  #0[0:16]      =", d0[:16].hex(), "in blob?", d0[:16] in blob)
    print("  #0[8:40] tile =", d0[8:40].hex(), "in blob?", d0[8:40] in blob)
    print("  #0[4:20]      =", d0[4:20].hex(), "in blob?", d0[4:20] in blob)
    print("  #4 (32B)      =", d4.hex(), "in blob?", d4 in blob)
    print("  #4[0:16]      =", d4[:16].hex(), "in blob?", d4[:16] in blob)
    print("  #2 (4B)       =", d2.hex(), "in blob?", d2 in blob)
    print("  #10 head      =", d10[:16].hex(), "in blob?", d10[:16] in blob)
    # which blob words match region words?
    bw = struct.unpack(">48I", blob)
    r0 = struct.unpack(">36I", d0)
    r4 = struct.unpack(">8I", d4)
    r2 = struct.unpack(">I", d2)
    print()
    print("  blob words present in #0:", [i for i, w in enumerate(bw) if w in r0][:20])
    print("  blob words present in #4:", [i for i, w in enumerate(bw) if w in r4][:20])
    print("  blob words == #2:", [i for i, w in enumerate(bw) if w == r2])
    print()
