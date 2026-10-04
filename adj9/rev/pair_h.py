"""pair_h.py - build the (claims, H, second) dataset for the 10 real signings and
test #0's informative words against H.

Pairing (device's own log, no index guessing):
  * nsign block  -> blob hex (+ ts)
  * nsign_in block -> arg3_hex = H (+ ts), 1 ms before the nsign block
  * the signing second is recovered by matching make_header(second) to the blob's
    first 16 bytes (tried around the claims' created_at, +-3 s).

Then: is #0 (W0 + 16-byte tile) a transform of H?  (H is 32 B; the tile is 16 B.)
"""
import calendar
import datetime
import hashlib
import hmac
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from header_gen import make_header

LOG = os.path.join(DEV, sys.argv[1] if len(sys.argv) > 1 else "adj9_wh4.log")
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\+\d{4}")
BLOCK = re.compile(r"###ADJ9_BEGIN type=(\w+)[^\n]*ts=(\d+)\n(.*?)###ADJ9_END", re.S)

print("scanning %s ..." % os.path.basename(LOG), flush=True)
raw = open(LOG, "rb").read().decode("utf-8", errors="replace")
blob_index = {}
nsign = []
nsignin = []
for m in BLOCK.finditer(raw):
    t, ts, body = m.group(1), int(m.group(2)), m.group(3)
    if t == "nsign":
        hm = re.search(r"hex=([0-9a-f]+)", body)
        if hm:
            b = bytes.fromhex(hm.group(1))
            blob_index.setdefault(b[:16], b)
            nsign.append((ts, b))
    elif t == "nsign_in":
        am = re.search(r"arg3_hex=([0-9a-f]+)", body)
        if am:
            nsignin.append((ts, am.group(1)))
print("nsign=%d nsign_in=%d distinct-blob-headers=%d" %
      (len(nsign), len(nsignin), len(blob_index)), flush=True)
nsign.sort()
nsignin.sort()


def wall_second(ca):
    dt = datetime.datetime.strptime(ca[:19], "%Y-%m-%dT%H:%M:%S")
    off = ca[-5:]
    sgn = 1 if off[0] == "+" else -1
    return calendar.timegm(dt.timetuple()) - sgn * (int(off[1:3]) * 3600 + int(off[3:5]) * 60)


def words(x, n):
    rawb = bytes.fromhex(x)
    return [int.from_bytes(rawb[i:i + 4], "big") for i in range(0, 4 * n, 4)]


rows = []
used_blobs = set()
for i, x in enumerate(S):
    m = ISO.search(bytes.fromhex(x["d10"]).decode("latin1"))
    if not m:
        continue
    ws = wall_second(m.group(0))
    cands = []
    for cand in range(ws - 900, ws + 901):
        h = make_header(cand)
        if h in blob_index:
            cands.append((cand, blob_index[h]))
    # prefer exact created_at, then nearest, and never reuse a blob
    cands.sort(key=lambda c: (abs(c[0] - ws), c[0]))
    hit = None
    for cand, blob in cands:
        if blob[:16] not in used_blobs:
            hit = (cand, blob)
            break
    if not hit:
        print("[%2d] ws=%d  NO BLOB PAIR (%d candidates, all used)" % (i, ws, len(cands)))
        continue
    second, blob = hit
    used_blobs.add(blob[:16])
    # H: nsign_in closest before the matching nsign record
    ts = None
    for t, b in nsign:
        if b[:16] == blob[:16]:
            ts = t
            break
    H = None
    if ts is not None:
        prev = [p for p in nsignin if p[0] <= ts]
        if prev:
            H = prev[-1][1]
    rows.append({"i": i, "ws": ws, "second": second, "blob": blob.hex(),
                 "H": H, "d0": x["d0"], "d2": x["d2"], "d4": x["d4"]})
    print("[%2d] ws=%-11d second=%-11d blob=%s H=%s" %
          (i, ws, second, blob[:8].hex(), (H[:32] + "..") if H else "none"))

json.dump(rows, open(os.path.join(HERE, "pair_h.json"), "w"), indent=1)
print("\nsaved pair_h.json (%d rows with blob)" % len(rows))
print("rows with H: %d" % sum(1 for r in rows if r["H"]))

# ---------------- is #0 a transform of H? -----------------------------------
print()
print("--- #0 (W0 + tile) vs H ---")
hits = 0
for r in rows:
    if not r["H"]:
        continue
    Hb = bytes.fromhex(r["H"])
    w = words(r["d0"], 5)
    W0, tile = w[0], w[1:5]
    tbs = b"".join(struct.pack(">I", t) for t in tile)
    cands = {
        "H[:16]": Hb[:16], "H[16:]": Hb[16:], "H[:16] rev": Hb[:16][::-1],
        "H[16:] rev": Hb[16:][::-1],
        "sha256(H)[:16]": hashlib.sha256(Hb).digest()[:16],
        "md5(H)": hashlib.md5(Hb).digest(),
        "sha1(H)[:16]": hashlib.sha1(Hb).digest()[:16],
    }
    w0b = struct.pack(">I", W0)
    xored = {}
    for nm, cb in cands.items():
        xored[nm + " ^ W0bytes"] = bytes(a ^ b for a, b in zip(cb, w0b * (len(cb) // 4 + 1)))
    cands.update(xored)
    found = [nm for nm, cb in cands.items() if cb == tbs]
    # W0 as a word of any digest of H
    w_hits = []
    for nm, fn in (("sha256", hashlib.sha256), ("sha1", hashlib.sha1),
                   ("md5", hashlib.md5), ("blake2s", hashlib.blake2s)):
        dg = fn(Hb).digest()
        for k in range(0, len(dg) - 3, 4):
            if int.from_bytes(dg[k:k + 4], "big") == W0 or \
               int.from_bytes(dg[k:k + 4], "little") == W0:
                w_hits.append("%s[%d]" % (nm, k))
    if found or w_hits:
        hits += len(found) + len(w_hits)
    print("[%2d] tile-match=%s  W0-in-digest=%s" % (r["i"], found or "none", w_hits or "none"))
print("total hits:", hits)