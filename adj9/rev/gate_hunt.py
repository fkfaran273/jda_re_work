"""gate_hunt.py - COMPREHENSIVE: is ANY body dword a digest of server-known data?

Server-known inputs: claims (#10), the request params, second, app_token,
cert SHA-1 (#9), plus the device ids. If one body dword is a digest of those,
the server CAN verify it - and that is our missing piece.

Battery: for every row, every window of every digest of every combination,
matched against every body dword (BE and LE).
"""
import hashlib
import itertools
import json
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))

P3 = json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))
A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
BYD2 = {r["d2"]: r for r in A}

DIGESTS = [("md5", hashlib.md5), ("sha1", hashlib.sha1), ("sha256", hashlib.sha256),
           ("sha512", hashlib.sha512), ("blake2s", hashlib.blake2s),
           ("sha3_256", hashlib.sha3_256), ("sha224", hashlib.sha224)]
CERT = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")

total_checks = 0
hits = []

for row in P3:
    src = BYD2.get(row["d2"])
    if not src:
        continue
    blob = bytes.fromhex(row["blob"])
    body = blob[16:]                       # 44 dwords
    bw = set(struct.unpack(">44I", body))
    claims = bytes.fromhex(src["d10"])
    sec = row["second"]

    parts = {
        "claims": claims,
        "claims_trim": claims.rstrip(b"\x00"),
        "cert": CERT,
        "sec_be": struct.pack(">I", sec),
        "sec_le": struct.pack("<I", sec),
        "token": b"jut9tib0eeps",
        "appver": b"3.13.9",
        "gaid": (row.get("gpid") or b"").encode() if isinstance(row.get("gpid"), bytes) else b"",
    }
    # combinations of 2 and 3 parts
    keys = list(parts)
    combos = {}
    for k, v in parts.items():
        if v:
            combos[k] = v
    for a_, b_ in itertools.permutations(keys, 2):
        if parts[a_] and parts[b_]:
            combos["%s+%s" % (a_, b_)] = parts[a_] + parts[b_]
    for a_, b_, c_ in itertools.permutations(keys, 3):
        if parts[a_] and parts[b_] and parts[c_]:
            combos["%s+%s+%s" % (a_, b_, c_)] = parts[a_] + parts[b_] + parts[c_]

    for cname, data in combos.items():
        for dname, dfn in DIGESTS:
            h = dfn(data).digest()
            total_checks += 1
            for off in range(0, len(h) - 3, 4):
                w = struct.unpack(">I", h[off:off+4])[0]
                if w in bw:
                    hits.append((row["d2"], cname, dname, off, "%08x" % w))
        crc = zlib.crc32(data) & 0xFFFFFFFF
        total_checks += 1
        if crc in bw:
            hits.append((row["d2"], cname, "crc32", 0, "%08x" % crc))

print("checks: %d" % total_checks)
print("hits: %d" % len(hits))
for h in hits[:40]:
    print("  HIT d2=%s %s %s@%d = %s" % h)
if not hits:
    print("=> NO body dword is a digest of any server-known combination")