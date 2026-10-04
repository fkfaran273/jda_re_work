"""fold_probe.py - is the unknown a FOLD of the claim string?

Untried family: #4 (8 words) as an 8-word fold of #10's dwords; #2 / W0 as the
first fold word; digest vectors (sha256/sha1/md5/blake2s of the claims) laid
against #4 word-by-word.  Tested on all 10 real rows (+ the app's fresh row where
it has a known map is not needed here -- only claims+d0/d2/d4 matter).
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))


def be(hexs, n=None):
    raw = bytes.fromhex(hexs)
    if n is None:
        n = len(raw) // 4
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 4 * n, 4)]


def xorfold(ws, n=8):
    out = [0] * n
    for i, w in enumerate(ws):
        out[i % n] ^= w
    return out


def addfold(ws, n=8):
    out = [0] * n
    for i, w in enumerate(ws):
        out[i % n] = (out[i % n] + w) & 0xFFFFFFFF
    return out


print("%-3s %-6s %-8s %s" % ("i", "claims", "#2", "fold-vs-#4 / digest-vs-#4 / first-word hits"))
tot = 0
for i, x in enumerate(S):
    claims = bytes.fromhex(x["d10"])
    dw_le = [int.from_bytes(claims[j:j + 4], "little") for j in range(0, len(claims), 4)]
    dw_be = [int.from_bytes(claims[j:j + 4], "big") for j in range(0, len(claims), 4)]
    tgt4 = be(x["d4"], 8)
    tgt2 = int(x["d2"], 16)
    w0 = be(x["d0"], 1)[0]
    hits = []
    for nm, seq in (("xorfold-le", xorfold(dw_le)), ("addfold-le", addfold(dw_le)),
                    ("xorfold-be", xorfold(dw_be)), ("addfold-be", addfold(dw_be))):
        if seq == tgt4:
            hits.append(nm + "==#4!")
        if seq[0] in (tgt2, w0):
            hits.append("%s[0]==#2/W0" % nm)
    for nm, fn in (("sha256", hashlib.sha256), ("sha1", hashlib.sha1),
                   ("md5", hashlib.md5), ("blake2s", hashlib.blake2s)):
        dg = fn(claims).digest()
        for k in range(0, len(dg) - 28 + 1, 4):
            if [int.from_bytes(dg[k + 4 * j:k + 4 * j + 4], "big") for j in range(8)] == tgt4:
                hits.append("%s[%d:]==#4!" % (nm, k))
            if [int.from_bytes(dg[k + 4 * j:k + 4 * j + 4], "little") for j in range(8)] == tgt4:
                hits.append("%s[%d:le]==#4!" % (nm, k))
        w0be = (int.from_bytes(dg[:4], "big"), int.from_bytes(dg[:4], "little"))
        if tgt2 in w0be:
            hits.append("%s==#2" % nm)
    # claims head/tail dwords vs W0
    if dw_be[0] == w0 or dw_le[0] == w0:
        hits.append("head==W0")
    if dw_be[-1] == w0 or dw_le[-1] == w0:
        hits.append("tail==W0")
    tot += len(hits)
    print("[%2d] claims=%-4d #2=%08x hits=%s" % (i, len(claims), tgt2, hits or "none"))
print()
print("total fold hits: %d" % tot)