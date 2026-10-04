# h_pair.py - is #4 the keystore MAC after all? Resolve the PAIRING rigorously.
#
# Slice 103 refuted "#4 = H" by comparing the golden #4 with wh4_records.mac_doFinal
# [golden_nsign_idx] - an INDEX pairing. But the captured H list is 8 entries with
# each distinct value appearing TWICE (e3,e3,8f,8f,62,62,ee,ee), so an index
# pairing may be wrong. This script pairs MAC records to nsign records by TIME
# from the device log and then re-tests the containment question.
import json
import os
import re
import struct
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
LOG = os.path.join(DEV, "adj9_wh4.log")
W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))

print("=== wh4_records arrays ===")
for k, v in W.items():
    print("  %-22s %s" % (k, len(v) if isinstance(v, list) else v))

Hs = [x["hex"] for x in W["mac_doFinal"]]
print("\nH list: %d entries, %d distinct" % (len(Hs), len(set(Hs))))
order = list(dict.fromkeys(Hs))
print("  distinct in order: %s" % order)

# --- record stream by type + time -------------------------------------------
raw = open(LOG, "rb").read().decode("utf-8", errors="replace")
recs = re.findall(r"###ADJ9_BEGIN type=(\w+)[^\n]*ts=(\d+)", raw)
print("\n=== device log record stream === ")
print("  total records: %d" % len(recs))
types = Counter(t for t, _ in recs)
print("  by type: %s" % dict(types))
print("  first 30:")
for t, ts in recs[:30]:
    print("    %-10s ts=%s" % (t, ts))

# nsign records with their blobs and times
ns = re.findall(r"###ADJ9_BEGIN type=nsign[^\n]*ts=(\d+)\n"
                r"text: len=\d+\nnano_out=\d+\nhex=([0-9a-f]+)", raw)
print("\n  nsign records with blob: %d" % len(ns))

# mac records (the keystore doFinal harvest) with times
macs = re.findall(r"###ADJ9_BEGIN type=(\w*mac\w*)[^\n]*ts=(\d+)\n(.*?)(?=###ADJ9_BEGIN|\Z)",
                  raw, re.S)
print("  mac-ish records: %d" % len(macs))
for t, ts, body in macs[:12]:
    hx = re.findall(r"[0-9a-f]{64}", body)
    print("    %-12s ts=%s  hex64=%s" % (t, ts, hx[:1]))

# --- containment: does any captured H appear in any d4 sample? --------------
print("\n=== does a captured H appear inside a #4 sample? ===")
samples = []       # (tag, d4_bytes)
FD = json.load(open(os.path.join(HERE, "fin_descs.json"), encoding="utf-8"))
for d in FD["descs"]:
    if d["build_idx"] == 4:
        samples.append(("golden(desc)", bytes.fromhex(d["data_hex"])))
DET = json.load(open(os.path.join(HERE, "desc_det_result.json"), encoding="utf-8"))
for i, e in enumerate(DET):
    samples.append(("det[%d]" % i,
                    b"".join(struct.pack(">I", x) for x in e["d4"])))
try:
    ALS = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
    for i, s in enumerate(ALS):
        if s.get("d4"):
            samples.append(("als[%d]" % i, bytes.fromhex(s["d4"])))
except Exception as e:
    ALS = []
    print("  all_signings: %s" % e)

print("  #4 samples: %d" % len(samples))
for h in order:
    hb = bytes.fromhex(h)
    hits = [t for t, d4 in samples if hb in d4]
    print("  H %s… contained in: %s" % (h[:16], hits or "NONE"))

# --- same transform test: d4 == H? d4 tail == H[:24]? xor? -------------------
print("\n=== transform tests on every (#4, H) pairing ===")
found = 0
for t, d4 in samples:
    for h in order:
        hb = bytes.fromhex(h)
        tests = {
            "eq": d4 == hb,
            "head8+tail24==H24": d4[8:] == hb[:24],
            "tail24==H[:24]": d4[-24:] == hb[:24],
            "xor(head8)": bytes(a ^ b for a, b in zip(d4[:8], hb[:8])) == bytes(8),
        }
        for name, ok in tests.items():
            if ok:
                print("  %-12s with H %s… : %s" % (t, h[:12], name))
                found += 1
print("  total matches: %d" % found)

# --- sample table ----------------------------------------------------------
print("\n=== #4 samples (head | tail) ===")
for t, d4 in samples:
    print("  %-12s head=%s tail=%s" % (t, d4[:8].hex(), d4[8:].hex()[:24]))