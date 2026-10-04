# desc_all.py - extract ALL signings' field-loop descriptors from the whcap EMIT
# stream; pair each with its nsign-record second (via the header law); test
# determinism: same second => same #0/#2/#8/#4?
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

DEV = os.path.join(os.path.dirname(HERE), "device")

d = json.load(open(os.path.join(DEV, "whcap_hits7.json"), encoding="utf-8"))
evs = [e for e in d if e.get("tag") == "emit"]

# same-sink runs
runs = []
cur = [evs[0]]
for e in evs[1:]:
    if e["sink"] == cur[-1]["sink"]:
        cur.append(e)
    else:
        runs.append(cur)
        cur = [e]
runs.append(cur)

def rw(r):
    return [int(x["val"], 16) for x in r]

# locate field loops: run len 36 followed by 5-run starting FAD0F10D
loops = []
for i in range(len(runs) - 8):
    if len(runs[i]) == 36 and len(runs[i + 1]) == 5 \
            and rw(runs[i + 1])[0] == 0xFAD0F10D and len(runs[i + 2]) == 4 \
            and len(runs[i + 3]) == 8:
        loops.append(i)
print("field loops found at run idx:", loops)

signings = []
for li in loops:
    r = runs[li:li + 9]
    w = [rw(x) for x in r]
    # VA_ORDER 0,9,8,4,2,7,#10,5,6  -> lens 36,5,4,8,1,1,L,1,1
    lens = [len(x) for x in w]
    if lens[:6] != [36, 5, 4, 8, 1, 1] or lens[7:] != [1, 1] \
            or lens[6] not in (90, 97):
        print("  loop@%d unexpected lens %s - skip" % (li, lens))
        continue
    signings.append({
        "d0": w[0], "d9": w[1], "d8": w[2], "d4": w[3],
        "single_a": w[4][0], "single_b": w[5][0],
        "d10_len": lens[6], "kind": "click" if lens[6] == 97 else "session",
        "s5": w[7][0], "s6": w[8][0],
    })
print("signings extracted:", len(signings))
for si, s in enumerate(signings):
    print("  S%d kind=%s d2=%08x d7=%08x d8=%s" % (
        si, s["kind"], s["single_a"], s["single_b"],
        b"".join(struct.pack(">I", x) for x in s["d8"]).hex()))

# ---- pair with nsign records: recover each record's second by header law ----
log = open(os.path.join(DEV, "adj9_wh4.log"), "rb").read().decode(
    "utf-8", errors="replace")
import re
recs = re.findall(
    r"###ADJ9_BEGIN type=nsign utf8len=\d+ ts=(\d+)\n"
    r"text: len=(\d+)\nnano_out=(\d+)\nhex=([0-9a-f]+)", log)
recs = [(int(ts), bytes.fromhex(hx)) for ts, l, nano, hx in recs]
print("nsign records:", len(recs))
for ri, (ts, blob) in enumerate(recs):
    sec = None
    for cand in range(ts // 1000 - 30, ts // 1000 + 3):
        if make_header(cand) == blob[:16]:
            sec = cand
            break
    print("  R%d ts=%d hdr=%s sec=%s" % (
        ri, ts, blob[:16].hex(), sec))
    recs[ri] = (ts, blob, sec)

# pairing by order (trace signings vs records count may differ; report both)
n = min(len(signings), len(recs))
print("\n--- same-second determinism pairs ---")
pairs = {}
for ri in range(len(recs)):
    sec = recs[ri][2]
    if sec is None:
        continue
    pairs.setdefault(sec, []).append(ri)
for sec, ridx in sorted(pairs.items()):
    if len(ridx) > 1:
        print("second", sec, "records", ridx)

# compare trace descriptors of signings whose record seconds are equal
if len(signings) == len(recs):
    for sec, ridx in sorted(pairs.items()):
        for i in range(len(ridx)):
            for j in range(i + 1, len(ridx)):
                a, b = signings[ridx[i]], signings[ridx[j]]
                same0 = a["d0"] == b["d0"]
                same2 = a["single_a"] == b["single_a"]
                same8 = a["d8"] == b["d8"]
                same4 = a["d4"] == b["d4"]
                print("S%d vs S%d sec=%s: d0=%s d2=%s d8=%s d4=%s" % (
                    ridx[i], ridx[j], sec,
                    "EQ" if same0 else "DIFF", "EQ" if same2 else "DIFF",
                    "EQ" if same8 else "DIFF", "EQ" if same4 else "DIFF"))
else:
    print("signing count %d != record count %d; pair by order fallback:"
          % (len(signings), len(recs)))
    for i in range(len(signings)):
        for j in range(i + 1, len(signings)):
            sa = signings[i].get("rec_sec")
            print("  (needs per-signing sec; see S-list above)")
