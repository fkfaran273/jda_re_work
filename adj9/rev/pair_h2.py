"""pair_h2.py - complete the (claims, H, second) dataset with the two sound rules.

Rule 1: pair each sample against the log its own capture belongs to, and only accept
        a header-law match (make_header(second) == blob[:16]) inside created_at +- 3 s.
Rule 2: when several samples share a created_at (7/8/9), assign the nearest-in-time
        DISTINCT blobs in capture order (they are consecutive signings).

Instead of regex-parsing 200+ MB logs, this scans them for the ~14 candidate header
hex strings per sample (plain substring search), then reads only the surrounding
record to pick up the blob and the nsign_in `arg3_hex` (= H).
"""
import calendar
import datetime
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from header_gen import make_header

S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\+\d{4}")
LOGS = ["adj9_wh4.log", "adj9_wh2.log", "adj9_wh.log"]


def wall_second(ca):
    dt = datetime.datetime.strptime(ca[:19], "%Y-%m-%dT%H:%M:%S")
    off = ca[-5:]
    sgn = 1 if off[0] == "+" else -1
    return calendar.timegm(dt.timetuple()) - sgn * (int(off[1:3]) * 3600 + int(off[3:5]) * 60)


# ---- candidate headers per sample -------------------------------------------
cand = {}
for i, x in enumerate(S):
    m = ISO.search(bytes.fromhex(x["d10"]).decode("latin1"))
    if not m:
        continue
    ws = wall_second(m.group(0))
    cand[i] = dict((make_header(sec).hex(), sec) for sec in range(ws - 600, ws + 601))
all_headers = set(h for d in cand.values() for h in d)
print("samples with created_at: %d ; candidate headers: %d" %
      (len(cand), len(all_headers)), flush=True)

# ---- scan the logs: keep nsign blobs whose header is a candidate, and all
#      nsign_in records in the same time neighbourhood -------------------------
found = {}          # header -> [(log, ts, blob_hex)]
hs = []             # (log, ts, arg3_hex)
for lg in LOGS:
    p = os.path.join(DEV, lg)
    if not os.path.exists(p) or os.path.getsize(p) == 0:
        continue
    print("scanning %s (%d MB) ..." % (lg, os.path.getsize(p) // 1048576), flush=True)
    raw = open(p, "rb").read().decode("utf-8", errors="replace")
    for h in all_headers:
        start = 0
        while True:
            k = raw.find(h, start)
            if k < 0:
                break
            start = k + 1
            # walk back to the record header to get ts
            b = raw.rfind("###ADJ9_BEGIN type=nsign", max(0, k - 4096), k)
            if b < 0:
                continue
            seg = raw[b:k + 400]
            tm = re.search(r"ts=(\d+)", seg)
            hm = re.search(r"hex=([0-9a-f]+)", seg)
            if tm and hm and hm.group(1).startswith(h):
                found.setdefault(h, []).append((lg, int(tm.group(1)), hm.group(1)[:384]))
    for m in re.finditer(r"###ADJ9_BEGIN type=nsign_in[^\n]*ts=(\d+)", raw):
        # read a small window to get arg3_hex
        w = raw[m.start():m.start() + 2000]
        am = re.search(r"arg3_hex=([0-9a-f]+)", w)
        if am:
            hs.append((lg, int(m.group(1)), am.group(1)))
    del raw
print("candidate-header hits: %d ; nsign_in records: %d" % (len(found), len(hs)), flush=True)

# ---- assignment -------------------------------------------------------------
used = set()
rows = []
for i in sorted(cand):
    opts = []
    for h, sec in cand[i].items():
        for lg, ts, blob in found.get(h, []):
            if blob[:32] not in used:
                opts.append((abs(sec - cand[i][h]), sec, lg, ts, blob))
    if not opts:
        print("[%2d] no free candidate" % i)
        continue
    opts.sort()
    _, sec, lg, ts, blob = opts[0]
    used.add(blob[:32])
    H = None
    near = [r for r in hs if r[0] == lg and 0 <= ts - r[1] <= 10000]
    if near:
        H = max(near, key=lambda r: r[1])[2]
    rows.append({"i": i, "second": sec, "log": lg, "nsign_ts": ts,
                 "blob": blob, "H": H, "d0": S[i]["d0"], "d2": S[i]["d2"],
                 "d4": S[i]["d4"]})
    print("[%2d] sec=%-11d log=%-12s ts=%d blob=%s H=%s" %
          (i, sec, lg, ts, blob[:16], (H[:32] + "..") if H else "none"))

json.dump(rows, open(os.path.join(HERE, "pair_h2.json"), "w"), indent=1)
print("\nsaved pair_h2.json: %d rows, %d with H" %
      (len(rows), sum(1 for r in rows if r["H"])))