"""pair_h3.py - finish the dataset the SOUND way and probe #2 with keyed mixing.

Assignment (replaces the unsound proximity rule):
  * candidates = header-law matches inside created_at +- 3 s, from ANY of the logs;
  * samples sharing a created_at form a group; the group's candidates are sorted by
    record ts and assigned to the group's samples IN CAPTURE ORDER (consecutive
    signings), which is what the captures are;
  * a candidate must sit at or after created_at (a signing cannot precede its own map);
  * H = arg3_hex of the nearest nsign_in <= ts (same log, <= 10 s).

Then: is #2 (4 B) a keyed digest of (claims, H, second)?
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

S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\+\d{4}")
LOGS = ["adj9_wh4.log", "adj9_wh2.log", "adj9_wh.log"]


def wall_second(ca):
    dt = datetime.datetime.strptime(ca[:19], "%Y-%m-%dT%H:%M:%S")
    off = ca[-5:]
    sgn = 1 if off[0] == "+" else -1
    return calendar.timegm(dt.timetuple()) - sgn * (int(off[1:3]) * 3600 + int(off[3:5]) * 60)


groups = {}
for i, x in enumerate(S):
    m = ISO.search(bytes.fromhex(x["d10"]).decode("latin1"))
    if not m:
        continue
    groups.setdefault(wall_second(m.group(0)), []).append(i)
print("groups:", dict((k, v) for k, v in sorted(groups.items())))

headers = {}
for ws, idxs in groups.items():
    for sec in range(ws - 3, ws + 4):
        headers[make_header(sec).hex()] = sec
print("candidate headers: %d" % len(headers), flush=True)

found = []          # (log, ts, blob_hex)
hs = []             # (log, ts, arg3_hex)
for lg in LOGS:
    p = os.path.join(DEV, lg)
    if not os.path.exists(p) or os.path.getsize(p) == 0:
        continue
    raw = open(p, "rb").read().decode("utf-8", errors="replace")
    for h in headers:
        k = raw.find(h)
        if k < 0:
            continue
        b = raw.rfind("###ADJ9_BEGIN type=nsign", max(0, k - 4096), k)
        if b < 0:
            continue
        seg = raw[b:k + 400]
        tm = re.search(r"ts=(\d+)", seg)
        hm = re.search(r"hex=([0-9a-f]+)", seg)
        if tm and hm and hm.group(1).startswith(h):
            found.append((lg, int(tm.group(1)), hm.group(1)[:384]))
    for m in re.finditer(r"###ADJ9_BEGIN type=nsign_in[^\n]*ts=(\d+)", raw):
        w = raw[m.start():m.start() + 2000]
        am = re.search(r"arg3_hex=([0-9a-f]+)", w)
        if am:
            hs.append((lg, int(m.group(1)), am.group(1)))
    del raw

rows = []
for ws, idxs in sorted(groups.items()):
    cands = sorted(set(found), key=lambda r: r[1])
    cands = [c for c in cands if c[1] // 1000 >= ws - 1]
    print("\nws=%d samples=%s candidates=%d" % (ws, idxs, len(cands)))
    for k, c in enumerate(cands):
        print("   cand %d: %-12s ts=%d blob=%s" % (k, c[0], c[1], c[2][:16]))
    for j, i in enumerate(sorted(idxs)):
        if j >= len(cands):
            print("[%2d] no candidate" % i)
            continue
        lg, ts, blob = cands[j]
        near = [r for r in hs if r[0] == lg and 0 <= ts - r[1] <= 10000]
        H = max(near, key=lambda r: r[1])[2] if near else None
        rows.append({"i": i, "second": ts // 1000, "log": lg, "nsign_ts": ts,
                     "blob": blob, "H": H, "d0": S[i]["d0"], "d2": S[i]["d2"],
                     "d4": S[i]["d4"]})
        print("[%2d] sec=%-11d %-12s blob=%s H=%s" %
              (i, ts // 1000, lg, blob[:16], (H[:32] + "..") if H else "none"))

json.dump(rows, open(os.path.join(HERE, "pair_h3.json"), "w"), indent=1)
print("\nsaved pair_h3.json: %d rows, %d with H" %
      (len(rows), sum(1 for r in rows if r["H"])))

# ---- keyed-mixing battery for #2 -------------------------------------------
print()
print("--- #2 vs keyed digests of (claims, H, second) ---")
hits = 0
for r in rows:
    if not r["H"]:
        continue
    Hb = bytes.fromhex(r["H"])
    claims = bytes.fromhex(S[r["i"]]["d10"])
    secb_be = struct.pack(">I", r["second"])
    secb_le = struct.pack("<I", r["second"])
    tgt = int(S[r["i"]]["d2"], 16)
    cands = {}
    cands["hmac(H,claims)"] = hmac.new(Hb, claims, hashlib.sha256).digest()
    cands["hmac(H,claims+sec)"] = hmac.new(Hb, claims + secb_be, hashlib.sha256).digest()
    cands["hmac(claims,H)"] = hmac.new(claims, Hb, hashlib.sha256).digest()
    cands["hmac(H,sec)"] = hmac.new(Hb, secb_be, hashlib.sha256).digest()
    cands["hmac(Hb,h_sha1)"] = hmac.new(Hb, claims, hashlib.sha1).digest()
    cands["sha256(H+claims)"] = hashlib.sha256(Hb + claims).digest()
    cands["sha256(claims+H)"] = hashlib.sha256(claims + Hb).digest()
    cands["sha256(H+sec)"] = hashlib.sha256(Hb + secb_be).digest()
    found_names = []
    for nm, dg in cands.items():
        for k in range(0, len(dg) - 3):
            if int.from_bytes(dg[k:k + 4], "big") == tgt:
                found_names.append("%s[%d:be]" % (nm, k))
            if int.from_bytes(dg[k:k + 4], "little") == tgt:
                found_names.append("%s[%d:le]" % (nm, k))
    if found_names:
        hits += len(found_names)
    print("[%2d] %s" % (r["i"], found_names or "none"))
print("total hits:", hits)