# nsign_recon.py - the native nSign ARGUMENT set, from the device's own log.
#
# adj9_wh.log contains, per signing, a jca_mac_doFinal record followed 1 ms later
# by an nsign_in record whose arg3_hex is byte-identical to the MAC output. So
# arg3 = the keystore HMAC ("H"), passed INTO nSign. This script dumps everything
# the log exposes per signing, so the descriptor set can be compared with the
# emit-derived #0/#2/#4 and the #4 == H question can be settled with the DEVICE's
# own pairing (not an index guess).
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
LOG = os.path.join(DEV, "adj9_wh.log")

raw = open(LOG, "rb").read().decode("utf-8", errors="replace")
blocks = re.findall(r"###ADJ9_BEGIN type=(\w+)[^\n]*ts=(\d+)\n(.*?)###ADJ9_END",
                    raw, re.S)
print("blocks: %d" % len(blocks))
print("by type: %s" % dict(Counter(t for t, _, _ in blocks)))

TXT = {"nsign_in": 0, "nsign": 0, "sign_input": 0, "canonical": 0,
       "jca_mac_doFinal": 0, "jca_mac_update": 0, "jca_ks_keyinfo": 0,
       "authorization_header": 0, "adj_verification": 0}
for t, ts, body in blocks:
    if t in TXT and TXT[t] < 1:
        TXT[t] += 1
        print("\n=== %s (ts=%s) ===" % (t, ts))
        print(body.strip()[:900])

# ---- align nsign_in <-> nsign <-> sign_input by time ----------------------
print("\n\n=== per-signing alignment ===")
ins = [(int(ts), b) for t, ts, b in blocks if t == "nsign_in"]
nsi = [(int(ts), b) for t, ts, b in blocks if t == "nsign"]
ssi = [(int(ts), b) for t, ts, b in blocks if t == "sign_input"]
macs = [(int(ts), b) for t, ts, b in blocks if t == "jca_mac_doFinal"]
print("nsign_in=%d nsign=%d sign_input=%d mac_doFinal=%d"
      % (len(ins), len(nsi), len(ssi), len(macs)))


def field(body, name):
    m = re.search(r"(?:^|\n)%s=([0-9a-fA-F]*)" % re.escape(name), body)
    return m.group(1) if m else None


print("\n%-14s %-14s %-66s %-10s" % ("nsign_ts", "mac_ts", "arg3 (=H)", "arg4"))
rows = []
for ts, body in ins[:12]:
    a3 = field(body, "arg3_hex")
    a4 = field(body, "arg4_int")
    mts = [m for m, _ in macs if 0 <= ts - m <= 5]
    print("%-14d %-14s %-66s %-10s" % (ts, mts[0] if mts else "-",
                                       (a3 or "")[:64], a4))
    rows.append({"ts": ts, "arg3": a3, "arg4": a4})
json.dump(rows, open(os.path.join(HERE, "nsign_recon.json"), "w"), indent=1)