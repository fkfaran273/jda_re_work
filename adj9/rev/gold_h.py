# gold_h.py - THE pairing test, using the device's own records.
#
# fin_descs.json says its trace's first signing is the golden one:
#   target.nsign_ts = 1789240514238, second = 1789240512, #4 = 0010040004144000…
# adj9_wh.log logs, per signing, `nsign_in.arg3_hex` = the jca_mac_doFinal output
# 1 ms earlier (the keystore HMAC of the map string). This script reads the arg3
# of THAT signing and answers: is #4 the keystore MAC or not?
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
F = json.load(open(os.path.join(HERE, "fin_descs.json"), encoding="utf-8"))
T = F["target"]
GOLD_BLOB = T["blob_hex"]
GOLD_TS = T["nsign_ts"]
D4 = [d for d in F["descs"] if d["build_idx"] == 4][0]["data_hex"]
D2 = [d for d in F["descs"] if d["build_idx"] == 2][0]["data_hex"]
D0 = [d for d in F["descs"] if d["build_idx"] == 0][0]["data_hex"]
print("golden: nsign_ts=%d second=%d created_at=%s" % (GOLD_TS, T["second"],
                                                       T["created_at"]))
print("  #4 = %s" % D4)
print("  #2 = %s" % D2)
print("  #0 = %s… (%d bytes)" % (D0[:64], len(D0) // 2))
print("  blob = %s…" % GOLD_BLOB[:48])


def blocks(path):
    raw = open(path, "rb").read().decode("utf-8", errors="replace")
    return re.findall(r"###ADJ9_BEGIN type=(\w+)[^\n]*ts=(\d+)\n(.*?)###ADJ9_END",
                      raw, re.S)


def arg3_of(bl, ts):
    """the nsign_in record nearest (just after) ts -> (arg3, arg4)"""
    best = None
    for t, bts, body in bl:
        if t != "nsign_in":
            continue
        d = int(bts) - ts
        if 0 <= d <= 400 and (best is None or d < best[0]):
            m = re.search(r"arg3_hex=([0-9a-f]+)", body)
            m4 = re.search(r"arg4_int=(\d+)", body)
            best = (d, bts, m.group(1) if m else None,
                    m4.group(1) if m4 else None)
    return best


for name in ("adj9_wh4.log", "adj9_wh.log", "adj9_wh2.log"):
    p = os.path.join(DEV, name)
    if not os.path.exists(p):
        continue
    bl = blocks(p)
    print("\n=== %s: %d blocks ===" % (name, len(bl)))
    r = arg3_of(bl, GOLD_TS)
    print("  nsign_in nearest %d: +%s ms ts=%s arg3=%s arg4=%s"
          % (GOLD_TS, r[0] if r else "-", r[1] if r else "-",
             (r[2] if r else "-"), (r[3] if r else "-")))
    if r and r[2]:
        print("  INPUT  #4 : %s" % D4)
        print("  DEVICE arg3: %s" % r[2])
        print("  ==> #4 == arg3 (the keystore MAC)? %s" % (D4 == r[2]))
        if D4 != r[2]:
            import itertools
            h, a = bytes.fromhex(D4), bytes.fromhex(r[2])
            print("  xor(head8) = %s" % bytes(x ^ y for x, y in
                                              zip(h[:8], a[:8])).hex())
            print("  #4[8:] == arg3[:24]? %s" % (h[8:] == a[:24]))
            print("  #4[8:] == arg3[8:]?  %s" % (h[8:] == a[8:]))
    # locate the nsign blob at that ts to confirm identity
    for t, bts, body in bl:
        if t == "nsign" and abs(int(bts) - GOLD_TS) <= 2000:
            m = re.search(r"hex=([0-9a-f]{384})", body)
            if m:
                print("  nsign ts=%s blob==golden? %s"
                      % (bts, m.group(1) == GOLD_BLOB))