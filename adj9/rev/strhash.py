"""strhash.py - is the #0 W-word a STRING hash of a map key/value?

Golden W0=0x13271271=321327729 (small, positive i32!). Test Java String.hashCode
(h = 31*h + c) of every map key, every map value, and key+value combos from
the golden sign_input order. Also test hashCode of the 50 pair-strings.
A HIT on W0 with hashCode would prove #0 = Java string hashes (deterministic,
offline-computable!).
"""
import sys
import os
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))
si = W["sign_inputs"][W["golden_sign_input_idx"]]
order = si["order"]


def jhash(s):
    h = 0
    for ch in s:
        h = (31 * h + ord(ch)) & 0xFFFFFFFF
    return h if h < 2**31 else h - 2**32


W0 = 0x13271271
W0S = struct_val = 321327729
print("target W0 = 0x13271271 = %d" % W0S)
pairs = [p.split("\x01") for p in order.split("\x02")]
print("npairs:", len(pairs))
hits = 0
for kv in pairs:
    for s in kv:
        if jhash(s) == W0S or (jhash(s) & 0xFFFFFFFF) == W0:
            print("HIT hashCode(%r) == W0" % s)
            hits += 1
    if len(kv) == 2:
        for s in (kv[0] + kv[1], kv[0] + "=" + kv[1], kv[0] + "\x01" + kv[1]):
            if (jhash(s) & 0xFFFFFFFF) == W0:
                print("HIT hashCode(%r) == W0" % s)
                hits += 1
# also: full pair-string and full order-string hashes
for s in (order, si.get("toString", "")):
    if (jhash(s) & 0xFFFFFFFF) == W0:
        print("HIT hashCode(full) == W0")
        hits += 1
print("hashCode hits: %d" % hits)

# ALSO test the OTHER region words as hashCodes of keys (C-triad? d2? d4w?)
import struct
A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
g = A[7]
w = struct.unpack(">36I", bytes.fromhex(g["d0"]))
targets = {"W0": w[0], "C1": w[1], "C2": w[2], "C3": w[3], "W1": w[4]}
targets["D2"] = int(g["d2"], 16)
d4 = bytes.fromhex(g["d4"])
for i in range(8):
    targets["d4[%d]" % i] = struct.unpack(">I", d4[4*i:4*i+4])[0]
print("\n=== hashCode sweep over all region words x all pair strings ===")
strs = []
for kv in pairs:
    strs.extend(kv)
    if len(kv) == 2:
        strs.append(kv[0] + kv[1])
S = set(strs)
hh = {}
for s in S:
    hh.setdefault(jhash(s) & 0xFFFFFFFF, []).append(s)
for tn, tv in targets.items():
    if tv in hh:
        print("HIT %s=0x%08x = hashCode(%s)" % (tn, tv, hh[tv][:3]))
print("done")
