# det_full.py - determinism of the per-call descriptors, with the FULL payload.
#
# desc_det.py segmented the Frida EMIT trace into signings and kept only lengths.
# This keeps the whole #10 payload string, so we can ask the question that decides
# whether a pure-Python signature is possible at all:
#     same payload  =>  same #0/#2/#4 ?
# If yes the per-call region is payload-derived (=> computable offline => the blob
# is computable => we can forge a recognised package). If no, it is device state
# we cannot reproduce.
import json
import os
import re
import struct
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

DEV = os.path.join(os.path.dirname(HERE), "device")
d = json.load(open(os.path.join(DEV, "whcap_hits7.json"), encoding="utf-8"))
evs = [e for e in d if isinstance(e, dict) and e.get("tag") == "emit"]
print("emit events: %d" % len(evs))


def take(i, n, sink0):
    sink = evs[i]["sink"]
    vals = []
    for j in range(n):
        e = evs[i + j]
        if e["sink"] != sink or int(e["pos"], 16) != j:
            raise AssertionError
        vals.append(int(e["val"], 16))
    if sink0 is not None and sink == sink0:
        raise AssertionError
    return vals, sink, i + n


signings = []
i, prev = 0, None
while i < len(evs) - 60:
    try:
        f0, s0, i2 = take(i, 36, prev)
        f9, s9, i3 = take(i2, 5, s0)
        if f9[0] != 0xFAD0F10D:
            i += 1
            continue
        f8, s8, i4 = take(i3, 4, s9)
        f4, s4, i5 = take(i4, 8, s8)
        fa, sa, i6 = take(i5, 1, s4)
        fb, sb, i7 = take(i6, 1, sa)
        if int(evs[i7]["val"], 16) != 0x4B6C6341:
            i += 1
            continue
        sink10 = evs[i7]["sink"]
        vals10, pos, j = [], 0, i7
        while j < len(evs) and evs[j]["sink"] == sink10:
            p = int(evs[j]["pos"], 16)
            if p != pos:
                break
            vals10.append(int(evs[j]["val"], 16))
            pos += 1
            j += 1
        i8 = j
        f5, s5, i9 = take(i8, 1, sink10)
        f6, s6, iA = take(i9, 1, s5)
    except (AssertionError, IndexError):
        i += 1
        continue
    b10 = b"".join(struct.pack(">I", v) for v in vals10)
    m = re.search(rb"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\+\d{4})", b10)
    m2 = re.search(rb"(click|session|attribution|event)\x00*$", b10)
    signings.append({
        "kind": m2.group(1).decode() if m2 else "?",
        "created_at": m.group(1).decode() if m else None,
        "payload": b10,
        "d10len": len(vals10),
        "d0": b"".join(struct.pack(">I", v) for v in f0),
        "d4": b"".join(struct.pack(">I", v) for v in f4),
        "d2": fa[0], "d8": b"".join(struct.pack(">I", v) for v in f8),
    })
    prev = s6
    i = iA
    if i < len(evs) and evs[i]["sink"] != prev:
        ms = evs[i]["sink"]
        while i < len(evs) and evs[i]["sink"] == ms:
            i += 1

print("signings segmented: %d" % len(signings))
print("kinds: %s" % dict(Counter(s["kind"] for s in signings)))
print("distinct #4: %d  distinct #2: %d  distinct #0: %d"
      % (len({s["d4"].hex() for s in signings}),
         len({s["d2"] for s in signings}),
         len({s["d0"].hex() for s in signings})))
print("\n%-4s %-7s %-26s %-5s %-9s %-34s" % ("#", "kind", "created_at", "#10l",
                                             "#2", "#4 (head)"))
for k, s in enumerate(signings):
    print("%-4d %-7s %-26s %-5d %08x %s" % (k, s["kind"], s["created_at"],
                                            s["d10len"], s["d2"],
                                            s["d4"].hex()[:32]))

print("\n=== SAME PAYLOAD => SAME #2/#4 ? ===")
g = defaultdict(list)
for s in signings:
    g[s["payload"]].append(s)
dup = {k: v for k, v in g.items() if len(v) > 1}
print("payload groups: %d, with duplicates: %d" % (len(g), len(dup)))
for p, ss in dup.items():
    print("  payload len=%d  n=%d" % (len(p), len(ss)))
    for s in ss:
        print("    %-7s ca=%s  #2=%08x  #4=%s  #0=%s"
              % (s["kind"], s["created_at"], s["d2"], s["d4"].hex()[:24],
                 s["d0"].hex()[:24]))
    same = len({(x["d2"], x["d4"].hex(), x["d0"].hex()) for x in ss}) == 1
    print("    => identical #0/#2/#4: %s" % same)
json.dump([{**{k: (v.hex() if isinstance(v, bytes) else v)
               for k, v in s.items()}, "payload": s["payload"].hex()}
           for s in signings],
          open(os.path.join(HERE, "det_full.json"), "w"), indent=1)