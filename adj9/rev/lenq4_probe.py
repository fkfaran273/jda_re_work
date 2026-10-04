"""lenq4_probe.py - the d2cand read context: which stream reads cd9d3a91?

lenq3 found stream 0x...3b70 reads=1: slot=0 val=cd9d3a91 (d2cand).
That single-read stream is the #2 DESCRIPTOR as the VM sees it.
Questions:
 1. What are the sibling streams (same prefix family)? Any other 1-read
    streams = other descriptors-as-seen?
 2. d2cand read count total (5): list all 5 with stream+slot.
 3. The 0x...cf0 / 0x...4950 streams (slots 0-3 = a[0..3]): full dumps --
    are they the #4 descriptor walks? what follows slot 3?
"""
import json, os, sys
from collections import Counter
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
L = d.get("lenq", [])


def be4(v):
    return "%08x" % (v & 0xFFFFFFFF)


D2C = 0xcd9d3a91
print("--- all reads of d2cand ---")
for e in L:
    if (e[2] & 0xFFFFFFFF) == D2C:
        print("   stream=%s slot=%s" % (e[0], e[1]))
print("--- 1-read streams (descriptor snapshots?) ---")
by_st = {}
for e in L:
    by_st.setdefault(e[0], []).append((e[1], e[2] & 0xFFFFFFFF))
for st, reads in sorted(by_st.items(), key=lambda x: str(x[0])):
    if len(reads) == 1:
        print("   stream=%s slot=%s val=%s" % (st, reads[0][0], be4(reads[0][1])))
print("--- streams 0x..cf0 / 0x..4950 full ---")
for st in [s for s in by_st if str(s).endswith(("3cf0", "4950"))]:
    print("   == %s reads=%d ==" % (st, len(by_st[st])))
    for n, v in by_st[st][:40]:
        print("      slot=%s val=%s" % (n, be4(v)))
