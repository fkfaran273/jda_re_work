"""lenq5_probe.py - exact VM-read view of seg27's descriptors.

LENQ tells us what the VM actually consumes (not what EMIT shows):
 1. claims stream (..36c0, 97 reads): full (slot,value) dump; tail words;
    does it match the EMIT 97w claims exactly?
 2. #7 stream (..3d50) and #2 stream (..3b70): all reads.
 3. #4 streams (..cf0/..4950) and #0 stream (..4bc0): full dumps --
    exact word sequences the VM reads (order matters for FinEx input!).
 4. #9 stream: which stream carries fad0f10d, how many reads?
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
L = d.get("lenq", [])


def be4(v):
    return "%08x" % (v & 0xFFFFFFFF)


by_st = {}
for e in L:
    by_st.setdefault(e[0], []).append((e[1], e[2] & 0xFFFFFFFF))
print("streams: %d total reads: %d" % (len(by_st), len(L)))
# claims stream: the one with 97 reads ending ...36c0
for st, reads in sorted(by_st.items(), key=lambda x: str(x[0])):
    if len(reads) == 97 and str(st).endswith("36c0"):
        print("== claims stream %s ==" % st)
        for n, v in reads:
            print("   slot=%s val=%s" % (n, be4(v)))
# #7 / #2 single-read streams
for st, reads in sorted(by_st.items(), key=lambda x: str(x[0])):
    if len(reads) == 1 and str(st).endswith(("3d50", "3b70", "16b0", "3570", "3cc0")):
        print("single %s slot=%s val=%s" % (st, reads[0][0], be4(reads[0][1])))
# #4 streams full
for st in [s for s in by_st if str(s).endswith(("3cf0", "4950"))]:
    print("== #4 stream %s reads=%d ==" % (st, len(by_st[st])))
    for n, v in by_st[st]:
        print("   slot=%s val=%s" % (n, be4(v)))
# #0 stream full (..4bc0, 56 reads)
for st in [s for s in by_st if str(s).endswith("4bc0")]:
    print("== #0 stream %s reads=%d ==" % (st, len(by_st[st])))
    for n, v in by_st[st]:
        print("   slot=%s val=%s" % (n, be4(v)))
# #9 stream: find fad0f10d
for st, reads in sorted(by_st.items(), key=lambda x: str(x[0])):
    hit = [(n, v) for n, v in reads if be4(v) == "fad0f10d"]
    if hit:
        print("== #9 stream %s reads=%d first-hits=%s ==" % (st, len(reads), hit[:4]))
        for n, v in reads[:12]:
            print("   slot=%s val=%s" % (n, be4(v)))
