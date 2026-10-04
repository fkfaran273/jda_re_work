# oracle_pairs.py — properly pair OVERLAPPING nSign calls (FIFO by completion)
# and analyze the 3 same-header pairs we have:
#   run4 hflip:  in#1@+6.648->out@+7.454, in#2@+7.036->out@+7.830  (same sec!)
#   run7 rapid:  t0 1788956309411 / 1788956310340  (rows 4,5)
#                t0 1788956314443 / 1788956315253  (rows 10,11)
import re, sys, os, json

def parse_events(path):
    ev, cur = [], None
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\S+) ts=(\d+)", ln)
        if m:
            cur = {"type": m.group(1), "ts": int(m.group(3)), "body": []}
            ev.append(cur); continue
        if cur is not None:
            if ln.startswith("###ADJ9_END"): cur = None; continue
            cur["body"].append(ln.rstrip("\n"))
    return ev

def txt(e): return "\n".join(e["body"])
def fld(e, name):
    m = re.search(r"(?:^|\s)" + name + r"=([^\s]+)", txt(e), re.M)
    return m.group(1) if m else None

def calls_of(path):
    ev = parse_events(path)
    ins, outs = [], []
    for e in ev:
        if e["type"] == "nsign_in":
            ins.append(e)
        elif e["type"] == "nsign":
            outs.append(e)
    # FIFO pairing: i-th completion belongs to i-th entry
    pairs = []
    for i in range(min(len(ins), len(outs))):
        pairs.append({"t_in": ins[i]["ts"], "arg3": fld(ins[i], "arg3_hex"),
                      "arg4": fld(ins[i], "arg4_int"),
                      "t_out": outs[i]["ts"], "blob": fld(outs[i], "hex")})
    return pairs

CAP = "C:/Users/Apps/Downloads/com.penti.app/adj9/cap"

print("=== run4: FIFO pairing (fixes the overwritten nsign_in) ===")
r4 = calls_of(CAP + "/oracle_run4.log")
for c in r4:
    print("t_in=%d arg3=%s lvl=%s  t_out=%d  blob16=%s" % (
        c["t_in"], (c["arg3"] or "?")[:16], c["arg4"], c["t_out"], (c["blob"] or "?")[:32]))

print("\n=== run7: rapid-fire calls ===")
r7 = calls_of(CAP + "/oracle_run7.log")
print("calls:", len(r7))
for c in r7:
    print("t_in=%d arg3=%s lvl=%s  t_out=%d  blob16=%s" % (
        c["t_in"], (c["arg3"] or "?")[:16], c["arg4"], c["t_out"], (c["blob"] or "?")[:32]))

def diff_bodies(a, b, name):
    A, B = bytes.fromhex(a), bytes.fromhex(b)
    assert len(A) == len(B) == 192
    ba, bb = A[16:], B[16:]
    diff = [i for i in range(176) if ba[i] != bb[i]]
    print("\n--- %s ---" % name)
    print("hdr same: %s" % (A[:16] == B[:16]))
    print("body diff: %d/176 bytes" % len(diff))
    if diff:
        # 16-byte block locality
        blocks = sorted(set(i // 16 for i in diff))
        print("diff spans 16B-blocks: %s" % blocks)
        # leading common prefix of body
        cp = 0
        while cp < 176 and ba[cp] == bb[cp]: cp += 1
        print("body common prefix: %d bytes" % cp)
        # print first 32 bytes of each body
        print("  A body[0:32]:", ba[:32].hex())
        print("  B body[0:32]:", bb[:32].hex())
        print("  A body[-32:]:", ba[-32:].hex())
        print("  B body[-32:]:", bb[-32:].hex())
    # bit-level hamming on body
    ham = sum(bin(x ^ y).count("1") for x, y in zip(ba, bb))
    print("body hamming: %d bits / 1408 (%.1f%%)" % (ham, 100.0 * ham / 1408))

# find the same-header pairs
def find_pairs(runs, name):
    from collections import defaultdict
    by = defaultdict(list)
    for c in runs:
        if c["blob"]:
            by[bytes.fromhex(c["blob"])[:16].append]  if False else None
    return
