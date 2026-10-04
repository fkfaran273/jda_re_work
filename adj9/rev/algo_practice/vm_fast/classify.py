"""classify.py — phase breakdown of the 9.88M-step session signing.

Buckets executed steps into 0x400-byte pc windows, profiles each window's
mnemonic mix and semantic-bl mix, and labels the phase from the dominant work
(claims-byte queue MAC / SHA-256 compression / whitening / fixed overhead).
"""
import collections, os, pickle, sys
HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(HERE))
for p in (HERE, REV, os.path.join(REV, "creditsea")):
    if p not in sys.path:
        sys.path.insert(0, p)
import vm_final as V

SEM = {0x147630: "PUSH", 0x147734: "POP", 0x146470: "PUSH2", 0x146478: "POP2",
       0x146ed8: "EMIT", 0x147304: "LENQ", 0x1472e8: "OUTLEN",
       0x147120: "PUSHS", 0x147220: "POPS", 0x146558: "MKITER",
       0x146650: "ITERNEXT", 0x148d10: "RAND", 0x146474: "ISEMPTY",
       0x147a20: "CAP_SWAP", 0x14784c: "CAP_PUSH", 0x147a18: "CAP_PUSH0"}
SHA_OPS = {"eor", "ror", "ands", "lsr", "lsl", "add", "sub", "mvn", "bic", "extr"}
ROT_MIX = {"eor", "lsr", "lsl", "ands", "add", "sub", "mvn"}

d = pickle.load(open(os.path.join(HERE, "hist_session.pkl"), "rb"))
counts, pc_of = d["counts"], d["pc_of"]
total = sum(counts.values())
W = 0x400
win = collections.defaultdict(lambda: {"n": 0, "m": collections.Counter(),
                                       "s": collections.Counter()})
for k, n in counts.items():
    pc = pc_of.get(k, -1)
    w = (pc // W) * W
    e = win[w]
    e["n"] += n
    m, ops, _npc = V.FAST[k]
    e["m"][m] += n
    if m == "bl":
        e["s"][SEM.get(V.pt(ops), "bl?")] += n


def label(e):
    m, s = e["m"], e["s"]
    n = e["n"]
    q = sum(v for k, v in s.items() if k in ("PUSH", "PUSH2", "POP", "POP2",
                                            "CAP_PUSH", "CAP_PUSH0",
                                            "CAP_SWAP", "ITERNEXT", "ISEMPTY"))
    eorish = sum(v for k, v in m.items() if k in ROT_MIX)
    alush = m.get("and", 0) + m.get("ands", 0)
    if eorish / n > 0.34 and alush / n > 0.02:
        return "SHA-256-style compression (eor/lsr/lsl/ands round mix)"
    if q / n > 0.10:
        return "claims-byte queue MAC (PUSH/POP/CAP/ITERNEXT per byte)"
    if m.get("eor", 0) / n > 0.15:
        return "whitening / block mixing (eor-dominated)"
    return "queue-program plumbing (ldr/mov/cbnz/cmp)"


rows = sorted(win.items(), key=lambda kv: -kv[1]["n"])
buckets = collections.Counter()
for _w, _e in win.items():
    buckets[label(_e)] += _e["n"]
mm = collections.Counter()
ss = collections.Counter()
for k, n in counts.items():
    m, ops, _ = V.FAST[k]
    mm[m] += n
    if m == "bl":
        ss[SEM.get(V.pt(ops), "bl?")] += n
print("=== 4-bucket classification (whole run, all 160 windows) ===")
for lab, n in buckets.most_common():
    print("  %-52s %12s  %5.2f%%" % (lab, format(n, ","), 100.0 * n / total))
_sha = sum(v for k, v in mm.items() if k in ("ands", "ror", "extr", "bic"))
_mov = sum(v for k, v in mm.items() if k in ("ldr", "mov", "cbnz", "bl", "cmp",
                                             "b.eq", "b.ne", "b.hs", "b.lt",
                                             "b.hi", "cbz", "tbz", "tbnz", "b"))
print("  SHA-256-only opcodes (ands/ror/extr/bic): %d steps (%.3f%%)"
      % (_sha, 100.0 * _sha / total))
print("  data-movement + control opcodes:          %d steps (%.2f%%)"
      % (_mov, 100.0 * _mov / total))
print()
print("TOTAL steps %s   (windows: %d)\n" % (format(total, ","), len(rows)))
print("%-10s %-12s %6s  %-52s %s" % ("window", "steps", "pct", "phase", "top ops"))
agg = collections.Counter()
for w, e in rows[:34]:
    lab = label(e)
    top = " ".join("%s:%s" % (k, format(v, ","))
                   for k, v in e["m"].most_common(5))
    sem = " ".join("%s:%s" % (k, format(v, ","))
                   for k, v in e["s"].most_common(4))
    print("%08x  %12s %5.2f%%  %-52s %s"
          % (w, format(e["n"], ","), 100.0 * e["n"] / total, lab,
             top + ("   [" + sem + "]" if sem else "")))
print("\n=== phase totals (all windows) ===")
for lab, n in agg.most_common():
    print("  %-52s %12s  %5.2f%%" % (lab, format(n, ","), 100.0 * n / total))
# whole-run mnemonic + semantic totals
mm = collections.Counter()
ss = collections.Counter()
for k, n in counts.items():
    m, ops, _ = V.FAST[k]
    mm[m] += n
    if m == "bl":
        ss[SEM.get(V.pt(ops), "bl?")] += n
print("\n=== whole-run semantic bl totals ===")
for k, v in ss.most_common():
    print("  %-10s %12s  %5.2f%%" % (k, format(v, ","), 100.0 * v / total))
