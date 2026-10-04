"""fin_recompute.py — from-inputs 44/44(+4) body recompute for the whcap_hits7
first signing (= adj9_wh4.log nsign #7, blob 5595c3c4…, second 1789240512).

Runs rev/vm_final.Ex over the REAL 11 descriptors (147 dwords from the live
field loop) and then:
  1. compares the emulator's merge-phase EMITs event-by-event against the 205
     live merge events (ground truth, sink …2fdee0) — first divergence report;
  2. reconstructs per-sink pos->val output maps and searches the best
     48-dword window vs the target blob (4 header + 44 body).

Usage: python fin_recompute.py [--seed S]
"""
import json
import struct
import sys

sys.path.insert(0, ".")
from fin_vm2 import FinEx as Ex  # corrected native stream/queue semantics

HERE = "C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
D = json.load(open(HERE + "/fin_descs.json"))
SEED = D["target"]["second"]
TGT = bytes.fromhex(D["target"]["blob_hex"])
TGT_DW = [struct.unpack_from(">I", TGT, 4 * i)[0] for i in range(48)]
MERGE_GT = [(p, v) for p, v in D["merge_events"]]          # 205 live merge events
N_FIELD_EVENTS = sum(d["len_dw"] for d in D["descs"])       # 147


def build_descs():
    out = []
    for d in D["descs"]:
        out.append((d["len_dw"], 0, bytes.fromhex(d["data_hex"])))
    return out


def run(seed, max_steps=8_000_000):
    descs = build_descs()
    ex = Ex(seed, descs)
    status = ex.run(max_steps=max_steps)
    return ex, status


def sink_maps(ex, max_pos=1 << 22):
    from collections import defaultdict
    maps = defaultdict(dict)
    for (s, n, v) in ex.emit_trace:
        if n < max_pos:
            maps[s][n] = v
    return maps


def best_window(arr, tgt, win=48):
    best = (0, 0)
    for st in range(0, max(1, len(arr) - win + 1)):
        c = sum(1 for k in range(win) if st + k < len(arr) and arr[st + k] == tgt[k])
        if c > best[0]:
            best = (c, st)
    return best


def compare_merge(ex, n_gt=len(MERGE_GT)):
    """Emulator merge phase = emit_trace events after the 147 field events,
    restricted to whichever sink the first post-field EMIT targets (the real
    merge writes one sink). Returns (matched, first_div, sink_va)."""
    tail = ex.emit_trace[N_FIELD_EVENTS:]
    if not tail:
        return 0, None, None, tail
    sink = tail[0][0]
    seq = [(n, v) for (s, n, v) in tail if s == sink]
    matched = 0
    first_div = None
    for k, ((pn, pv), (gn, gv)) in enumerate(zip(seq, MERGE_GT)):
        if pn != gn or pv != gv:
            first_div = (k, pn, pv, gn, gv)
            break
        matched += 1
    return matched, first_div, sink, seq


def main():
    seed = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[1] == "--seed" else SEED
    ex, status = run(seed)
    print("seed=%d  status=%s  steps=%d  nrand=%d" % (seed, status, ex.steps, ex.nrand))
    w = ex.mem.get(ex.W)
    print("writer cell:", None if w is None else "%#x" % w)
    print("emit_trace events: %d (field loop = first %d)" % (len(ex.emit_trace), N_FIELD_EVENTS))

    # ---- 1. merge ground-truth comparison ----
    matched, first_div, sink, seq = compare_merge(ex)
    if sink is None:
        print("MERGE: emulator produced NO post-field emits (merge did not run)")
    else:
        print("MERGE sink va=%x: emulator merge events=%d  matched %d/%d event-by-event"
              % (sink, len(seq), matched, len(MERGE_GT)))
        if first_div:
            k, pn, pv, gn, gv = first_div
            print("  FIRST DIVERGENCE at event %d:" % k)
            print("    emulator: pos=%d val=%08x" % (pn, pv))
            print("    real    : pos=%d val=%08x" % (gn, gv))
            print("  context (emulator events %d..%d):" % (max(0, k - 4), k + 4))
            for j in range(max(0, k - 4), min(len(seq), k + 5)):
                mark = " <<" if j == k else ""
                g = MERGE_GT[j] if j < len(MERGE_GT) else None
                print("    [%4d] emu pos=%-4d val=%08x   gt %s%s"
                      % (j, seq[j][0], seq[j][1],
                         ("pos=%-4d val=%08x" % g) if g else "-", mark))
        elif matched < len(MERGE_GT):
            print("  emulator merge ran SHORT: %d events vs %d ground truth"
                  % (len(seq), len(MERGE_GT)))

    # ---- 2. output-stream window search ----
    maps = sink_maps(ex)
    print("\noutput-window search vs target (48 dwords):")
    results = []
    for s, am in maps.items():
        mx = (max(am) + 1) if am else 0
        mx = min(mx, 1 << 22)
        arr = [am.get(i) for i in range(mx)]
        c, st = best_window(arr, TGT_DW)
        results.append((c, s, st, mx))
    results.sort(reverse=True)
    for c, s, st, mx in results[:6]:
        print("  sink %#x len=%-5d best %d/48 at pos %d" % (s, mx, c, st))
    c0 = results[0][0] if results else 0
    print("\nBEST MATCH: %d/48 dwords" % c0)
    return ex, results, matched, first_div


if __name__ == "__main__":
    main()
