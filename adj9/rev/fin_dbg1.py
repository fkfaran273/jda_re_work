"""fin_dbg1.py — stage 1: locate divergence in steps + EMIT call sites.

Runs FinEx with a step-correlated _emit_pc log, compares merge events,
dumps around first divergence. Saves rev/fin_dbg1_out.json.
"""
import json, struct, sys, time

sys.path.insert(0, "C:/Users/Apps/Downloads/com.penti.app/adj9/rev")
from fin_vm2 import FinEx

HERE = "C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
D = json.load(open(HERE + "/fin_descs.json"))
SEED = D["target"]["second"]
MERGE_GT = [tuple(e) for e in D["merge_events"]]
N_FIELD = sum(d["len_dw"] for d in D["descs"])


class StepLog(list):
    """list that appends (entry..., step) using the live executor's step."""
    def __init__(self, ex):
        super().__init__()
        self._ex = ex
    def append(self, v):
        try:
            super().append(tuple(v) + (self._ex.steps,))
        except TypeError:
            super().append((v, self._ex.steps))


def main():
    max_steps = int(sys.argv[1]) if len(sys.argv) > 1 else 2_000_000
    descs = [(d["len_dw"], 0, bytes.fromhex(d["data_hex"])) for d in D["descs"]]
    ex = FinEx(SEED, descs)
    ex._emit_pc = StepLog(ex)
    t0 = time.time()
    status = ex.run(max_steps=max_steps)
    dt = time.time() - t0
    print("status=%s steps=%d nrand=%d  (%.1f s)" % (status, ex.steps, ex.nrand, dt))
    print("emit_trace events: %d (field=%d)" % (len(ex.emit_trace), N_FIELD))

    from collections import Counter
    allcnt = Counter(s for (s, n, v) in ex.emit_trace)
    print("ALL sinks (event counts):")
    for s, c in allcnt.most_common():
        print("  %#x: %d" % (s & 0xFFFFFFFFFFFF, c))
    tail = ex.emit_trace[N_FIELD:]
    cnt = Counter(s for (s, n, v) in tail)
    print("tail sinks:", {hex(k & 0xFFFFFFFFFFFF): v for k, v in cnt.items()})
    sink = tail[0][0]
    seq = [(n, v) for (s, n, v) in tail if s == sink]
    print("merge sink %#x: %d emu events vs %d gt" % (sink & 0xFFFFFFFFFFFF, len(seq), len(MERGE_GT)))
    matched = 0
    first_div = None
    for k, ((pn, pv), (gn, gv)) in enumerate(zip(seq, MERGE_GT)):
        if pn != gn or pv != gv:
            first_div = k
            break
        matched += 1
    print("matched %d/%d, first_div=%s" % (matched, len(MERGE_GT), first_div))

    # step numbers of the merge EMITs (from _emit_pc: (pc, sink, n, v, step))
    me = [e for e in ex._emit_pc if e[1] == sink]
    print("emit_pc merge entries: %d" % len(me))
    out = {
        "status": status, "steps": ex.steps, "nrand": ex.nrand, "secs": dt,
        "sink": sink, "matched": matched, "first_div": first_div,
        "n_emu_merge": len(seq),
        "all_sink_counts": {hex(s & 0xFFFFFFFFFFFF): c for s, c in allcnt.most_common()},
        "field_first147": {},
        "div_context_emu": [],
        "div_context_gt": [],
        "emit_pc_around": [],
        "first_div_pc": None,
    }
    # field-phase events per sink (first 147) — compare with gt counts
    fcnt = Counter(s for (s, n, v) in ex.emit_trace[:N_FIELD])
    out["field_first147"] = {hex(s & 0xFFFFFFFFFFFF): c for s, c in fcnt.most_common()}
    print("field counts (first 147 events):", out["field_first147"])
    k0 = first_div if first_div is not None else len(seq)
    for j in range(max(0, k0 - 8), min(len(seq), k0 + 12)):
        out["div_context_emu"].append([j, seq[j][0], seq[j][1]])
        out["div_context_gt"].append([j, MERGE_GT[j][0], MERGE_GT[j][1]] if j < len(MERGE_GT) else None)
    if first_div is not None and first_div < len(me):
        # merge emit #k0 = me[k0] (1:1 with seq if all on same sink & order kept)
        out["first_div_pc"] = me[k0]
        for j in range(max(0, k0 - 10), min(len(me), k0 + 14)):
            out["emit_pc_around"].append([j, me[j][0], me[j][1], me[j][2], me[j][3], me[j][4]])
    # pcs used for the X-writes (pos 0) and out[i]-writes
    pcs_pos0 = {}
    pcs_out = {}
    for j, (n, v) in enumerate(seq):
        if j < len(me):
            pc = me[j][0]
            if n == 0:
                pcs_pos0[pc] = pcs_pos0.get(pc, 0) + 1
            elif 1 <= n <= 15:
                pcs_out[pc] = pcs_out.get(pc, 0) + 1
    out["pcs_pos0"] = {hex(k): v for k, v in pcs_pos0.items()}
    out["pcs_out"] = {hex(k): v for k, v in pcs_out.items()}
    json.dump(out, open(HERE + "/fin_dbg1_out.json", "w"), indent=1)
    print("pcs writing pos0:", out["pcs_pos0"])
    print("pcs writing out[1..15]:", out["pcs_out"])
    if out["first_div_pc"]:
        print("first_div emit_pc:", out["first_div_pc"])
    print("saved fin_dbg1_out.json")


if __name__ == "__main__":
    main()
