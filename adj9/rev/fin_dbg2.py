"""fin_dbg2.py — stage 2: full op logs (LENQ/PUSH/POP/CAP/PUSHS/POPS + pc log)
from step 0 to just past the merge divergence (step ~10157).
Saves rev/fin_dbg2_out.json (+ a readable timeline print).
"""
import json, struct, sys, time

sys.path.insert(0, "C:/Users/Apps/Downloads/com.penti.app/adj9/rev")
from fin_vm2 import FinEx

HERE = "C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
D = json.load(open(HERE + "/fin_descs.json"))
SEED = D["target"]["second"]
MERGE_GT = [tuple(e) for e in D["merge_events"]]
N_FIELD = sum(d["len_dw"] for d in D["descs"])
STOP = int(sys.argv[1]) if len(sys.argv) > 1 else 11000


def main():
    descs = [(d["len_dw"], 0, bytes.fromhex(d["data_hex"])) for d in D["descs"]]
    ex = FinEx(SEED, descs)
    ex._sp_log = []
    ex._qop_log = []
    ex._cap_log = []
    ex._lenq_log = []
    ex._emit_pc = []
    ex._pc_log = []
    t0 = time.time()
    status = ex.run(max_steps=STOP)
    dt = time.time() - t0
    print("status=%s steps=%d nrand=%d (%.1f s)" % (status, ex.steps, ex.nrand, dt))
    print("emit_trace=%d  sp=%d qop=%d cap=%d lenq=%d pclen=%d" % (
        len(ex.emit_trace), len(ex._sp_log), len(ex._qop_log),
        len(ex._cap_log), len(ex._lenq_log), len(ex._pc_log)))

    # merge events with pc+step
    sink = ex.emit_trace[N_FIELD][0]
    me = [e for e in ex._emit_pc if e[1] == sink]
    print("merge sink %#x, %d merge emits" % (sink & 0xFFFFFFFFFFFF, len(me)))
    print("\nmerge events 180..end (idx, pc, n, v, step):")
    for j in range(180, len(me)):
        print("  [%3d] pc=%#x n=%-4d v=%-10d" % (j, me[j][0], me[j][2], me[j][3]))

    print("\n_sp_log (PUSHS/POPS) entries with step <= %d:" % STOP)
    for e in ex._sp_log:
        print("  %s pc=%#x sink=%#x acc=%d top=%s" % (
            e[0], e[1], e[2] & 0xFFFFFFFFFFFF, e[3], e[4]))

    print("\n_qop_log tail:")
    for e in ex._qop_log[-60:]:
        print("  %s pc=%#x val=%d" % (e[0], e[1], e[2]))

    print("\n_cap_log tail:")
    for e in ex._cap_log[-40:]:
        print("  %s pc=%#x qlen=%d k=%d q[:6]=%s" % (e[0], e[1], e[2], e[3], e[4]))

    out = {
        "status": status, "steps": ex.steps,
        "sink": sink,
        "merge_emits": [[j, e[0], e[2], e[3]] for j, e in enumerate(me)],
        "sp_log": [list(e) for e in ex._sp_log],
        "qop_log": [[e[0], e[1], e[2]] for e in ex._qop_log],
        "cap_log": [list(e[:4]) + [list(e[4])] for e in ex._cap_log],
        "lenq_log": [list(e) for e in ex._lenq_log],
        "pc_log": list(ex._pc_log),
        "emit_pc": [[e[0], e[1], e[2], e[3]] for e in ex._emit_pc],
    }
    json.dump(out, open(HERE + "/fin_dbg2_out.json", "w"))
    print("saved fin_dbg2_out.json")


if __name__ == "__main__":
    main()
