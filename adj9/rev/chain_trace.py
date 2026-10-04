"""chain_trace.py — full instrumented trace of the merge program (row 7)."""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as M

ROW = int(sys.argv[1]) if len(sys.argv) > 1 else 7

def main():
    asg = json.load(open(os.path.join(HERE, "all_signings.json")))
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    r, p = asg[ROW], ph3[ROW]
    descs = []
    for bi in M.VA_ORDER:
        hx = r.get("d%d" % bi, "")
        data = bytes.fromhex(hx) if hx else b""
        descs.append((len(data) // 4, 0, data))
    ex = M.FinEx(int(p["second"]), descs)
    for k in ("_qop_log", "_emit_pc", "_lenq_log", "_sp_log", "_cap_log"):
        ex.__dict__[k] = []
    st = ex.run(max_steps=60_000_000)
    print("status", st, "steps", ex.steps)
    for k in ("_qop_log", "_emit_pc", "_lenq_log", "_sp_log", "_cap_log"):
        print(k, len(ex.__dict__[k]))
    json.dump({k: ex.__dict__[k] for k in
               ("_qop_log", "_emit_pc", "_lenq_log", "_sp_log", "_cap_log")},
              open(os.path.join(HERE, "chain_trace_row%d.json" % ROW), "w"))
    json.dump({("%x" % va): {"top": s.top, "acc": s.acc,
                             "offs": {str(k): v for k, v in s.offs.items()}}
               for va, s in ex.streams.items() if s.offs},
              open(os.path.join(HERE, "chain_streams_row%d.json" % ROW), "w"))

if __name__ == "__main__":
    main()
