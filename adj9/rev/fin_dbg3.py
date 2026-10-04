"""fin_dbg3.py — stage 3: register-level trace of the X-block iterations.
Captures (step, pc, w0, w2, w3, w21, x21, x26) each step in a window around
the divergence (default 9900..10250). Saves rev/fin_dbg3_out.json.
"""
import json, sys, time

sys.path.insert(0, "C:/Users/Apps/Downloads/com.penti.app/adj9/rev")
from fin_vm2 import FinEx

HERE = "C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
D = json.load(open(HERE + "/fin_descs.json"))
SEED = D["target"]["second"]

LO = int(sys.argv[1]) if len(sys.argv) > 1 else 9900
HI = int(sys.argv[2]) if len(sys.argv) > 2 else 10250


def main():
    descs = [(d["len_dw"], 0, bytes.fromhex(d["data_hex"])) for d in D["descs"]]
    ex = FinEx(SEED, descs)
    trace = []

    def hook(e):
        if LO <= e.steps <= HI:
            R = e.R
            trace.append((
                e.steps, e.pc,
                R.get("w0", 0), R.get("w1", 0), R.get("w2", 0), R.get("w3", 0),
                R.get("w21", 0), R.get("x21", 0) & 0xFFFFFFFF,
                R.get("x26", 0) & 0xFFFFFFFF,
            ))
    ex._step_hook = hook
    t0 = time.time()
    status = ex.run(max_steps=HI + 50)
    print("status=%s steps=%d captured=%d (%.1fs)" % (status, ex.steps, len(trace), time.time() - t0))
    json.dump(trace, open(HERE + "/fin_dbg3_out.json", "w"))
    print("saved fin_dbg3_out.json")


if __name__ == "__main__":
    main()
