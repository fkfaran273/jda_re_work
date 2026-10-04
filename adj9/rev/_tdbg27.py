"""_tdbg27.py — watchpoint: follow the tainted node created at step 333579
(and w2, w0, w21 -> 0x96) through the machine: every op that consumes a node
equal to it, every push/pop/emit of it.  NEW file.
"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(400000)

import vm_taint as T
import vm_final as V

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.FinEx(second, descs)
tn = T.Taint(ex, T.default_seednames())

WATCH = []          # ids to watch (grows: anything derived from a watched node)
LOG = []
_orig_apply = tn._apply
ARMED = [False]


def kidids(nd):
    if nd[0] == "op":
        return [c for c in nd[4]]
    if nd[0] == "sel":
        return [nd[1], nd[2]]
    return []


def apply(pend):
    kind, extra, pc = pend
    if kind != "BL" and kind != "none" and kind != "mem" and kind != "cmp":
        dest, specs = T.parse_alu(pc, extra[0], extra[1]) if kind == "alu" \
            else (None, [])
        if dest is not None:
            kids = [tn.kid(sp, ex, pc) for sp in specs]
            hit = [i for i, k in enumerate(kids) if id(k) in WATCH]
            if hit and len(LOG) < 60:
                LOG.append(("alu", ex.steps, hex(pc), extra[0], extra[1],
                            [str(k)[:60] for k in kids], hit))
                for k in kids:
                    WATCH.append(id(k))
    if kind == "BL":
        for op in extra:
            if op[0] == "qpush" and id(op[2]) in WATCH and len(LOG) < 60:
                WATCH.append(id(op[2]))
                LOG.append(("qpush", ex.steps, hex(pc), str(op[2])[:60], "", []))
            if op[0] == "emit" and id(op[3]) in WATCH and len(LOG) < 60:
                LOG.append(("emit", ex.steps, hex(pc), str(op[3])[:60], "", []))
    # arm after step 333570
    if not ARMED[0] and ex.steps > 333570:
        ARMED[0] = True
    r = _orig_apply(pend)
    # after the 0x96 creation, add its node id
    if ARMED[0] and ex.pc == 0x104c34 and len(WATCH) == 0:
        pass
    return r


# simpler arming: after the 'and' at 0x104c28 executes (step 333579), watch w2
_orig_hook = tn.hook


def hook(e=None):
    e = e if e is not None else ex
    r = _orig_hook(e)
    if not ARMED[0] and e.steps >= 333580 and not WATCH:
        nd = tn.R.get("w2")
        if nd is not None and nd[0] == "op":
            WATCH.append(id(nd))
            LOG.append(("ARM", e.steps, hex(e.pc), str(nd)[:80], "", []))
    return r


tn.hook = hook
ex.__dict__["_step_hook"] = hook
st = ex.run(max_steps=60_000_000)
print("status=%s watch=%d logged=%d" % (st, len(WATCH), len(LOG)), flush=True)
for ent in LOG:
    print("  %s step=%s pc=%s %s %s kids=%s"
          % (ent[0], ent[1], ent[2], ent[3], ent[4], ent[5]), flush=True)
