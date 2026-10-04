"""fast zone-word mint: early-stop the FinEx VM once the sink has emitted
the words we need."""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as M
from header_gen import make_header
SINK = M.SINK

def mint_words(descs, second, nwords=4, max_steps=60_000_600):
    ex = M.FinEx(int(second), descs)
    got = {}
    hdr = struct.unpack(">4I", make_header(int(second)))
    hit = [False]*4
    def on_emit(sva, n, v):
        if (sva & 0xFFFFFFFFFFFF) == SINK:
            n &= 0xFFFFFFFF
            if n < nwords:
                got[n] = v & 0xFFFFFFFF
                if len(got) == nwords:
                    for i in range(4):
                        if got.get(i, 0) != hdr[i]:
                            return
    ex._emit_pc = []
    st = ex.run(max_steps=max_steps)
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    bys = {}
    for ((sva, n), v) in last.items():
        bys.setdefault(sva, {})[n] = v
    if SINK in bys and tuple(bys[SINK].get(k, 0) for k in range(4)) == hdr:
        s = bys[SINK]
    else:
        for sva in sorted(bys):
            if tuple(bys[sva].get(k, 0) for k in range(4)) == hdr:
                s = bys[sva]; break
        else:
            raise RuntimeError("no stream for %d status=%s" % (second, st))
    return [s.get(k, 0) for k in range(nwords)], st, ex.steps
