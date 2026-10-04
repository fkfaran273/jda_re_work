"""Robust body mint: read the SINK stream directly, no header-law filter."""
import struct, sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mint_pipeline as M


def mint_body(dmap, second, sink=None, max_steps=60_000_600):
    """dmap: {bi: bytes}.  Returns list of 44 body words (blob[16:])."""
    sink = M.SINK if sink is None else sink
    descs = [(len(dmap[bi]) // 4, 0, dmap[bi]) for bi in M.VA_ORDER]
    ex = M.FinEx(int(second), descs)
    ex.run(max_steps=max_steps)
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    bys = {}
    for ((sva, n), v) in last.items():
        bys.setdefault(sva, {})[n] = v
    if sink not in bys:
        return None, sorted(bys)
    s = bys[sink]
    return [s.get(k, 0) for k in range(4, 4 + 44)], None
