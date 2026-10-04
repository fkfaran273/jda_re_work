"""d2_mech.py - mechanism trace: WHERE and HOW FinEx consumes d2 and d4.

Three instrumented runs on row 7 (base, d2^1, d4[4]^0x10000):
  - every load from the d4 data page (0x570000003000) and the d2 data page
    (0x570000004000): (pc, addr, value)
  - the full EMIT trace (all streams): first divergence point vs base
  - queue ops (PUSH/POP/CAP) for value-routing evidence
"""
import json
import struct
import sys
import time

sys.path.insert(0, '.')
import vm_final as V
from fin_vm2 import FinEx
import mint_pipeline as M

D4PAGE = 0x5700003000   # d4 data: dva = 0x5700000000 + 3*0x1000 (VA_ORDER pos 3)
D2PAGE = 0x5700004000   # d2 data: dva = 0x5700000000 + 4*0x1000 (VA_ORDER pos 4)

rows = json.load(open('all_signings.json', encoding='utf-8'))
pairs = {r['i']: r for r in json.load(open('pair_h3.json', encoding='utf-8'))}
r = rows[7]
sec = pairs[7]['second']
d0w = list(struct.unpack('>36I', bytes.fromhex(r['d0'])))
d2w = struct.unpack('>I', bytes.fromhex(r['d2']))[0]
d4w = list(struct.unpack('>8I', bytes.fromhex(r['d4'])))
claims = bytes.fromhex(r['d10'])
unp = len(claims)
padded = claims + b'\x00' * ((-unp) % 4)
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")


def mk(d0, d2, d4):
    by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
          2: (1, 0, d2), 7: (1, 0, struct.pack(">I", unp)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
          1: (0, 0, b""), 3: (0, 0, b"")}
    return [by[i] for i in M.VA_ORDER]


def descs_of(d2w_, d4w_):
    d0 = b''.join(struct.pack('>I', w) for w in d0w)
    d2 = struct.pack('>I', d2w_ & 0xFFFFFFFF)
    d4 = b''.join(struct.pack('>I', w) for w in d4w_)
    return mk(d0, d2, d4)


class TraceEx(FinEx):
    def ld(self, va, size=8):
        v = super().ld(va, size)
        a = (va & V.PM) & ~3
        if D4PAGE <= a < D2PAGE + 8:
            self._loadlog.append((self.pc, a, v))
        return v


def instrumented(d2w_, d4w_, tag):
    t = time.time()
    ex = TraceEx(sec, descs_of(d2w_, d4w_))
    ex._loadlog = []
    ex._emit_full = []
    ex._qop_log = []
    ex._cap_log = []
    status = ex.run(max_steps=60_000_000)
    loads = [{'pc': hex(pc), 'addr': hex(a), 'val': '%08x' % (v & 0xFFFFFFFF)}
             for (pc, a, v) in ex._loadlog]
    emits = [(sva & 0xFFFFFFFFFFFF, top, n, v)
             for (pc, sva, top, n, v) in ex._emit_full]
    out = {'tag': tag, 'status': status, 'steps': ex.steps,
           'nrand': ex.nrand,
           'loads': loads,
           'n_emits': len(emits),
           'emits': [[sva, top, n, v] for (sva, top, n, v) in emits],
           'qops': len(ex._qop_log), 'caps': len(ex._cap_log)}
    json.dump(out, open('d2_mech_%s.json' % tag, 'w'))
    print("[%s] status=%s steps=%d loads_d2d4=%d emits=%d qops=%d caps=%d "
          "(%.0f s)" % (tag, status, ex.steps, len(loads), len(emits),
                        len(ex._qop_log), len(ex._cap_log), time.time() - t),
          flush=True)
    return out


base_m = instrumented(d2w, d4w, 'base')
p2_m = instrumented(d2w ^ 1, d4w, 'd2xor1')
p4_m = instrumented(d2w, d4w[:4] + [d4w[4] ^ 0x00010000] + d4w[5:], 'd4_4b16')

# ---- first divergence in the EMIT stream ----
for tag, pm in (('d2xor1', p2_m), ('d4_4b16', p4_m)):
    eb, ep = base_m['emits'], pm['emits']
    k = 0
    while k < min(len(eb), len(ep)) and eb[k] == ep[k]:
        k += 1
    ctx = eb[max(0, k - 3):k + 3]
    print("[%s] first emit divergence at index %d/%d  ctx(base)=%s"
          % (tag, k, len(eb), ctx), flush=True)
    # sink-stream-only divergence (sva == 0x5500000000)
    ks = [i for i in range(min(len(eb), len(ep)))
          if eb[i][0] == 0x5500000000 and eb[i] != ep[i]]
    print("[%s] first SINK divergence at emit idx %s (n=%s)"
          % (tag, ks[0] if ks else None, eb[ks[0]][2] if ks else None),
          flush=True)
print("done", flush=True)
