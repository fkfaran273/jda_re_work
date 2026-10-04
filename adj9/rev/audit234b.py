"""Full twin-miss classification: rerun FinEx, diff native vs emu event streams."""
import json, struct, sys, os
HERE = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from collections import defaultdict, Counter
D = json.load(open(HERE + '/fin_descs.json'))
nat_raw = json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\device\whcap_hits7.json'))
evs = [e for e in nat_raw if e.get('tag') == 'emit']
seen = []
for i in range(147):
    s = evs[i]['sink']
    if not seen or seen[-1] != s:
        seen.append(s)
FIELD_SINKS = {}
for k, s in enumerate(seen):
    FIELD_SINKS[s] = k if k < 8 else 9
FIELD_SINKS[evs[352]['sink']] = 10
MERGE_SINK = evs[147]['sink']
NAT_END = 22272


def cls_of(s):
    if s in FIELD_SINKS:
        return 'F%d' % FIELD_SINKS[s]
    if s == MERGE_SINK:
        return 'M'
    return 'X'


nat = [(cls_of(evs[i]['sink']), int(evs[i]['pos'], 16), int(evs[i]['val'], 16))
       for i in range(NAT_END)]
descs = [(d['len_dw'], 0, bytes.fromhex(d['data_hex'])) for d in D['descs']]
ex = FinEx(D['target']['second'], descs)
st = ex.run(max_steps=20_000_000)
print('status:', st, 'steps:', ex.steps, flush=True)
slotmap = {0x5500000000 + 0x1000 * i: 'F%d' % i for i in range(16)}
emu = []
for (sva, n, v) in ex.emit_trace:
    sva &= 0xFFFFFFFFFFFF
    if sva in slotmap:
        cls = slotmap[sva]
    elif sva == 0x5450001000:
        cls = 'M'
    else:
        cls = 'X'
    emu.append((cls, n & 0xFFFFFFFF, v & 0xFFFFFFFF))
eset = Counter(emu)
miss = []
for e in nat:
    if eset[e] > 0:
        eset[e] -= 1
    else:
        miss.append(e)
print('misses:', len(miss), flush=True)
print('miss class hist:', dict(Counter(m[0] for m in miss)), flush=True)
# heaplike?
hl = sum(1 for m in miss if (m[2] >> 28) in (0x7, 0xb) or (m[2] & 0xFFFF0000) == 0xb4000000)
print('heaplike values:', hl, flush=True)
# do miss positions get a LATER native write (intermediate) or is miss the final?
writes = defaultdict(list)
for idx, (c, p, v) in enumerate(nat):
    writes[(c, p)].append((idx, v))
inter = sum(1 for m in miss if writes[(m[0], m[1])][-1][1] != m[2])
final = len(miss) - inter
print('miss-is-intermediate(overwritten later):', inter, 'miss-is-final:', final, flush=True)
for m in miss:
    if writes[(m[0], m[1])][-1][1] == m[2]:
        print('FINAL-MISS:', m[0], m[1], '%08x' % m[2], flush=True)
# F0 ascii context 100..125
fm = {}
for (c, p, v) in nat:
    if c == 'F0':
        fm[p] = v
raw = b''.join(struct.pack('>I', fm[p]) for p in range(100, 126) if p in fm)
print('F0[100..126) ascii:', raw.decode('latin1', 'replace'), flush=True)
