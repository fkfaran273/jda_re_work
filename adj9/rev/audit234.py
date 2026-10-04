"""Audit the 234 native-without-twin merge events + the F0-112 map diff."""
import json
HERE = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
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


nat = []
for i in range(NAT_END):
    e = evs[i]
    nat.append((cls_of(e['sink']), int(e['pos'], 16), int(e['val'], 16)))
print('nat events:', len(nat))
# emu stream twins need the emu trace; rebuild cheaply from saved out? not saved.
# Instead: positions rewritten later in the NATIVE stream itself (intermediates).
from collections import defaultdict
writes = defaultdict(list)
for idx, (c, p, v) in enumerate(nat):
    writes[(c, p)].append((idx, v))
multi = {k: v for k, v in writes.items() if len(v) > 1}
print('positions written >1x:', len(multi))
# classify last-write values vs earlier ones
inter_garbage = 0
tot_multi_writes = 0
heaplike = 0
for k, v in multi.items():
    tot_multi_writes += len(v)
    final = v[-1][1]
    for idx, val in v[:-1]:
        inter_garbage += 1
        if (val >> 28) in (0x7, 0xb) or (val & 0xFFFF0000) in (0xb4000000,):
            heaplike += 1
print('intermediate writes:', inter_garbage, 'heaplike-ish:', heaplike)
import collections
print('class histogram of intermediate writes:',
      dict(collections.Counter(k[0] for k in multi for _ in [0])))
# F0-112: locate in claims
f0_112_nat = writes.get(('F0', 112), [])
print('F0-112 writes:', [(i, hex(v)) for i, v in f0_112_nat])
# find dword 112 in descs[6] (#10 claims, 90 dw)? no - 90 dw only. F0 MAIN is bigger.
# show neighbor finals
for p in (110, 111, 112, 113, 114):
    w = writes.get(('F0', p), [])
    if w:
        print('F0 pos %d final=%08x (%r)' % (p, w[-1][1],
              bytes.fromhex('%08x' % w[-1][1]).decode('latin1', 'replace')))
