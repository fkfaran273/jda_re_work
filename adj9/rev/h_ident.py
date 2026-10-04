# h_ident.py - IS descriptor #4 really H?
#
# Why: slice 99 measured #4 as NON-uniform (29 always-zero bits in bytes 0-7,
# byte-0 alphabet {00,02,04}): impossible for HMAC-SHA256 output. Either the
# harvester mis-segmented #4, or the 32-byte buffer is not the raw MAC. Both
# possibilities change the maker, so this script decides it by comparing the
# harvested #4 values against ground-truth H captures (nSign arg3 /
# Mac.doFinal), which the device traces contain.
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), 'device')
HEX32 = re.compile(r'^[0-9a-fA-F]{64}$')


def walk(o, path='', out=None):
    """collect every 32-byte hex string with its key path"""
    if out is None:
        out = []
    if isinstance(o, dict):
        for k, v in o.items():
            walk(v, path + '/' + str(k), out)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            walk(v, path + '[%d]' % i, out)
    elif isinstance(o, str):
        s = o[2:] if o.startswith('0x') else o
        if HEX32.match(s):
            out.append((path, s.lower()))
    return out


print('=== ground-truth H candidates ===')
truth = {}
for f in ('wh4_records.json', 'gold6.json', 'nsign_trace.json', 'wh4_nsign.json'):
    p = os.path.join(DEV, f) if f != 'wh4_records.json' else os.path.join(HERE, f)
    if not os.path.exists(p):
        p = os.path.join(DEV, f)
    if not os.path.exists(p):
        print('  (missing) %s' % f)
        continue
    d = json.load(open(p, encoding='utf-8'))
    hits = walk(d)
    keys = {}
    for path, val in hits:
        leaf = path.split('/')[-1].split('[')[0]
        keys.setdefault(leaf, set()).add(val)
    print('  %-20s 32-B-hex fields: %s'
          % (f, {k: len(v) for k, v in sorted(keys.items())}))
    for k, vs in keys.items():
        kl = k.lower()
        if any(t in kl for t in ('h', 'hmac', 'mac', 'arg3', 'nsign_in', 'doFinal',
                                 'sign_input')):
            truth.setdefault(k, set()).update(vs)
print()

# label H as: arg3 / mac_doFinal / nsign input when the key says so
HKEYS = [k for k in truth if any(t in k.lower() for t in
                                 ('arg3', 'hmac', 'mac', 'h_', '_h'))]
print('H-bearing fields: %s' % {k: len(v) for k, v in truth.items()})
HSET = set()
for k, vs in truth.items():
    if any(t in k.lower() for t in ('arg3', 'hmac', 'mac', 'h', 'doFinal')):
        HSET |= vs
print('total distinct ground-truth H candidates: %d' % len(HSET))
for h in sorted(HSET)[:6]:
    print('   %s  head8=%s' % (h, h[:16]))
print()

# ---- the corpus group: fin_descs #4, desc_det_result d4[], all_signings #4 ----
print('=== descriptor #4 as harvested by the repo ===')
groups = {}

fd = json.load(open(os.path.join(HERE, 'fin_descs.json'), encoding='utf-8'))
d4 = [d for d in fd['descs'] if d['build_idx'] == 4]
if d4:
    groups['fin_descs[4]'] = {d4[0]['data_hex'].lower()}

det = json.load(open(os.path.join(HERE, 'desc_det_result.json'), encoding='utf-8'))
groups['desc_det_result.d4'] = {
    b''.join(__import__('struct').pack('>I', v) for v in e['d4']).hex() for e in det}

als = json.load(open(os.path.join(HERE, 'all_signings.json'), encoding='utf-8'))
groups['all_signings.d4'] = {s['d4'].lower() for s in als if s.get('d4')}

for name, vals in groups.items():
    inH = [v for v in vals if v in HSET]
    print('  %-22s n=%-3d in ground-truth H set: %d/%d'
          % (name, len(vals), len(inH), len(vals)))
    for v in sorted(vals)[:8]:
        mark = ' <== MATCHES a captured H' if v in HSET else ''
        print('      %s%s' % (v, mark))
print()

# ---- uniformity: a real MAC must show none of this ----
import collections
allv = set()
for vs in groups.values():
    allv |= vs
print('=== uniformity check on the harvested #4 corpus (n=%d) ===' % len(allv))
if allv:
    bs = [bytes.fromhex(v) for v in allv]
    zerobits = [0] * 256
    for b in bs:
        for i in range(32):
            for bit in range(8):
                if not (b[i] >> bit) & 1:
                    zerobits[i * 8 + bit] += 1
    always0 = sum(1 for z in zerobits if z == len(bs))
    byte0 = collections.Counter(b[0] for b in bs)
    print('  always-zero bits across %d samples: %d / 256' % (len(bs), always0))
    print('  byte0 alphabet: %s' % {hex(k): v for k, v in sorted(byte0.items())})
    print('  (HMAC-SHA256 output must show ~0 always-zero bits and a wide alphabet)')
    print('  head bytes: %s' % sorted({b[:8].hex() for b in bs})[:8])