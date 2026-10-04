# analyze_pack.py - derive the #10 packing law analytically from golden desc bytes
import json, sys, os
HERE = r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev'
DEV  = r'C:/Users/Apps/Downloads/com.penti.app/adj9/device'

D = json.load(open(HERE + '/fin_descs.json'))
descs = D['descs']
print('=== golden descs (build_idx -> len_dw) ===')
for d in descs:
    print(' idx %2d  len_dw %3d  (%d bytes)' % (d['build_idx'], d['len_dw'], d['len_dw']*4))

by = {d['build_idx']: bytes.fromhex(d['data_hex']) for d in descs}
d10 = by[10]
d0  = by[0]
print('\n=== desc10 (%d bytes) ===' % len(d10))
print('first 96:', d10[:96].hex())
print('ascii-ish:', ''.join(chr(c) if 32 <= c < 127 else '.' for c in d10[:200]))
print('last 64 :', d10[-64:].hex())

# load golden msg candidates
cands = {}
for name, path in [('corpus', HERE + '/corpus.json'), ('own', HERE + '/own_capture.json')]:
    try:
        j = json.load(open(path))
        cands[name] = j
    except Exception as e:
        print('load', name, 'fail', e)
print('\n=== corpus keys:', list(cands.get('corpus', {}).keys()) if isinstance(cands.get('corpus'), dict) else type(cands.get('corpus')))
msg = None
try:
    si = cands['corpus']['sign_inputs'][0]
    print('sign_input[0] keys:', list(si.keys()))
    for k in ('msg', 'msg_hex', 'map_toString', 'toString'):
        if k in si:
            v = si[k]
            msg = bytes.fromhex(v) if k.endswith('hex') else v.encode()
            print('golden msg from', k, 'len', len(msg))
            break
except Exception as e:
    print('corpus msg extract fail:', e)

if msg:
    def show(tag, b):
        print(tag, len(b), b[:64].hex(), '|', ''.join(chr(c) if 32 <= c < 127 else '.' for c in b[:80]))
    show('msg   ', msg)
    show('desc10', d10)
    # containment checks
    for probe in (b'd016e7e4', b'com.penti.app', b'android5.7.0', b'KlcAG2cb', b'jut9tib0'):
        print('probe %-14s in msg %s  in desc10 %s' % (probe.decode(), probe in msg, probe in d10))
    # is desc10 == msg (or prefix/pad)?
    n = min(len(msg), len(d10))
    same = sum(1 for a, b in zip(msg[:n], d10[:n]) if a == b)
    print('common-prefix len msg/desc10:', end=' ')
    p = 0
    while p < n and msg[p] == d10[p]:
        p += 1
    print(p, 'of', n, 'same bytes:', same)
    if len(d10) > len(msg):
        tail = d10[len(msg):]
        print('desc10 tail beyond msg (%d bytes):' % len(tail), tail[:48].hex(),
              ''.join(chr(c) if 32 <= c < 127 else '.' for c in tail[:80]))
    elif len(msg) > len(d10):
        tail = msg[len(d10):]
        print('msg tail beyond desc10 (%d bytes):' % len(tail), tail[:48].hex())
