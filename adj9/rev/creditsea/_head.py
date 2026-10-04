"""_head.py — what d0 head phase does the GENUINE CREDITSEA device use?

We recovered (0x2b,0x48) from PENTI's capture.  The head is the one
descriptor constant that could legitimately differ PER APP.  Decode the genuine
creditsea blobs and brute-force the head, exactly as we did for penti.
"""
import sys, os, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9sign')
sys.path.insert(0, r'C:SERSAPPSDOWNLOADSM.PENTI.APPDJ9SIGN')
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
from testbed import mine_log, decode, region_parts
import desc10_58 as D
import signer_simple as sg

for s in mine_log():
    kind = s['val'].get('activity_kind', 'session')
    dec = decode(s['blob'])
    d0, d4, d2, pfx = region_parts(dec, s['second'])
    seed = int.from_bytes(d2, 'little')
    hits = []
    for a in range(0x20, 0x60):
        w, _, _ = sg.region(seed, 0, 0, head=(a,))
        b0 = b"".join(x.to_bytes(4, 'big') for x in w)
        if b0 == d0: hits.append((a,))
    for a in range(0x20, 0x60):
        for c in range(0x20, 0x60):
            w, _, _ = sg.region(seed, 0, 0, head=(a, c))
            b0 = b"".join(x.to_bytes(4, 'big') for x in w)
            if b0 == d0: hits.append((a, c))
    names = {43:'0x2b', 65:'0x41', 72:'0x48', 34:'0x22', 46:'0x2e', 7:'0x07'}
    print('%-11s second=%d  genuine d0=%s' % (kind, s['second'], d0[:16].hex()))
    print('     matching head phases: %s'
          % [ '(' + ','.join(names.get(x, hex(x)) for x in h) + ')' for h in hits ])
    # what does the runner's WIN_PHASE give?
    w, _, _ = sg.region(seed, 0, 0, head=sg.WIN_PHASE)
    b0 = b"".join(x.to_bytes(4, 'big') for x in w)
    print('     runner WIN_PHASE %s -> %s  %s'
          % (tuple(hex(x) for x in sg.WIN_PHASE), b0[:16].hex(),
             'MATCH' if b0 == d0 else 'MISMATCH'))
