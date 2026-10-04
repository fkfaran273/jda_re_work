"""_rp2.py — runner's signer vs genuine blobs, WITH the genuine per-fill seed."""
import sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from testbed import mine_log, decode, region_parts, build_descs
import desc10_58 as D
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj9sign')
import signer_simple as sg

sg.DESC9 = bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")
_o = D.claims_for_law_58
def c58(val, kind):
    v = dict(val); v["client_sdk"] = "flutter5.8.0@android5.8.0"
    return _o(v, kind)
sg.claims_for_law = c58

for s in mine_log():
    kind = s['val'].get('activity_kind', 'session')
    dec = decode(s['blob'])
    d0, d4, d2, pfx = region_parts(dec, s['second'])
    # recover the genuine per-fill seed from the decoded d2
    import struct
    seed = int.from_bytes(d2, 'little') ^ ((sg.__dict__.get('DEFAULT_PID', 0) & 0xFFFF) << 16)
    blob, sec, info = sg.sign_request(s['val'], kind, second=s['second'], seed=seed & 0xFFFFFFFF)
    h = bytes(blob)
    n = sum(1 for a, b in zip(h, s['blob']) if a == b)
    print('%-11s second=%d  seed=0x%08x  %d/192  %s'
          % (kind, s['second'], seed & 0xFFFFFFFF, n,
             'BYTE-EXACT' if h == s['blob'] else 'MISMATCH'))
