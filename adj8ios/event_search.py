"""Targeted claims search for the /event kind.

Not a blind byte-edit sweep: we vary the things that can plausibly differ --
which pool keys the SDK puts in the map, and the activity_kind token -- and
reuse the precomputed SHA-256 state of the fixed 75-byte preimage prefix so each
candidate costs only the claim blocks.
"""
import re, sys, os, struct, hashlib, urllib.parse as up
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from carve import carve_chls, carve_query, split_blob, CLAIMS, SHA0, IV2, _sha256_block

def _pad(msg):
    return (msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64)
            + struct.pack(">Q", len(msg) * 8))

def block_state(st, data):
    m = _pad(data)
    for i in range(0, len(m), 64):
        st = _sha256_block(st, struct.unpack(">16I", m[i:i + 64]))
    return st

class Oracle:
    """sha256_iv2(prefix || X) for a fixed 75-byte prefix."""
    def __init__(self, pt):
        self.pre = pt[25:45] + b"\x00\x08" + pt[3:19] + pt[20:24][::-1] + SHA0 + bytes((pt[112],))
        n = (len(self.pre) // 64) * 64
        self.head = block_state(list(IV2), self.pre[:n])
        self.rest = self.pre[n:]
        self.target = pt[46:78]
    def ok(self, claim_bytes):
        st = block_state(self.head, self.rest + claim_bytes)
        return struct.pack(">8I", *st) == self.target

POOL_M, POOL_R = CLAIMS['main'], CLAIMS['rest']
AKS = ['event', 'click', 'session', 'attribution', 'info', 'event_request',
       'adjust_event', 'event_tracking', 'eventtoken', 'EVENT', None, '']

def build(params, ak, drop=(), extra=None):
    p = dict(params)
    for k in drop:
        p.pop(k, None)
    parts = [str(p[k]) for k in POOL_M if p.get(k) not in (None, '')]
    parts.append('1400000')
    parts += [str(p[k]) for k in POOL_R if p.get(k) not in (None, '')]
    s = ''.join(parts) + '9' + '3.67.0'
    if extra:
        s = extra + s
    return s.encode('latin-1')

def body_for(raw, pos):
    anchors = [m.start() for m in
               re.finditer(r'(?:app_version|bundle_id|app_token|idfv|idfa|event_token)=', raw[:pos])]
    return carve_query(raw, anchors[-1])

if __name__ == '__main__':
    targets = [(r"C:\Users\Apps\Downloads\wave_19may_install_newapp_ios8.chls", 6),
               (r"C:\Users\Apps\Downloads\niceoneiosauto_6may_lvl2_ios11.chls", 7),
               (r"C:\Users\Apps\Downloads\niceoneiosauto_6may_lvl2_ios11.chls", 18)]
    for path, i in targets:
        raw = open(path, 'rb').read().decode('latin-1')
        items = carve_chls(path)
        _idx, bufs, kind, blob, sdk = items[i-1]
        sigpos = [m.start() for m in re.finditer(r'Signature signature="([A-Za-z0-9+/=]+)"', raw)]
        params = dict(up.parse_qsl(body_for(raw, sigpos[i-1]), keep_blank_values=True))
        pt, t, h = split_blob(blob)
        orc = Oracle(pt)
        found = None
        present = [k for k in POOL_M + POOL_R if params.get(k) not in (None, '')]
        # 1) ak sweep
        for ak in AKS:
            p = dict(params)
            if ak is None:
                cl = build(params, None).replace(('activity_kind' and b''), b'')
                parts = [str(params[k]) for k in POOL_M if params.get(k) not in (None, '')] + ['1400000']
                parts += [str(params[k]) for k in POOL_R if k != 'activity_kind' and params.get(k) not in (None, '')]
                cl = (''.join(parts) + '93.67.0').encode()
            else:
                cl = build(params, ak)
            if orc.ok(cl):
                found = ('ak', ak); break
        # 2) drop up to two pool keys, ak='event'
        if not found:
            import itertools
            for r in (1, 2):
                for combo in itertools.combinations(present, r):
                    for ak in ('event', None, 'click'):
                        p = dict(params)
                        for k in combo:
                            p.pop(k, None)
                        if ak:
                            cl = build(p, ak)
                        else:
                            parts = [str(p[k]) for k in POOL_M if p.get(k) not in (None, '')] + ['1400000']
                            parts += [str(p[k]) for k in POOL_R if k != 'activity_kind' and p.get(k) not in (None, '')]
                            cl = (''.join(parts) + '93.67.0').encode()
                        if orc.ok(cl):
                            found = ('drop', combo, ak); break
                    if found: break
                if found: break
        # 3) prepend/append any single param value not already in the claims
        if not found:
            base = build(params, 'event')
            vals = {str(v) for v in params.values()} | {'event', 'ios', 'iPhone12,1', '1', '0'}
            for v in vals:
                if not v: continue
                vb = v.encode()
                if orc.ok(vb + base) or orc.ok(base + vb):
                    found = ('affix', v); break
        print('%-26s #%-3d -> %s' % (os.path.basename(path)[:26], i, found))
