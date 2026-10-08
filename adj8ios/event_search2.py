"""General single-edit search for a failing claims string (fast oracle).

The preimage prefix (d9 || 00 08 || head16 || LE32(S) || sha256("") || variant)
is 75 bytes for every request, so its first 64-byte block state is constant per
blob.  Precompute it once, then every candidate claim costs only its own blocks.
"""
import re, sys, os, struct, urllib.parse as up
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from carve import carve_chls, carve_query, split_blob, CLAIMS, SHA0, IV2, _sha256_block
from event_search import Oracle, build, body_for, POOL_M, POOL_R

def search(pt, params, ak, sdk, verbose=True):
    orc = Oracle(pt)
    base = build(params, ak)
    n = len(base)
    if orc.ok(base):
        return ('already', None)
    cand = {str(v) for v in params.values()}
    cand |= {ak, sdk, '1400000', '9', '3.67.0', '1', '0', 'event', 'ios',
             'com.niceonesa', 'com.ma.waveapp', 'iPhone12,1', 'iPhone10,1', '5.6.9', '3.8.0'}
    cand |= set(k for k in params)
    cand = {c for c in cand if c and c.encode('latin-1', 'ignore')}
    tries = 0
    for c in sorted(cand):
        cb = c.encode('latin-1', 'ignore')
        for p in range(n + 1):
            tries += 1
            if orc.ok(base[:p] + cb + base[p:]):
                return ('insert', c, p)
    for p in range(n):
        for ln in (1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 40, 48, 56, 64, 80):
            if p + ln <= n:
                tries += 1
                if orc.ok(base[:p] + base[p+ln:]):
                    return ('delete', base[p:p+ln].decode('latin-1'), p)
    for c in sorted(cand):
        cb = c.encode('latin-1', 'ignore')
        for p in range(n + 1):
            for ln in (1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 40, 48, 56, 64, 80):
                if p + ln <= n:
                    tries += 1
                    if orc.ok(base[:p] + cb + base[p+ln:]):
                        return ('replace', c, p, base[p:p+ln].decode('latin-1'))
    if verbose:
        print('   (no single edit explains it; %d candidates tried, claims=%dB)'
              % (tries, n))
    return None

if __name__ == '__main__':
    path = sys.argv[1]
    i = int(sys.argv[2])
    ak = sys.argv[3] if len(sys.argv) > 3 else 'event'
    raw = open(path, 'rb').read().decode('latin-1')
    items = carve_chls(path)
    _idx, bufs, kind, blob, sdk = items[i-1]
    sigpos = [m.start() for m in re.finditer(r'Signature signature="([A-Za-z0-9+/=]+)"', raw)]
    q = body_for(raw, sigpos[i-1])
    params = dict(up.parse_qsl(q, keep_blank_values=True))
    pt, t, h = split_blob(blob)
    print('%s #%d  params=%d sdk=%s ak=%s' % (os.path.basename(path), i, len(params), sdk, ak))
    print('  result:', search(pt, params, ak, sdk))
