"""Structural sweep for the /event block preimage.

Every search so far varied the CLAIMS.  This one varies the preimage itself,
which is the other half of the block hash:

  * the variant byte (0x00..0xFF, not just the 0x02 the record carries)
  * the variant byte absent
  * an extra 16-byte descriptor (the adj9-ios "dev" field)
  * claims with / without the activity_kind
"""
import re, sys, os, struct, urllib.parse as up
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from carve import carve_chls, split_blob, SHA0, IV2, _sha256_block, CLAIMS
from event_search import body_for


def _pad(m):
    return (m + b"\x80" + b"\x00" * ((55 - len(m)) % 64)
            + struct.pack(">Q", len(m) * 8))


def sha_iv2(msg):
    st = list(IV2)
    m = _pad(msg)
    for i in range(0, len(m), 64):
        st = _sha256_block(st, struct.unpack(">16I", m[i:i + 64]))
    return struct.pack(">8I", *st)


def claims(params, ak, sdk):
    p = dict(params); p['client_sdk'] = sdk
    if ak:
        p['activity_kind'] = ak
    else:
        p.pop('activity_kind', None)
    parts = ([str(p[k]) for k in CLAIMS['main'] if p.get(k) not in (None, '')]
             + ['1400000']
             + [str(p[k]) for k in CLAIMS['rest'] if p.get(k) not in (None, '')])
    return (''.join(parts) + '9' + '3.67.0').encode('latin-1')


def dev16(device_name):
    d = device_name.encode('latin-1')[:16]
    return d + b'\x00' * (16 - len(d))


def sweep(path, idx):
    raw = open(path, 'rb').read().decode('latin-1')
    items = carve_chls(path)
    _i, bufs, kind, blob, sdk = items[idx - 1]
    sigpos = [m.start() for m in re.finditer(r'Signature signature="([A-Za-z0-9+/=]+)"', raw)]
    params = dict(up.parse_qsl(body_for(raw, sigpos[idx - 1]), keep_blank_values=True))
    pt, t, h = split_blob(blob)
    d9, head, S = pt[25:45], pt[3:19], pt[20:24][::-1]
    base = d9 + b"\x00\x08" + head + S + SHA0
    dn = params.get('device_name', 'iPhone10,1')
    hits = []
    for ak in ('event', 'click', 'session', 'attribution', 'info', None):
        cl = claims(params, ak, sdk)
        for v in range(256):
            if sha_iv2(base + bytes((v,)) + cl) == pt[46:78]:
                hits.append(('variant', ak, v))
        if sha_iv2(base + cl) == pt[46:78]:
            hits.append(('no-variant', ak))
        for extra, name in ((dev16(dn), 'dev16-zero'), (b'\x00' * 16, 'dev16-null'),
                            (b'\x0f' * 16, 'dev16-0f'), (dev16(dn) + b'\x0f' * 14, 'dev+0e')):
            if sha_iv2(base + b'\x02' + extra + cl) == pt[46:78]:
                hits.append((name, ak))
    return params, hits


if __name__ == '__main__':
    for p, i in ((sys.argv[1], int(sys.argv[2])),):
        params, hits = sweep(p, i)
        print('%s #%d params=%d -> %s'
              % (os.path.basename(p)[:26], i, len(params), hits or 'no structural hit'))
