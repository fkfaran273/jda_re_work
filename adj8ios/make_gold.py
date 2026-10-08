"""Freeze every genuinely-verified adj8-iOS capture blob into gold_vectors.json.

For each capture (.saz via Fiddler, .chls via Charles) we carve the request
params, decrypt the blob, and keep the record only when the FULL 176-byte
signature is reproduced from (params, activity_kind, client_sdk, second, S)
alone -- i.e. the pure signer's byte-exact proof set.  The signing second comes
from inverting the MINSTD header around the request's own `sent_at`.

The captures are NOT kept in this folder (they are 40+ MB and already live in
C:\\Users\\Apps\\Downloads); point CAPTURES elsewhere if you move them:

    CAPTURES="C:/path/a.saz;C:/path/b.chls" python make_gold.py
"""
import re, sys, os, base64, json, struct, datetime, urllib.parse as up
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from carve import carve_saz, carve_chls, split_blob, block_ok, CLAIMS, sdk_of

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CAPTURES = [
    r"C:\Users\Apps\Downloads\neomindios_adjust.saz",
    r"C:\Users\Apps\Downloads\wave_19may_install_newapp_ios8.chls",
    r"C:\Users\Apps\Downloads\niceoneiosauto_6may_lvl2_ios11.chls",
]
CAPTURES = [p for p in os.environ.get("CAPTURES", "").split(";") if p] \
    or [p for p in DEFAULT_CAPTURES if os.path.exists(p)]
AKS = ('session', 'click', 'attribution', 'event', 'info')

P = 2147483647
def minstd_hdr(seed):
    x = int(seed) % P or 1
    d = []
    for _ in range(8):
        x = (16807 * x) % P
        d.append(x)
    return b"".join(struct.pack(">I", (d[2*i] ^ d[2*i+1]) & 0xFFFFFFFF) for i in range(4))

def second_for(hdr, around, span=900):
    for off in range(-span, span + 1):
        if minstd_hdr(around + off) == hdr:
            return around + off
    return None

def parse_ts(v):
    m = re.match(r'(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)\.\d+Z([+-])(\d\d):?(\d\d)?$', v or '')
    if not m:
        return None
    y, mo, dy, h, mi, s, sign, hh, mm = m.groups()
    base = datetime.datetime(int(y), int(mo), int(dy), int(h), int(mi), int(s),
                             tzinfo=datetime.timezone.utc)
    off = int(hh or 0) * 3600 + int(mm or 0) * 60
    return int(base.timestamp()) - (off if sign == '+' else -off)

def claims_of(params, ak, sdk):
    p = dict(params); p['activity_kind'] = ak; p['client_sdk'] = sdk
    return (''.join([str(p[k]) for k in CLAIMS['main'] if p.get(k) not in (None, '')]
                    + ['1400000']
                    + [str(p[k]) for k in CLAIMS['rest'] if p.get(k) not in (None, '')])
            + '9' + '3.67.0').encode('latin-1')

gold = []
def take(src, tag, kind_hint, blob, params, sdk):
    pt, tag_ok, head_ok = split_blob(blob)
    for ak in AKS:
        if block_ok(pt, params, ak, sdk):
            sec = second_for(blob[:16], parse_ts(params.get('sent_at')))
            if sec is None:
                return None
            rec = {"src": src, "n": tag, "kind": ak, "second": sec,
                   "nonce4": pt[20:24].hex(), "blob_hex": blob.hex(),
                   "client_sdk": sdk, "params": params}
            gold.append(rec)
            print("  %-38s #%-9s %-13s second=%d  claims=%dB"
                  % (src[:38], str(tag), ak, sec, len(claims_of(params, ak, sdk))))
            return rec
    return None

for path in CAPTURES:
    full = path
    if not os.path.exists(full):
        print("skip (missing): %s" % full)
        continue
    if path.endswith('.saz'):
        print(os.path.basename(path))
        for name, params, kind, blob, sdk in carve_saz(full):
            take(os.path.basename(path), name, kind, blob, params, sdk)
    elif path.endswith('.chls'):
        print(os.path.basename(path))
        for idx, bufs, kind, blob, sdk in carve_chls(full):
            for _st, q in bufs:
                params = dict(up.parse_qsl(q, keep_blank_values=True))
                if take(os.path.basename(path), idx, kind, blob, params, sdk):
                    break

with open(os.path.join(HERE, 'gold_vectors.json'), 'w') as fh:
    json.dump(gold, fh, indent=1)
print('froze %d vectors' % len(gold))
