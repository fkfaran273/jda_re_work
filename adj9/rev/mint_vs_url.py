# mint_vs_url.py - did the sends of the AMC minted blob carry a query that matches
# the SIGNED map? (payload-consistency hypothesis test, offline)
import json
import os
import urllib.parse

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
M = json.load(open(os.path.join(REV, 'minted4.json'), encoding='utf-8'))
print('minted4.json keys: %s' % list(M.keys()))
blob = M.get('blob_hex') or M.get('blobB64') or ''
if blob and not blob.startswith('20') and 'blobB64' in M:
    import base64
    blob_bytes = base64.b64decode(M['blobB64'])
else:
    blob_bytes = bytes.fromhex(blob) if blob else b''
pairs = M.get('mapPairs') or M.get('pairs') or []
print('blob %d B  pairs %d  stamp %s'
      % (len(blob_bytes), len(pairs), M.get('stamp')))
signed = {}
dups = {}
for k, v in pairs:
    if k in signed:
        dups.setdefault(k, [signed[k]]).append(v)
    signed[k] = v
print('duplicate keys in the signed map: %s' % (dups or 'none'))
print('signed gps_adid     = %s' % signed.get('gps_adid'))
print('signed android_uuid = %s' % signed.get('android_uuid'))
print('signed activity_kind= %s' % signed.get('activity_kind'))
print()

for name, path, key in (('AMC amc_final', 'amc_final_result.json', 'url'),
                        ('send_minted5', 'send_minted5_result.json', 'url'),
                        ('send_mint4', 'send_mint4_result.json', 'url')):
    p = os.path.join(REV, path)
    if not os.path.exists(p):
        continue
    d = json.load(open(p, encoding='utf-8'))
    url = d.get(key)
    q = {k: v[0] for k, v in urllib.parse.parse_qs(
        urllib.parse.urlsplit(url).query).items()}
    print('--- %s ---' % name)
    print('  url gps_adid=%s  url android_uuid=%s' % (q.get('gps_adid'),
                                                      q.get('android_uuid')))
    missing = [k for k in signed if k not in q]
    extra = [k for k in q if k not in signed]
    mism = [(k, signed[k], q[k]) for k in q if k in signed and signed[k] != q[k]]
    print('  keys in SIGNED map missing from url : %s' % missing)
    print('  keys in url missing from signed map : %s' % extra)
    print('  VALUE MISMATCHES (%d):' % len(mism))
    for k, a, b in mism:
        print('      %-28s signed=%r url=%r' % (k, a, b))
    print()
print('note: the signed map is the payload the keystore actually signed; if the')
print('server rebuilds the payload from the request, ANY mismatch breaks it.')