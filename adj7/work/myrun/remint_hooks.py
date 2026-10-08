import json, struct, sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7_pure as A
rows = json.load(open(os.path.join(HERE, '..', 'soverify_hook_parsed.json')))
print('rows:', len(rows))
for r in rows:
    claims = bytes.fromhex(r['claims_hex'])
    nonce12 = bytes.fromhex(r['nonce12'])
    cert40 = r['cert40'].encode()
    sec = r['sec_used']
    h = A.commitment_digest(claims, nonce12, cert40).hex().upper()
    # full blob
    blob = A.sign(sec, nonce12, claims, cert40)
    whole = blob.hex().upper() == r['blob_hex'].upper()
    print('n=%s kind=%-11s Hmatch=%s WHOLE=%s claims=%dB sec=%s' % (
        r['n'], r['kind'], h == r['device_H'].upper(), whole, len(claims), sec))
    if not whole:
        a, b = r['blob_hex'].upper(), blob.hex().upper()
        i = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), None)
        print('  first diff hex', i, 'rec', a[max(0, i-4):i+12], 'mint', b[max(0, i-4):i+12])
