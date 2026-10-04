# race_check.py - inspect the captured nsign blob in minted4.json: which map did
# the app sign? If activity_kind=attribution -> replay it verbatim (race branch).
import base64
import json

M = json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\minted4.json',
                   encoding='utf-8'))
n = M.get('nsign_b64')
print('nsign present:', n is not None)
if n:
    b = base64.b64decode(n)
    print('len:', len(b), 'hdr:', b[:16].hex())
    print('mint hdr:', bytes.fromhex(M['blob_hex'])[:16].hex())
    print('same blob as mint:', b.hex() == M['blob_hex'])
    print('sigmap activity keys:', list((M.get('sigmap') or {}).get('activity', {}).keys())[:50])
    act = (M.get('sigmap') or {}).get('activity', {})
    print('activity_kind in sigmap:', act.get('activity_kind'))
    print('created_at in sigmap:', act.get('created_at'))
