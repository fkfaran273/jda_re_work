import json, re, sys

sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
sys.path.insert(0, r'C:\Apps\Downloads\com.penti.app\adj7\cap')
from decrypt_rec import cbc_decrypt

D = json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json'))
e = next(x for x in D if str(x['sid']) == '45')
auth = None
for k, v in e['request_headers']:
    if k.lower() == 'authorization':
        auth = v
blob = bytes.fromhex(re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1))
rec = cbc_decrypt(blob[16:272], blob[:16])
print(repr(rec[:170]))
print('tail:', repr(rec[240:]))
