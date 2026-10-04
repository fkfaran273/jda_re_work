# sign_recheck.py  part 1: offline exec reproduction + comparison to golden body
import base64, json, os, struct, sys
from collections import defaultdict

HERE = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
sys.path.insert(0, HERE)
import fin_vm2 as F
from header_gen import make_header as MH
FIN = json.load(open(os.path.join(HERE, 'fin_descs.json'), encoding='utf-8'))
ORDER = FIN['va_order']
GOLD_BLOB = bytes.fromhex(FIN['target']['blob_hex'])
GOLD_SEC  = FIN['target']['second']
GOLD_BODY = GOLD_BLOB[16:]
GOLD_HDR  = GOLD_BLOB[:16]
print('golden body len', len(GOLD_BODY), '(192 - 16 = 176 B)  hdr=%s' % GOLD_HDR.hex())
print('golden second', GOLD_SEC, 'expected header', MH(GOLD_SEC).hex())

D = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex'])) for d in FIN['descs']}
for i,(lw,b) in D.items():
    assert len(b) == lw*4, 'desc %d len_dw mismatch: %d vs %d'%(i,lw,len(b))
