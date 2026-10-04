import base64, struct, sys
sys.path.insert(0, '.')
import mint_pipeline as M
import F as Fmod
import whiten_decoder as WD
gen = base64.b64decode(open('transport_blob.txt').read().strip())
rec = WD.decode_blob(gen)
print('type', type(rec), 'len', len(rec))
if isinstance(rec, dict):
    for k, v in rec.items():
        print('  %-14s %s' % (k, (v.hex() if isinstance(v, (bytes, bytearray)) else str(v)[:60])))
else:
    print(repr(rec)[:300])
