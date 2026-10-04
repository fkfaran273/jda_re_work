"""_vf6.py — full 192/192 verification with the recovered head (0x2b,)."""
import base64, struct, sys
sys.path.insert(0, '.')
import mint_pipeline as M
import F as Fmod
import whiten_decoder as WD

gen = base64.b64decode(open('transport_blob.txt').read().strip())
d = WD.decode_blob(gen)
S = d['F_seed']; SEC = 1790517288
d4w = Fmod._d4_words(S)
d0w = Fmod._d0_words(d4w, head=(0x2b,))
d0 = b''.join(w.to_bytes(4,'big') for w in d0w)
d4 = b''.join(w.to_bytes(4,'big') for w in d4w)
d2 = d['d2w'].to_bytes(4,'big')
print('region rebuilt from S + head=(0x2b,)')
print('  head_words match:', WD.head_words(d0w) == d['head'])

# claims: need the app's sign_input map for THIS blob.
import json, re, os
# blob_diff_data.json should carry it
try:
    bd = json.load(open('blob_diff_data.json'))
    print('  blob_diff_data keys:', list(bd)[:8])
except Exception as e:
    print('  no blob_diff_data:', e)
