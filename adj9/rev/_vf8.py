"""_vf8.py — recover the head phase for all 6 blobs in the capture."""
import base64, glob, json, os, sys
sys.path.insert(0, '.')
import mint_pipeline as M
import F as Fmod
import whiten_decoder as WD

for p in sorted(glob.glob('../device/nblob_*.hex')):
    hx = open(p).read().strip()
    b = bytes.fromhex(hx)
    d = WD.decode_blob(b)
    S = d['F_seed']; target = d['head']
    d4w = Fmod._d4_words(S)
    hits = []
    for a in range(0x20, 0x60):
        if WD.head_words(Fmod._d0_words(d4w, head=(a,))) == target:
            hits.append((a,))
    for a in range(0x20, 0x60):
        for c in range(0x20, 0x60):
            if WD.head_words(Fmod._d0_words(d4w, head=(a, c))) == target:
                hits.append((a, c))
    names = {43: '0x2b', 65: '0x41', 72: '0x48'}
    print('%-28s S=%08x  head phases: %s'
          % (os.path.basename(p), S,
             [ '(' + ','.join(names.get(x, hex(x)) for x in h) + ')' for h in hits ]))
