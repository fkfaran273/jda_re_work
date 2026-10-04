import base64, struct, sys
sys.path.insert(0, '.')
import mint_pipeline as M
import F as Fmod
import whiten_decoder as WD

gen = base64.b64decode(open('transport_blob.txt').read().strip())
d = WD.decode_blob(gen)
S = d['F_seed']; target = d['head']
print('F_seed = 0x%08x' % S)
print('genuine head bytes = %s' % target.hex())
print('region_from_record -> %s  (None = neither shipped phase matches)'
      % (d['region'],))
print()
d4w = Fmod._d4_words(S)
print('d4 =', ' '.join('%08x' % w for w in d4w))
print()
# search all 1- and 2-selector heads
found = []
for a in range(0x20, 0x60):
    if WD.head_words(Fmod._d0_words(d4w, head=(a,))) == target:
        found.append((a,))
for a in range(0x20, 0x60):
    for b in range(0x20, 0x60):
        if WD.head_words(Fmod._d0_words(d4w, head=(a, b))) == target:
            found.append((a, b))
print('matching head phases found:', found)
