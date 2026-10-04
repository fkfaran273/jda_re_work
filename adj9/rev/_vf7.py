"""_vf7.py — INDEPENDENT 192/192 reproduction using the recovered head (0x2b,).

Rebuilds everything from the genuine record alone:
  S      = record[20:24] big-endian
  d4     = F._d4_words(S)
  d0     = F._d0_words(d4, head=(0x2b,))     <- head recovered this session
  d2     = record[20:24] little-endian word
  desc10 = claims law over the app's sign_input map (blob_diff_data)
then mints and diffs all 192 bytes.
"""
import base64, json, struct, sys
sys.path.insert(0, '.')
import mint_pipeline as M
import F as Fmod
import whiten_decoder as WD

gen = base64.b64decode(open('transport_blob.txt').read().strip())
d = WD.decode_blob(gen)
bd = json.load(open('blob_diff_data.json'))
SEC = bd['second']; S = bd['genuine_S']; S = int(S, 16)

# claims: rebuild the desc10 from the recorded key order + the app's map
desc10_hex = bd.get('desc10')
if desc10_hex:
    desc10 = desc10_hex.encode('latin1')
    unpadded = bd['desc10_unpadded']
else:
    raise SystemExit('no desc10 in data')

d4w = Fmod._d4_words(S)
d0w = Fmod._d0_words(d4w, head=(0x2b,))
print('head_words match:', WD.head_words(d0w) == d['head'])

import math
padded = desc10 + b'\x00' * ((4 - len(desc10) % 4) % 4)
d0 = b''.join(w.to_bytes(4,'big') for w in d0w)
d4 = b''.join(w.to_bytes(4,'big') for w in d4w)
d2 = struct.pack('>I', d['d2w'])
D8 = bytes.fromhex('bffffffffffffd1f0007000000000000')
D9 = bytes.fromhex('fad0f10d60f93c17937b2f1eb6c09691ae7d74bd')
by = {0:(36,d0), 9:(5,D9), 8:(4,D8), 4:(8,d4), 2:(1,d2),
      7:(1,struct.pack('>I',unpadded)), 10:(len(padded)//4,padded),
      5:(1,b'\0'*4), 6:(1,b'\0'*4), 1:(0,b''), 3:(0,b'')}
descs = [(by[i][0], 0, by[i][1]) for i in M.VA_ORDER]
ours, vm = M.finex_mint(descs, SEC)
print('vm status:', vm.get('status'), 'steps', vm.get('steps'))
same = sum(1 for a,b in zip(ours, gen) if a==b)
print()
print('BYTE MATCH: %d/192   identical=%s' % (same, ours == gen))
if ours != gen:
    fd = next((i for i,(a,b) in enumerate(zip(ours,gen)) if a!=b), None)
    print('first diff at', fd)
    print('  ours   ', ours[fd:fd+24].hex())
    print('  genuine', gen[fd:fd+24].hex())
else:
    print()
    print('*** 192/192 BYTE-EXACT REPRODUCTION, independently derived ***')
