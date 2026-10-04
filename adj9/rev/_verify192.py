"""_verify192.py — independently reproduce the parallel session's 192/192 claim.

Their doc says: with the app's own claims, the app's own signing second, and
the region rebuilt from the app's own S and head=(0x2b,), mint_pipeline
reproduces the genuine blob exactly.  Verify it from scratch here.
"""
import base64, binascii, json, os, re, struct, sys
sys.path.insert(0, '.')
import mint_pipeline as M
import F as Fmod

# 1. the genuine blob + its signing second
blob_b64 = open('transport_blob.txt').read().strip()
gen = base64.b64decode(blob_b64)
print('genuine blob: %d B' % len(gen))

SEC = 1790517288
hdr_ok = gen[:16] == M.make_header(SEC)
print('header matches make_header(%d): %s' % (SEC, hdr_ok))

# 2. S from the decoded record: record[20:24) big-endian = f67d5e5e
S = 0xf67d5e5e
print('S = %08x' % S)

# 3. head phase (0x2b,) -- recovered by the parallel session
for nm, head in (('(0x2b,)', (0x2b,)), ('(0x2b,0x48)', (0x2b, 0x48)),
                 ('HEAD_FIRST', Fmod.HEAD_FIRST),
                 ('HEAD_RESIGN', Fmod.HEAD_RESIGN)):
    d0w, d2w, d4w = Fmod.region(S, M.DEFAULT_PID, 0, head=head)
    d0 = b''.join(w.to_bytes(4,'big') for w in d0w)
    print('  head %-12s d0[0:16]=%s' % (nm, d0[:16].hex()))
print('  genuine      d0[0:16]=%s' % gen[16:32].hex())
