"""_sha_test.py — is the record a hash?  Test it directly.

Uses a genuine declic blob, so the inputs (S_seed, d4, d0 head, desc10) are
all real.  Then asks: does any simple SHA-256/SHA-1/MD5 of those inputs
reproduce the record's block32 field or the trailing 32-byte digest?
"""
import hashlib, re, struct, sys
sys.path.insert(0, '.')
import adj9_signature as S

b = open('../adj9/rev/creditsea/adj9_cap_declic.log','rb').read().decode('utf-8','replace')
blob_hex = re.findall(r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]{384})", b)[0]
blob = bytes.fromhex(blob_hex)
d = S.decode_blob(blob)
rec = d['record']
block32 = rec[46:78]
digest  = blob[160:192]

# the real inputs
S_seed = d['F_seed']
d4 = S._d4_words(S_seed)
d4b = b''.join(w.to_bytes(4,'big') for w in d4)
d0w = S._d0_words(d4, head=(43,))
d0b = b''.join(w.to_bytes(4,'big') for w in d0w)
# the claims that were signed
m = re.search(r'map_toString=\{([^}]*)\}', b)
claims = m.group(1).encode() if m else b''

print('target block32 :', block32.hex()[:40], '...')
print('target digest  :', digest.hex()[:40], '...')
print()
tokens = {
    'S_seed_be': struct.pack('>I', S_seed),
    'S_seed_le': struct.pack('<I', S_seed),
    'd4': d4b,
    'd0': d0b,
    'claims': claims,
    'd0+d4': d0b + d4b,
    'd4+claims': d4b + claims,
    'd0+S+d4+claims': d0b + struct.pack('>I', S_seed) + d4b + claims,
    'record_0_46': rec[0:46],
    'record_0_79': rec[0:79],
}
algs = {'sha256': hashlib.sha256, 'sha1': hashlib.sha1, 'md5': hashlib.md5}
hits = 0
for tname, tv in tokens.items():
    for aname, af in algs.items():
        h = af(tv).digest()
        for label, target in (('block32', block32), ('digest', digest)):
            if h[:32] == target:
                print('  *** HIT: %s(%s) -> %s' % (aname, tname, label)); hits += 1
print('direct hits:', hits)
if not hits:
    print('no simple hash of any single input (or pair) reproduces either field')
