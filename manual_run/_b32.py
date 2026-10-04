"""_b32.py — is record block32 a standard cipher over the known inputs?

We have, for one genuine declic signing:
  key2   = 32 bytes of keystore material
  record block32 = the 32 unknown bytes
  S, d0(head), desc10, D9, D8 = everything else in the record
Test: any AES mode / hash keyed with key2 over any simple input.
"""
import hashlib, hmac, itertools, re, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
sys.path.insert(0, '.')
import adj9_signature as SG

b = open('../adj9/rev/creditsea/adj9_cap_declic.log','rb').read().decode('utf-8','replace')
key2 = bytes.fromhex(re.findall(r'key2_hex=([0-9a-fA-F]+)', b)[0])
print('key2 (%d B): %s' % (len(key2), key2.hex()))

blob_hex = re.findall(r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]{384})", b)[0]
d = SG.decode_blob(bytes.fromhex(blob_hex))
rec = d['record']
block32 = rec[46:78]
print('block32      : %s' % block32.hex())
print()

# candidate inputs we can build
S_seed = d['F_seed']
d4 = SG._d4_words(S_seed)
d0 = SG._d0_words(d4, head=(43,))
cands = {
    'S_seed_be': S_seed.to_bytes(4,'big'),
    'd4': b''.join(w.to_bytes(4,'big') for w in d4),
    'd0': b''.join(w.to_bytes(4,'big') for w in d0),
    'desc10(capture)': re.search(r'map_toString=\{([^}]*)\}', b).group(1).encode(),
    'D9': bytes.fromhex('dd60fcbb9a438b4c8eb82d274aa8818595bc8445'),
    'D8': bytes.fromhex('bffffffffffffd1f0007000000000000'),
}
def try_all(label, data):
    hits = []
    for kname, key in (('key2', key2), ('key2[:16]', key2[:16])):
        for mode_name, mk in (
            ('ECB', lambda k: modes.ECB()),
            ('CBC-zeroiv', lambda k: modes.CBC(b'\0'*16)),
            ('CBC-S', lambda k: modes.CBC(S_seed.to_bytes(4,'big')*4)),
        ):
            try:
                c = Cipher(algorithms.AES(key), mk(key)).encryptor()
                out = c.update(data) + c.finalize()
            except Exception:
                continue
            if out[:32] == block32:
                hits.append('AES-%s-%s' % (mode_name, kname))
    for hname, hf in (('sha256', hashlib.sha256), ('md5', hashlib.md5)):
        if hf(data).digest()[:32] == block32: hits.append(hname)
    if hmac.new(key2, data, hashlib.sha256).digest() == block32: hits.append('hmac-sha256')
    if hmac.new(key2, data, hashlib.sha256).digest()[:16] == block32[:16]: hits.append('hmac-sha256(half)')
    return hits

allhits = []
for name, data in cands.items():
    h = try_all(name, data)
    if h:
        allhits.append((name, h)); print('*** HIT %s -> %s' % (name, h))
print()
print('combinations tested: %d inputs x (AES-ECB/CBC x 2 key lengths) + sha256/md5/hmac' % len(cands))
print('HITS:', allhits if allhits else 'none')
