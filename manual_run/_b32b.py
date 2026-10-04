"""_b32b.py — is record block32 derivable without the VM?

The keystore key is HmacSHA256 inside AndroidKeyStore, so it is NOT readable.
That kills "AES keyed by key2" unless the key is derived from public inputs.
So test the unkeyed / publicly-derived space properly:
  - hashes over every ordered pair and triple of the known record fields
  - AES-ECB/CBC over the same, with the key being each single field
"""
import hashlib, hmac, itertools, re, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
sys.path.insert(0, '.')
import adj9_signature as SG

b = open('../adj9/rev/creditsea/adj9_cap_declic.log','rb').read().decode('utf-8','replace')
blob_hex = re.findall(r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]{384})", b)[0]
d = SG.decode_blob(bytes.fromhex(blob_hex))
rec = d['record']
block32 = rec[46:78]
S_seed = d['F_seed']
d4 = SG._d4_words(S_seed)
d0w = SG._d0_words(d4, head=(43,))
claims = re.search(r'map_toString=\{([^}]*)\}', b).group(1).encode()

F = {
 'magic': rec[0:3], 'head': rec[3:19], 'S': rec[20:24], 'cert': rec[25:45],
 'S4': S_seed.to_bytes(4,'big'), 'd0': b''.join(w.to_bytes(4,'big') for w in d0w),
 'd4': b''.join(w.to_bytes(4,'big') for w in d4),
 'claims': claims, 'sha0': rec[79:111], 'D8': bytes.fromhex('bffffffffffffd1f0007000000000000'),
 'zeros14': rec[114:128], 'ones14': rec[130:144],
}
names = list(F)
print('block32 = %s' % block32.hex())
print('testing %d fields, all ordered pairs (%d) and triples (%d)'
      % (len(names), len(names)**2, len(names)**3))
print()
hits = []
for n in names:
    if hashlib.sha256(F[n]).digest() == block32: hits.append('sha256(%s)'%n)
    if hashlib.md5(F[n]).digest()[:16] == block32[:16]: hits.append('md5(%s)'%n)
for a, c in itertools.permutations(names, 2):
    m = F[a]+F[c]
    if hashlib.sha256(m).digest() == block32: hits.append('sha256(%s+%s)'%(a,c))
    for mode_name, mk in (('ECB', lambda k: modes.ECB()),
                          ('CBC0', lambda k: modes.CBC(b'\0'*16))):
        try:
            e = Cipher(algorithms.AES(F[a].ljust(32,b'\0')[:32]), mk(None)).encryptor()
            if (e.update(m)+e.finalize())[:32] == block32:
                hits.append('AES-%s key=%s data=%s+%s'%(mode_name,a,a,c))
        except Exception: pass
for a, c, e_ in itertools.permutations(names, 3):
    if hashlib.sha256(F[a]+F[c]+F[e_]).digest() == block32:
        hits.append('sha256(%s+%s+%s)'%(a,c,e_))
print('HITS:', hits if hits else 'none')
