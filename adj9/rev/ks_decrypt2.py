# ks_decrypt2.py - last DB-only attempts: IV reuse, AAD variants, HKDF/ECDH-ish
import hashlib
import sqlite3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DB = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\ks.sqlite'
IV = bytes.fromhex('b5723ba163b49ca6ae07bc4f841ca8fa')
CT = bytes.fromhex('4f8c854670fd3d54b346cb9b4da4400952815f4869bd5fcbf1c49e5768344264')
TAG = bytes.fromhex('e43d722687b4a84f81145e8bd40cdfbb')
UID64 = bytes.fromhex('5f27857d9eec5f58')
PARAMS = bytes.fromhex(
    'a201ac1a2000000181021a1000000218801a300000031901001a2000000581041a300000'
    '081901001a1000012d001a700001f7f51a100002be001a300002c11a0001d4c01a300002'
    'c21a000315dd1a300002ce1a01348a551a300002cf1a01348a5500a11a600002bd1b00000'
    '1a038c16ea0')

con = sqlite3.connect(DB)
cur = con.cursor()
rows = list(cur.execute('select id, subcomponent_type, keyentryid, blob from blobentry'))

# 1) IV reuse across all pKMblob envelopes (catastrophic-reuse check)
import re
IVS = {}
for (bid, sub, keid, blob) in rows:
    b = bytes(blob)
    if b.startswith(b'pKMblob'):
        for m in re.finditer(rb'[\x80-\xff\x00-\x1f]', b):
            pass
        # crude: look for our IV bytes anywhere
        if IV in b:
            IVS[bid] = 'our_iv_present'
print('blobs containing OUR IV:', IVS or 'none')

# 2) candidate keys: every raw 32/16-byte blob + sha256/hkdf variants
cands = {}
for (bid, sub, keid, blob) in rows:
    b = bytes(blob)
    if len(b) in (16, 32):
        cands['be%d_raw' % bid] = b
        cands['be%d_sha256' % bid] = hashlib.sha256(b).digest()
        cands['be%d_rawhalf' % bid] = b[:16]
        for info in (b'keystore2', b'AndroidKeyStore', b'key', b'seed', b'AES',
                     b'', b'keymint', b'storage'):
            try:
                k = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                         info=info).derive(b)
                cands['be%d_hkdf_%s' % (bid, info.decode() or 'none')] = k
            except Exception:
                pass

AADS = {'empty': None, 'params': PARAMS, 'uid': UID64,
        'params_uid': PARAMS + UID64, 'uid_params': UID64 + PARAMS,
        'params_enc': PARAMS}
hits = []
for name, key in cands.items():
    if len(key) not in (16, 24, 32):
        continue
    for an, aad in AADS.items():
        try:
            pt = AESGCM(key).decrypt(IV, CT + TAG, aad)
            hits.append((name, an, key.hex(), pt.hex()))
            print('*** OPENED *** %s aad=%s key=%s pt=%s'
                  % (name, an, key.hex(), pt.hex()))
        except Exception:
            pass
print('candidates tried: %d, AAD variants: %d' % (len(cands), len(AADS)))
print('hits:', len(hits))
print()
print('=== sanity: does OUR key2 blob appear verbatim in any other blob? ===')
print()
print('=== blobmetadata for a few blobs (tags 0,1,2,3,6) ===')
alias = {kid: (a.decode('latin1') if isinstance(a, bytes) else str(a))
         for (kid, a) in cur.execute('select id, alias from keyentry')}
for (bid, beid, tag, data) in cur.execute(
        'select id, blobentryid, tag, data from blobmetadata where tag != 4'):
    d = bytes(data) if isinstance(data, (bytes, bytearray)) else str(data)
    dh = d.hex() if isinstance(d, (bytes, bytearray)) else d
    print('  blobentryid=%-6s tag=%-3s %s' % (beid, tag, dh[:100]))