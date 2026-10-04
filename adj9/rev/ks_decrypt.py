# ks_decrypt.py - try to open the KeyMint AES-GCM envelope with candidate keys
import hashlib
import sqlite3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\ks.sqlite'
IV = bytes.fromhex('b5723ba163b49ca6ae07bc4f841ca8fa')
CT = bytes.fromhex('4f8c854670fd3d54b346cb9b4da4400952815f4869bd5fcbf1c49e5768344264')
TAG = bytes.fromhex('e43d722687b4a84f81145e8bd40cdfbb')
UID64 = bytes.fromhex('5f27857d9eec5f58')

con = sqlite3.connect(DB)
cur = con.cursor()
alias = {kid: (a.decode('latin1') if isinstance(a, bytes) else str(a))
         for (kid, a) in cur.execute('select id, alias from keyentry')}
rows = list(cur.execute('select id, subcomponent_type, keyentryid, blob from blobentry'))

cands = {}
for (bid, sub, keid, blob) in rows:
    b = bytes(blob)
    nm = alias.get(keid, 'none')
    for ln in (16, 24, 32, 48, 64):
        if len(b) == ln:
            cands['be%s(%s)raw' % (bid, nm[:22])] = b
        if len(b) >= ln:
            pass
# also: the tail 32/16 of every pKMblob (in case the key sits alongside)
for (bid, sub, keid, blob) in rows:
    b = bytes(blob)
    if len(b) > 60:
        cands['be%s.tail32' % bid] = b[-32:]
        cands['be%s.tail48' % bid] = b[-48:]
        cands['be%s.head32' % bid] = b[:32]

print('candidate keys: %d' % len(cands))
found = []
for name, k in cands.items():
    if len(k) not in (16, 32):
        continue
    for trial, key in ((name, k), (name + '+sha256', hashlib.sha256(k).digest())):
        try:
            pt = AESGCM(key).decrypt(IV, CT + TAG, None)
            found.append((trial, key.hex(), pt.hex()))
            print('  *** OPENED ***  %s  key=%s' % (trial, key.hex()))
            print('      plaintext(%d): %s' % (len(pt), pt.hex()))
        except Exception:
            pass
print()
if not found:
    print('no candidate opened the envelope')
    print('distinct blob lengths:', sorted({len(bytes(r[3])) for r in rows}))
    print()
    print('=== raw (non-pKMblob) blobs, by size ===')
    for (bid, sub, keid, blob) in rows:
        b = bytes(blob)
        if not b.startswith(b'pKMblob'):
            print('  be%-5s sub=%-2s %-40s len=%-5d %s'
                  % (bid, sub, alias.get(keid, 'none')[:40], len(b), b[:48].hex()))
    print()
    print('=== blobs whose keyentry has NO alias / domain!=0 ===')
    for (kid, kt, dom, ns, al) in cur.execute(
            'select id, key_type, domain, namespace, alias from keyentry'):
        if dom != 0:
            print('  kid=%-21s type=%s dom=%s ns=%s alias=%s'
                  % (kid, kt, dom, ns,
                     (al.decode('latin1') if isinstance(al, bytes) else al)))
    print()
    print('=== blobmetadata tags (all distinct) ===')
    print('  ', sorted({r[2] for r in cur.execute(
        'select id, blobentryid, tag, data from blobmetadata')}))