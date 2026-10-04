# ks_dump3.py - full structural dump: find the software KeyMint's protecting seed
import sqlite3

DB = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\ks.sqlite'
con = sqlite3.connect(DB)
cur = con.cursor()

print('=== ALL keyentry (88) ===')
print('  id                    type dom ns     alias')
for (kid, kt, dom, ns, alias, st, km) in cur.execute(
        'select id, key_type, domain, namespace, alias, state, km_uuid from keyentry'):
    a = alias.decode('latin1') if isinstance(alias, bytes) else str(alias)
    print('  %-21s %-4s %-3s %-6s %s' % (kid, kt, dom, ns, a[:60]))
print()
print('=== ALL blobentry (101) ===')
print('  id     sub  keyentryid               len   head32')
rows = list(cur.execute('select id, subcomponent_type, keyentryid, blob from blobentry'))
bykey = {}
for (bid, sub, keid, blob) in rows:
    b = bytes(blob) if blob is not None else b''
    bykey.setdefault(keid, []).append((bid, sub, b))
    print('  %-6s %-4s %-22s %-5d %s' % (bid, sub, keid, len(b), b[:32].hex()))
print()
print('=== blobentry with keyentryid NULL/unknown (KeyMint-instance blobs) ===')
for keid, items in bykey.items():
    if keid is None or not any(True for _ in cur.execute(
            'select 1 from keyentry where id=?', (keid,))):
        for bid, sub, b in items:
            print('  blobentry %s sub=%s keyentryid=%s len=%d'
                  % (bid, sub, keid, len(b)))
            print('    hex:', b.hex()[:400])
print()
print('=== distinct subcomponent_type values ===')
print('  ', sorted({r[1] for r in rows}))
print()
print('=== blobmetadata: all (127) ===')
for (bid, beid, tag, data) in cur.execute(
        'select id, blobentryid, tag, data from blobmetadata'):
    d = bytes(data) if isinstance(data, (bytes, bytearray)) else str(data)
    dh = d.hex() if isinstance(d, (bytes, bytearray)) else d
    print('  blobentryid=%-6s tag=%-4s len=%-4s %s'
          % (beid, tag, len(dh) // 2, dh[:80]))