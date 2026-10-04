# ks_dump2.py - the app's key2 entry: blob, metadata, parameters (software KeyMint?)
import sqlite3

DB = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\ks.sqlite'
con = sqlite3.connect(DB)
cur = con.cursor()

print('=== keyentry aliases of interest ===')
rows = list(cur.execute('select id, key_type, domain, namespace, alias, state, '
                        'km_uuid from keyentry'))
TARGET = None
for (kid, kt, dom, ns, alias, st, km) in rows:
    a = alias.decode('latin1') if isinstance(alias, bytes) else alias
    if a in ('key2', 'seed', 'aes_key') or 'seed' in a.lower():
        print('  id=%-22s ns=%-6s dom=%s type=%s alias=%-14s km=%s'
              % (kid, ns, dom, kt, a, km.hex()))
        if a == 'key2' and ns == 10350:
            TARGET = kid
print()
print('TARGET (app key2, ns 10350) =', TARGET)
print('total keyentry rows:', len(rows))
print()
print('=== blobentry rows ===')
brows = list(cur.execute('select id, subcomponent_type, keyentryid, blob '
                         'from blobentry'))
print('  id            sub  keyentryid              len   head')
for (bid, sub, keid, blob) in brows:
    b = bytes(blob) if blob is not None else b''
    if TARGET is not None and keid == TARGET:
        print('  %-13s %-4s %-22s %-5d %s   <== TARGET' % (bid, sub, keid, len(b), b[:32].hex()))
    elif keid is None:
        print('  %-13s %-4s %-22s %-5d %s   (no keyentry -> KeyMint instance blob)'
              % (bid, sub, 'None', len(b), b[:32].hex()))
print()
print('=== target blob full-ish ===')
for (bid, sub, keid, blob) in brows:
    if keid == TARGET:
        b = bytes(blob)
        print('  blobentry %s sub=%s len=%d' % (bid, sub, len(b)))
        print('  hex:', b.hex())
        print()
print('=== blobmetadata for target ===')
ids = [bid for (bid, sub, keid, blob) in brows if keid == TARGET]
q = ','.join(str(i) for i in ids) or 'NULL'
for (bid, beid, tag, data) in cur.execute(
        'select id, blobentryid, tag, data from blobmetadata'):
    if beid in ids:
        d = bytes(data).hex() if isinstance(data, (bytes, bytearray)) else data
        print('  blobentryid=%-13s tag=%-4s data=%s' % (beid, tag, str(d)[:200]))
print()
print('=== keymetadata for target ===')
for (kid, tag, data) in cur.execute(
        'select keyentryid, tag, data from keymetadata'):
    if kid == TARGET:
        d = bytes(data).hex() if isinstance(data, (bytes, bytearray)) else data
        print('  tag=%-5s data=%s' % (tag, str(d)[:120]))
print()
print('=== keyparameter for target ===')
for (kid, tag, data, sec) in cur.execute(
        'select keyentryid, tag, data, security_level from keyparameter'):
    if kid == TARGET:
        d = bytes(data).hex() if isinstance(data, (bytes, bytearray)) else data
        print('  tag=%-5s sec=%-3s data=%s' % (tag, sec, str(d)[:120]))