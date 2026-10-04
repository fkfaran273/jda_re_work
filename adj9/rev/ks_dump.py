# ks_dump.py - inspect the keystore2 DB: schema + which keys the app owns
import os
import sqlite3

DB = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\ks.sqlite'
con = sqlite3.connect(DB)
cur = con.cursor()
print('=== tables ===')
for (name, sql) in cur.execute(
        "select name, sql from sqlite_master where type='table'"):
    print('  %s' % name)
    print('    %s' % (sql or '').replace('\n', ' ')[:300])
print()
for t in [r[0] for r in cur.execute(
        "select name from sqlite_master where type='table'")]:
    try:
        n = cur.execute('select count(*) from "%s"' % t).fetchone()[0]
    except Exception as e:
        n = 'err %s' % e
    print('  %-24s rows=%s' % (t, n))
print()
print('=== metadata ===')
try:
    for k, v in cur.execute('select * from metadata'):
        vs = v.hex() if isinstance(v, (bytes, bytearray)) else v
        print('  %-30s %s' % (k, str(vs)[:120]))
except Exception as e:
    print('  err', e)
print()
print('=== keyentry (non-blob columns) ===')
try:
    cur.execute('select * from keyentry')
    cols = [d[0] for d in cur.description]
    print('  cols:', cols)
    for row in cur.fetchall():
        d = dict(zip(cols, row))
        line = []
        for k, v in d.items():
            if isinstance(v, (bytes, bytearray)):
                line.append('%s=<%dB %s>' % (k, len(v), v[:12].hex()))
            else:
                line.append('%s=%s' % (k, v))
        print('  ', ' '.join(line))
except Exception as e:
    print('  err', e)