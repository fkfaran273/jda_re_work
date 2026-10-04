# pull_ks_db.py - byte-safe pull of the live keystore2 DB as root.
# adb shell mangles binary via CRLF translation, so use adb exec-out; and the
# su invocation needs its inner quotes preserved, hence the single string arg.
import os
import subprocess

SRC = '/data/misc/keystore/persistent.sqlite'
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'ks_after.sqlite')

cmd = '/debug_ramdisk/su -c "cat %s"' % SRC
r = subprocess.run(['adb', 'exec-out', cmd], capture_output=True)
d = r.stdout
print('pulled %d bytes (stderr: %s)' % (len(d), r.stderr.decode('utf-8', 'replace').strip()[:200]))
if d[:16] != b'SQLite format 3\x00':
    print('WARNING: header is not SQLite:', d[:16])
open(OUT, 'wb').write(d)
print('written', OUT)