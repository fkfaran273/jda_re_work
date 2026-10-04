# verify_genuine.py - INDEPENDENT offline replication of a GENUINE device-minted
# adj9 signature (rev/fresh_genuine.json: the /attribution query + the 192-B blob
# the device actually sent). This map is NOT the golden capture, so a byte-exact
# reproduction here proves the offline signer generalises to arbitrary maps.
#
# Steps:
#   1. decode the query into the claim dict;
#   2. recover the embedded `second` from the header law (blob[:16] == Random3(s));
#   3. rebuild the blob with adj9_forge.make_signature_map and diff it byte-wise.
import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
from header_gen import make_header, Random3

G = json.load(open(os.path.join(HERE, 'fresh_genuine.json'), encoding='utf-8'))
q = urllib.parse.parse_qs(G['query'].lstrip('?'), keep_blank_values=True)
val = {k: v[0] for k, v in q.items()}
blob = bytes.fromhex(G['blob_hex'])
print('genuine blob: %d bytes' % len(blob))
print('head16      :', blob[:16].hex())
print('claims (%d) : %s' % (len(val), sorted(val)[:12]))
print()

# ---- 1. recover `second` from the header law --------------------------------
ca = val.get('created_at', '')
print('created_at  :', ca)


def iso_to_epoch(s):
    """'2026-09-15T17:51:54.783Z+0530' -> epoch seconds (UTC)."""
    import datetime as dt
    core, _, off = s.partition('Z')
    tz = dt.timezone(dt.timedelta(hours=int(off[1:3]), minutes=int(off[3:5])
                                  * (1 if off[0] == '+' else -1))) if off else dt.timezone.utc
    if '+' in core or '-' in core[10:]:
        core = core.split('+')[0]
    return int(dt.datetime.strptime(core, '%Y-%m-%dT%H:%M:%S.%f')
               .replace(tzinfo=tz).timestamp())


try:
    base = iso_to_epoch(ca)
except Exception as e:
    print('  could not parse created_at (%s); using now' % e)
    base = int(time.time())

hdr = blob[:16]
found = []
for s in range(base - 7200, base + 7200):
    try:
        if make_header(s) == hdr:
            found.append(s)
    except Exception:
        pass
print('seconds matching header law: %s' % found)
if not found:
    print('NO second matched the header law - cannot proceed')
    raise SystemExit(1)
second = found[0]
print('using second = %d (%s)' % (second, time.strftime('%Y-%m-%d %H:%M:%S UTC',
                                                        time.gmtime(second))))
print()

# ---- 2. rebuild and diff ----------------------------------------------------
for kind in ('session', 'attribution', 'click'):
    try:
        st, got, used = F.make_signature_map(val, kind=kind, second=second)
    except Exception as e:
        print('kind=%-11s -> raised %s: %s'
              % (kind, type(e).__name__, str(e)[:160]))
        continue
    same = got == blob
    diff = sum(1 for i in range(48)
               if got[i * 4:i * 4 + 4] != blob[i * 4:i * 4 + 4])
    print('kind=%-11s status=%-11s header_law=%-4s bytes_equal=%-5s '
          'differing_dwords=%d/48'
          % (kind, st, 'OK' if got[:16] == make_header(second) else 'BAD', same, diff))
    if same:
        print('\n*** BYTE-EXACT REPRODUCTION OF A GENUINE DEVICE SIGNATURE ***')
        print('    blob =', got.hex())
        break