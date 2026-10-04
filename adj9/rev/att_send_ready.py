# att_send_ready.py - build a WIRE-READY /attribution blob with the correct
# 21-key claim set (slice 107) and verify the VM accepts it.
#
# Inputs: the genuine /attribution query from rev/fresh_genuine.json (22 params,
# real device) + the six constant law keys (adj_verification, adj_signing_id,
# activity_kind, client_sdk, headers_id, native_version).
# Output: rev/att_send_ready.json with the blob, the exact query, and the header line.
import json
import os
import re
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
from desc10_law import build_desc10, desc10_keys

GEN = json.load(open(os.path.join(HERE, 'fresh_genuine.json'), encoding='utf-8'))
q = {k: v[0] for k, v in urllib.parse.parse_qs(GEN['query'].split('?', 1)[1],
                                               keep_blank_values=True).items()}
val = dict(q)
val.update({
    'adj_verification': 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI',
    'adj_signing_id': '1500000',
    'activity_kind': 'attribution',
    'client_sdk': 'android5.7.0',
    'headers_id': '10',
    'native_version': '5.0.0',
})

keys = desc10_keys('attribution', val)
missing = [k for k in keys if k not in val or val[k] in (None, '')]
print('attribution law keys : %d' % len(keys))
print('keys missing from val: %s' % (missing or 'NONE'))
if missing:
    raise SystemExit('cannot build: missing %s' % missing)

# second: the genuine request's own header second (created_at is +0530)
import calendar
import datetime
ca = val['created_at']
m = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})Z\+(\d{2})(\d{2})', ca)
dt = datetime.datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S.%f')
off = int(m.group(2)) * 3600 + int(m.group(3)) * 60
second = calendar.timegm(dt.timetuple()) - off
print('created_at %s -> second %d' % (ca, second))

raw = build_desc10(val, 'attribution')
print('desc10 unpadded %d B -> padded %d B (%d dwords)'
      % (len(raw), (len(raw) + 3) // 4 * 4, (len(raw) + 3) // 4))
print()

t0 = time.time()
status, blob, desc, unpadded = F.make_signature_law(val, 'attribution', second=second)
print('=== VM result ===')
print('  status      : %s   (%.1fs)' % (status, time.time() - t0))
print('  #10 unpadded: %d B   #10 padded: %d B' % (unpadded, len(desc)))
print('  blob        : %d B' % len(blob))
print('  blob[:16]   : %s' % blob[:16].hex())
from header_gen import make_header
print('  header law  : %s' % ('OK' if blob[:16] == make_header(second) else 'BROKEN'))
print('  blob hex    : %s' % blob.hex())

hdr = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
       'headers_id="10",native_version="5.0.0",adj_verification="%s"'
       % (__import__('base64').b64encode(blob).decode(),
          val['adj_verification']))
out = {'kind': 'attribution', 'second': second, 'query': q, 'law_keys': keys,
       'desc10_unpadded': unpadded, 'blob_hex': blob.hex(), 'header': hdr,
       'status': status,
       'url': 'https://app.adjust.com/attribution?' + urllib.parse.urlencode(q)}
json.dump(out, open(os.path.join(HERE, 'att_send_ready.json'), 'w'), indent=1)
print()
print('saved att_send_ready.json  (url + header + blob ready to send)')
print('  url: %s' % out['url'][:160])