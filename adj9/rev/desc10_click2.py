# desc10_click2.py - resolve the CLICK desc10 order: dump si[1] click map, dump the
# wh4 click-burst fetch values, extend the trace click run tail, greedy-segment.
import json, re, struct

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
DEV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\device'
W = json.load(open(REV + r'\wh4_records.json', encoding='utf-8'))

def fields_of(si):
    out = []
    for part in si['order'].split('\x02'):
        if '\x01' in part:
            k, v = part.split('\x01', 1)
            out.append((k, v))
    return out

si1 = W['sign_inputs'][1]
f1 = fields_of(si1)
print('=== si[1] (click) map: %d fields ===' % len(f1))
for k, v in f1:
    print('  %-26s %r' % (k, v[:60]))
print('toString:', si1['toString'][:600])
print()

# wh4 click burst values (signing 1 = second nsign burst)
LOG = DEV + r'\adj9_wh4.log'
CLAIMS = set('''adj_verification android_uuid api_level app_token app_version created_at device_name
device_type environment gps_adid gps_adid_src hardware_name installed_at os_build os_name os_version
package_name adj_signing_id updated_at activity_kind client_sdk headers_id native_version
store_name_from_system initiating_package_name session_count tracking_enabled raw_referrer reftag
referrer utm_source utm_medium utm_campaign utm_content utm_term network install_referrer'''.split())
nsigns = []
gets = []
with open(LOG, encoding='utf-8', errors='replace') as f:
    cur = None
    for ln, line in enumerate(f, 1):
        m = re.match(r'###ADJ9_BEGIN type=(\w+)', line)
        if m:
            cur = m.group(1)
            continue
        if cur == 'mapget':
            m2 = re.match(r'text: th=\S+ this=\d+ key=(\S+) val=(.*)', line.rstrip('\r\n'))
            if m2 and m2.group(1) in CLAIMS:
                gets.append((ln, m2.group(1), m2.group(2)))
        elif cur == 'nsign':
            m2 = re.match(r'hex=([0-9a-f]+)', line)
            if m2:
                nsigns.append((ln, m2.group(1)))
# first click burst = nsign idx 1
b0 = nsigns[0][0]; b1 = nsigns[1][0]
burst1 = {}
seen = []
for ln, k, v in gets:
    if b0 < ln <= b1:
        if k not in burst1:
            burst1[k] = v
            seen.append((k, v))
print('=== click burst (signing 1) unique fetch values: %d ===' % len(seen))
for k, v in seen:
    print('  %-26s %r' % (k, v[:70]))
print()

# extend click run tail: raw dwords after the printable run
d = json.load(open(DEV + r'\whcap_hits7.json', encoding='utf-8'))
evs = [e for e in d if e.get('tag') == 'emit']
words = [int(e['val'], 16) for e in evs]
print('=== dwords at click run head 22327 (first 8): ===')
for i in range(22327, 22335):
    print('  %5d %08x %r' % (i, words[i], struct.pack('>I', words[i])))
print('=== dwords around 22327+96 (=run tail): ===')
for i in range(22327 + 92, 22327 + 106):
    print('  %5d %08x %r' % (i, words[i], struct.pack('>I', words[i])))
