# gold_sec_scan.py - brute-force sec for each gold6 blob header, both ends
import json, sys, calendar, re
HERE = r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev'
sys.path.insert(0, HERE)
from header_gen import make_header
g = json.load(open(r'C:/Users/Apps/Downloads/com.penti.app/adj9/device/gold6.json'))
maps, outs = g['sign_input'], g['nsign']

def getv(entry, pref):
    for it in entry:
        if it.startswith(pref): return it.split('=', 1)[1]
    return None

for i, out in enumerate(outs):
    blob = bytes.fromhex(getv(out, 'hex='))
    mo = getv(maps[i], 'map_order=') or ''
    ts = getv(maps[i], 'map_toString=') or ''
    src = mo + '\x02' + ts
    m = re.search(r'created_at\x01(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})', src)
    m2 = re.search(r'created_at\x01\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z([+-])(\d{2})(\d{2})', src)
    if not (m and m2):
        print(i, 'created_at parse fail'); continue
    Y, Mo, Dd, H, Mi, S = map(int, m.groups())
    base = calendar.timegm((Y, Mo, Dd, H, Mi, S, 0, 0, 0))
    off = int(m2.group(2)) * 3600 + int(m2.group(3)) * 60
    base -= off if m2.group(1) == '+' else -off
    print(i, 'created_at_utc_sec =', base, 'blob[:8]', blob[:8].hex(), 'blob[-8:]', blob[-8:].hex())
    hit_head = hit_tail = None
    for d in range(-43200, 43201):
        sec = base + d
        try:
            h = make_header(sec)
        except Exception:
            continue
        if hit_head is None and h == blob[:16]: hit_head = sec
        if hit_tail is None and h == blob[-16:]: hit_tail = sec
        if hit_head and hit_tail: break
    print('   head-match sec:', hit_head, '(delta %d)' % (hit_head - base) if hit_head else '',
          '| tail-match sec:', hit_tail, '(delta %d)' % (hit_tail - base) if hit_tail else '')
