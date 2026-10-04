# gold_pack.py — decisive pack-law test on gold6 (today's install).
# d10 = values-concat in true SDK order (map_order sequence), H = arg3,
# #0 = core0 (today's real 144-B record), #2/#8/#9/#5/#1/#3 = template,
# sec = recovered from the blob's own Random3 header.
import json, struct, sys, time
HERE = r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev'
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header

g = json.load(open(r'C:/Users/Apps/Downloads/com.penti.app/adj9/device/gold6.json'))
maps, ns, outs = g['sign_input'], g['nsign_in'], g['nsign']
D = json.load(open(HERE + '/fin_descs.json'))
by = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex'])) for d in D['descs']}
core = json.load(open(r'C:/Users/Apps/Downloads/com.penti.app/adj9/device/core0_samples.json'))
core0 = bytes.fromhex([c for c in core if c.get('tag') == 'vm' and 'hex' in c][0]['hex'])
print('core0 #0 =', len(core0), 'bytes (=36dw:', len(core0) == 144, ')', flush=True)

def getv(entry, pref):
    for it in entry:
        if it.startswith(pref):
            return it.split('=', 1)[1]
    return None

def vals_in_order(map_order):
    out = []
    for ent in map_order.split('\x02'):
        if ent:
            k, _, v = ent.partition('\x01')
            out.append(v)
    return ''.join(out)

def find_sec(mo, hdr):
    # header law: sec = created_at second + 1 (S1 proof); try +-1 around it
    import re
    from datetime import datetime, timezone, timedelta
    m = re.search(r'created_at=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)Z([+-]\d{4})', mo)
    if not m:
        return None
    dt = datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc)
    off = m.group(2)
    omin = int(off[1:3]) * 60 + int(off[3:5])
    dt -= timedelta(minutes=omin if off[0] == '+' else -omin)
    base = int(dt.timestamp())
    for d in (1, 0, 2, -1):
        try:
            if make_header(base + d) == hdr:
                return base + d
        except Exception:
            continue
    return None

ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
win = 0
for i in range(min(len(maps), len(ns), len(outs))):
    mo = getv(maps[i], 'map_order=')
    H = getv(ns[i], 'arg3_hex=')
    blob_hex = getv(outs[i], 'hex=')
    kind = getv(maps[i], 'map_toString=')
    if not (mo and H and blob_hex):
        print(i, 'missing pieces', flush=True); continue
    expect = bytes.fromhex(blob_hex)
    sec = find_sec(mo, expect[:16])
    if sec is None:
        print(i, 'NO SEC for header', expect[:8].hex(), flush=True); continue
    t10 = vals_in_order(mo).encode()
    if len(t10) % 4:
        t10 += b'\x00' * (4 - len(t10) % 4)
    by[10] = (len(t10) // 4, t10)
    by[4] = (8, bytes.fromhex(H))
    by[0] = (len(core0) // 4, core0)
    by[7] = (1, struct.pack('>I', len(t10)))
    t0 = time.time()
    ex = FinEx(sec, [(by[k][0], 0, by[k][1]) for k in ORDER])
    st = ex.run(max_steps=40_000_000)
    sinks = {}
    for (sn, n, v) in ex.emit_trace:
        sinks.setdefault(sn, {})[n] = v
    got = b''.join(struct.pack('>I', sinks.get(0x5500000000, {}).get(n, 0)) for n in range(48))
    diff = [n for n in range(48) if got[4*n:4*n+4] != expect[4*n:4*n+4]]
    ok = not diff
    win += ok
    print('case %d sec=%d len10=%d hdr=%s -> %s (%d diffs) %s'
          % (i, sec, len(t10), got[:16] == expect[:16],
             'BYTE-EXACT' if ok else 'DIFF', len(diff),
             diff[:10] if diff else ''), flush=True)
    print('   map tail:', mo[-160:].replace('\x01', '=').replace('\x02', ' | '), flush=True)
print('PACK LAW:', 'PROVEN %d/%d' % (win, len(maps)) if win else 'NOT PROVEN', flush=True)