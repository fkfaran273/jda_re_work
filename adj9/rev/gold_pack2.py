# gold_pack2.py - wide-window sec recovery + pack law on gold6
import json, struct, sys, time, re
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
print('core0', len(core0), 'bytes', flush=True)
def getv(entry, pref):
    for it in entry:
        if it.startswith(pref): return it.split('=', 1)[1]
    return None
def vals_in_order(mo):
    out = []
    for ent in mo.split('\x02'):
        if ent:
            k, _, v = ent.partition('\x01'); out.append(v)
    return ''.join(out)
def find_sec(mo, hdr):
    m = re.search(r'created_at=(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})', mo)
    if not m: return None
    Y,Mo,Dd,H,Mi,S = map(int, m.groups())
    import calendar
    base = calendar.timegm((Y,Mo,Dd,H,Mi,S,0,0,0))
    m2 = re.search(r'created_at=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z([+-])(\d{2})(\d{2})', mo)
    if m2:
        off = int(m2.group(2))*3600 + int(m2.group(3))*60
        base -= off if m2.group(1)=='+' else -off
    for d in range(2, 400):
        try:
            if make_header(base + d) == hdr: return base + d
        except Exception: pass
    return None
ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
win = 0; done = 0
for i in range(min(len(maps), len(ns), len(outs))):
    mo = getv(maps[i], 'map_order='); H = getv(ns[i], 'arg3_hex=')
    blob = bytes.fromhex(getv(outs[i], 'hex='))
    if not (mo and H and blob): print(i, 'missing', flush=True); continue
    hdr = blob[:16]
    src = mo + '\x02' + (getv(maps[i], 'map_toString=') or '')
    sec = find_sec(src, hdr)
    if sec is None:
        print(i, 'NO SEC in +400s window for', hdr.hex(), flush=True); continue
    t10 = vals_in_order(mo).encode()
    if len(t10) % 4: t10 += b'\x00' * (4 - len(t10) % 4)
    by[10] = (len(t10)//4, t10); by[4] = (8, bytes.fromhex(H))
    by[0] = (len(core0)//4, core0); by[7] = (1, struct.pack('>I', len(t10)))
    t0 = time.time()
    ex = FinEx(sec, [(by[k][0], 0, by[k][1]) for k in ORDER])
    st = ex.run(max_steps=60_000_000)
    sinks = {}
    for (sn, n, v) in ex.emit_trace: sinks.setdefault(sn, {})[n] = v
    got = b''.join(struct.pack('>I', sinks.get(0x5500000000, {}).get(n, 0)) for n in range(48))
    diff = [n for n in range(48) if got[4*n:4*n+4] != blob[4*n:4*n+4]]
    done += 1; ok = not diff; win += ok
    print('case %d sec=%d (%.0fs) hdrmatch=%s -> %s diffs=%d %s' % (i, sec, time.time()-t0, got[:16]==hdr, 'BYTE-EXACT' if ok else 'DIFF', len(diff), diff[:12] if diff else ''), flush=True)
print('PACK LAW:', ('PROVEN %d/%d' % (win, done)) if done else 'NO SEC RECOVERED', flush=True)

