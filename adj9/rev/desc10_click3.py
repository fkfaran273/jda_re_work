# desc10_click3.py - (a) dump the 3 'wh' events in whcap_hits7.json (might carry the
# click signing's map), (b) exact-length re-extract of both desc10 runs, (c) DP
# segmentation of the click run into known (key,value) tokens.
import json, struct

DEV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\device'
REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
d = json.load(open(DEV + r'\whcap_hits7.json', encoding='utf-8'))
wh = [e for e in d if e.get('tag') == 'wh']
print('=== %d wh events ===' % len(wh))
for i, e in enumerate(wh):
    print('--- wh[%d] keys=%s' % (i, list(e.keys())))
    for k, v in e.items():
        s = repr(v)
        print('    %-8s %s' % (k, s[:300]))

# exact extraction: from head dword, take bytes until NUL, no printable filtering
evs = [e for e in d if e.get('tag') == 'emit']
words = [int(e['val'], 16) for e in evs]

def extract(head, cap=200):
    out = bytearray()
    i = head
    while i < len(words) and len(out) < cap:
        out += struct.pack('>I', words[i])
        i += 1
    z = out.find(b'\x00')
    return bytes(out[:z]) if z >= 0 else bytes(out)

s = extract(55)
c = extract(22327)
print()
print('SESSION desc10 exact len = %d' % len(s))
print('CLICK   desc10 exact len = %d' % len(c))
D = json.load(open(REV + r'\fin_descs.json', encoding='utf-8'))
g10 = bytes.fromhex([x for x in D['descs'] if x['build_idx'] == 10][0]['data_hex'])
print('session == fin_descs desc10:', s == g10)
print('CLICK RAW (%d B):' % len(c)); print(c.decode('latin1'))

# ---- DP segmentation of the click run -------------------------------------
W = json.load(open(REV + r'\wh4_records.json', encoding='utf-8'))

def fields_of(si):
    out = []
    for part in si['order'].split('\x02'):
        if '\x01' in part:
            k, v = part.split('\x01', 1)
            out.append((k, v))
    return out

cand = {}          # value -> list of keys (dedup)
for si in W['sign_inputs']:
    for k, v in fields_of(si):
        if v:
            cand.setdefault(v, [])
            if k not in cand[v]:
                cand[v].append(k)
# add values observed in the click run but maybe not in maps
extra = {'utm_source=google-play&utm_medium=organic': ['referrer'],
         'google': ['referrer_api'], 'install_referrer': ['source'],
         'click': ['activity_kind'], 'session': ['activity_kind']}
for v, ks in extra.items():
    cand.setdefault(v, [])
    for k in ks:
        if k not in cand[v]:
            cand[v].append(k)

vals = sorted(cand, key=len, reverse=True)     # longest-first greedy
pos, seg, bad = 0, [], []
while pos < len(c):
    hit = None
    for v in vals:
        if c.startswith(v.encode('latin1'), pos):
            hit = (cand[v][0], v); break
    if hit is None:
        bad.append(pos); break
    seg.append(hit); pos += len(hit[1])
print()
print('greedy tokens (%d), unmatched at %s:' % (len(seg), bad))
off = 0
for k, v in seg:
    print('  %4d %-26s %r' % (off, k, v))
    off += len(v)
print('covered %d/%d' % (off, len(c)))
