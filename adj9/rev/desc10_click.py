# desc10_click.py - decode the 384B click desc10 runs and verify the law against
# the click signing's own map (wh4 sign_input with activity_kind=click).
import json, struct

DEV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\device'
REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
d = json.load(open(DEV + r'\whcap_hits7.json', encoding='utf-8'))
evs = [e for e in d if e.get('tag') == 'emit']
words = [int(e['val'], 16) for e in evs]

def run(i, maxlen=110):
    out = bytearray()
    while i < len(words) and len(out) < maxlen * 4:
        b = struct.pack('>I', words[i])
        if all(32 <= c < 127 for c in b):
            out += b; i += 1
        else:
            break
    return bytes(out)

c1 = run(22327)
c2 = run(22522)
print('click run lens:', len(c1), len(c2), '| identical:', c1 == c2)
D = json.load(open(REV + r'\fin_descs.json', encoding='utf-8'))
g10 = bytes.fromhex([x for x in D['descs'] if x['build_idx'] == 10][0]['data_hex']).decode('latin1')
print('click vs session golden: common prefix =', next(n for n in range(400) if c1[n:n + 1] != g10[n:n + 1]))
print()
print('FULL CLICK DESC10 (%d B):' % len(c1))
print(c1.decode('latin1'))
print()

# click signing's own map: pick the wh4 sign_input with activity_kind=click
W = json.load(open(REV + r'\wh4_records.json', encoding='utf-8'))
clicks = []
for i, s in enumerate(W['sign_inputs']):
    if 'activity_kind=click' in s['toString']:
        clicks.append(i)
print('click sign_inputs in wh4:', clicks)
# which one matches the run? use created_at (bytes 84..113 region contains created_at)
for ci in clicks:
    tostr = W['sign_inputs'][ci]['toString']
    import re
    ca = re.search(r'created_at=([^,]+)', tostr).group(1)
    inrun = ca.encode() in c1
    print('  si[%d] created_at=%s in run: %s' % (ci, ca, inrun))
    if inrun:
        fields = []
        for part in W['sign_inputs'][ci]['order'].split('\x02'):
            if '\x01' in part:
                k, v = part.split('\x01', 1)
                fields.append((k, v))
        val = dict(fields)
        # greedy segmentation of the run by map values
        seg = []
        pos = 0
        ok = True
        while pos < len(c1):
            hit = None
            for k, v in fields:
                if v and c1.startswith(v.encode(), pos):
                    # longest-match preference
                    if hit is None or len(v) > len(hit[1]):
                        hit = (k, v)
            if hit is None:
                print('    NO MATCH at pos %d: %r' % (pos, c1[pos:pos + 30]))
                ok = False
                break
            seg.append(hit)
            pos += len(hit[1])
        if ok:
            print('  greedy segmentation of run by map values (%d tokens):' % len(seg))
            print('  ', [k for k, _ in seg])
        # sorted-order check: group into sorted runs
        print()
