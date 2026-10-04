# desc10_click9.py - DEFINITIVE click-map recovery:
# (1) parse the full map toString at wh4 line ~286234 -> complete key->value set
# (2) extract the native's mapget fetch order for the click burst (this=244449033)
# (3) labeled DP over the FULL key set on the 387B click desc10.
import json, re

DEV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\device'
REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
LOG = DEV + r'\adj9_wh4.log'

# ---- (1) map toString at line 286234
with open(LOG, encoding='utf-8', errors='replace') as f:
    for ln, line in enumerate(f, 1):
        if ln == 286234:
            tostr_line = line.strip()
            break
m = re.search(r'\{(.*)\}', tostr_line)
pairs = re.findall(r'([A-Za-z0-9_]+)=([^,]*(?:\([^)]*\)[^,]*)*), ?', m.group(1) + ',')
cmap = {}
for k, v in pairs:
    cmap[k] = v
print('=== toString@286234 map: %d keys ===' % len(cmap))
for k in sorted(cmap):
    print('  %-26s %r' % (k, cmap[k]))

# ---- (2) fetch order for this=244449033
seq = []
with open(LOG, encoding='utf-8', errors='replace') as f:
    for ln, line in enumerate(f, 1):
        if ln < 286380 or ln > 286660:
            continue
        mm = re.match(r'text: th=\S+ this=244449033 key=(\S+) val=(.*)', line.rstrip('\r\n'))
        if mm:
            seq.append((ln, mm.group(1), mm.group(2)))
print()
print('=== click burst mapgets: %d events ===' % len(seq))
print('key order:', ' '.join(k for _, k, _ in seq))
