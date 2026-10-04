"""_vocab.py — the real Adjust vocabularies for these fields."""
import os, re
SD = re.compile(r'screen_density=([A-Za-z0-9_]+)')
HW = re.compile(r'hardware_name=([A-Za-z0-9_.\-]+)')
SS = re.compile(r'screen_size=([A-Za-z]+)')
SF = re.compile(r'screen_format=([A-Za-z]+)')
vals, hw, ss, sf = {}, {}, {}, {}
for root, d, fs in os.walk('../..'):
    if any(x in root for x in ('node_modules', '.git', '__pycache__')):
        continue
    for f in fs:
        p = os.path.join(root, f)
        try:
            if os.path.getsize(p) > 80_000_000: continue
            b = open(p, 'rb').read().decode('utf-8', 'replace')
        except Exception:
            continue
        for rx, acc in ((SD, vals), (HW, hw), (SS, ss), (SF, sf)):
            for m in rx.findall(b):
                acc[m] = acc.get(m, 0) + 1
for name, acc in (('screen_density', vals), ('screen_size', ss),
                  ('screen_format', sf), ('hardware_name', hw)):
    print('%s:' % name)
    for k, v in sorted(acc.items(), key=lambda x: -x[1])[:12]:
        print('   %-30s %d' % (k[:30], v))
    print()
