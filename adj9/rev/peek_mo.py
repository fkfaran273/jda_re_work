# peek_mo.py - what's inside the mint artifacts (mo1/mo1b/mo2)?
import json
import os

T = os.environ.get('TEMP')
for n in ('mo1.json', 'mo1b.json', 'mo2.json'):
    p = os.path.join(T, n)
    if not os.path.exists(p):
        print('%s missing' % n)
        continue
    raw = open(p, 'rb').read()
    try:
        d = json.loads(raw.decode('utf-16'))
    except Exception:
        d = json.loads(raw.decode('utf-8', 'replace'))
    print('=== %s ===' % n)
    if isinstance(d, dict):
        for k, v in d.items():
            s = v if isinstance(v, (int, float, bool)) or v is None else str(v)
            print('   %-14s %s' % (k, str(s)[:120]))
    else:
        print('   list len %d' % len(d))
    print()