# inspect gold6.json (category -> list of 6) : find which signing = golden desc10
import json, re
G = json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\device\gold6.json', encoding='utf-8'))
cats = list(G.keys())
print('categories:', cats)
n = len(G.get('nsign_in', []))
print('n signings:', n)
print('=== per-signing created_at / android_uuid ===')
for i in range(n):
    blob = json.dumps(G['nsign_in'][i])
    ca = re.search(r'2026-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z[+\-]\d{4}', blob)
    au = re.findall(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', blob)
    print(i, ca.group(0) if ca else None, au[0] if au else None)
print('=== nsign_in[0] structure ===')
v0 = G['nsign_in'][0]
print(type(v0).__name__, 'len=', len(v0))
if isinstance(v0, str):
    print(repr(v0[:600]))
elif isinstance(v0, dict):
    for k, vv in v0.items():
        print(' ', k, '->', repr(vv)[:200])
elif isinstance(v0, list):
    for j, item in enumerate(v0[:8]):
        print(' [%d]' % j, repr(item)[:200])
# golden desc10 identity: created_at 2026-09-12T21:15:11.678Z, uuid d773f47f-...
print('=== which gold6 entries mention 21:15:11 or d773f47f? ===')
for c in cats:
    v = G[c]
    if not isinstance(v, list): continue
    for i, item in enumerate(v):
        b = item if isinstance(item, str) else json.dumps(item)
        if '21:15:11' in b or 'd773f47f' in b:
            print('HIT %s[%d]' % (c, i))

