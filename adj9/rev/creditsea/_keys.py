"""_keys.py — genuine CREDITSEA wire key sets vs what the runner sends."""
import re, sys
b = open('adj9_cap_fresh.log', 'rb').read().decode('utf-8', 'replace')
print('map_toString hits:', b.count('map_toString'))
found = {}
for m in re.finditer(r'map_size=(\d+)\nmap_toString=\{', b):
    seg = b[m.end():m.end() + 4000]; end = seg.find('}'); raw = seg[:end]
    kind = re.search(r'activity_kind=([^,]*)', raw)
    k = kind.group(1) if kind else '?'
    keys = re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=', raw)
    if k in ('session', 'click') and k not in found:
        found[k] = keys
        print('\n=== genuine %s: %d keys (map_size=%s) ===' % (k, len(keys), m.group(1)))
for k, v in found.items():
    print('%s: %s' % (k, sorted(v)))
