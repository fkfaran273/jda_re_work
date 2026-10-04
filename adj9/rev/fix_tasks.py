# fix_tasks.py - mark the forge fold item as DONE in adj9/TASKS.md (both copies).
p = r'C:\Users\Apps\Downloads\com.penti.app\adj9\TASKS.md'
s = open(p, encoding='utf-8').read()
old = ('- [ ] Fold `build_desc10` into `adj9_forge.py` as '
       '`build_desc10(map, kind)`.\n')
new = ('- [x] Fold `build_desc10` into `adj9_forge.py` — DONE, verified BYTE-EXACT:\n'
       '      `build_desc10(val, kind)` + `make_signature_map(val, kind, second, …)`\n'
       '      (arbitrary-map blob built from the law). Proof: `rev/verify_map_blob2.py`\n'
       '      (device golden 192-B blob BYTE-EXACT) and `rev/verify_law_blob.py`\n'
       '      variant B (law-built #10/#7 → BYTE-EXACT); slice 98 §12.\n')
n = s.count(old)
assert n, 'item text not found'
s = s.replace(old, new)
open(p, 'w', encoding='utf-8').write(s)
print('patched %d occurrence(s)' % n)