# patch_gp2.py - add map_toString fallback into find_sec source text
import io
p = r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev/gold_pack2.py'
s = io.open(p, encoding='utf-8').read()
old = "    blob = bytes.fromhex(getv(outs[i], 'hex='))\n    if not (mo and H and blob): print(i, 'missing', flush=True); continue\n    hdr = blob[:16]; sec = find_sec(mo, hdr)"
new = ("    blob = bytes.fromhex(getv(outs[i], 'hex='))\n"
       "    if not (mo and H and blob): print(i, 'missing', flush=True); continue\n"
       "    hdr = blob[:16]\n"
       "    src = mo + '\\x02' + (getv(maps[i], 'map_toString=') or '')\n"
       "    sec = find_sec(src, hdr)")
if old not in s:
    print('PATTERN NOT FOUND'); raise SystemExit(1)
s = s.replace(old, new)
io.open(p, 'w', encoding='utf-8').write(s)
print('patched OK')
