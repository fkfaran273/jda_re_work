"""_valdiff.py — our creditsea bodies vs the GENUINE creditsea map VALUES."""
import re, sys, importlib.util
CAP = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\creditsea\adj9_cap_fresh.log'
b = open(CAP, 'rb').read().decode('utf-8', 'replace')
gen = {}
for m in re.finditer(r'map_toString=\{', b):
    seg = b[m.end():m.end()+6000]
    end = seg.find('}')
    raw = seg[:end]
    k = re.search(r'activity_kind=([^,]*)', raw)
    k = k.group(1) if k else '?'
    d = dict(re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=([^,]*)', raw))
    if k in ('session', 'click') and k not in gen:
        gen[k] = d
print('genuine session keys=%d  click keys=%d' % (len(gen.get('session',{})), len(gen.get('click',{}))))
spec = importlib.util.spec_from_file_location('rcf', 'run_creditsea_fixed.py')
rcf = importlib.util.module_from_spec(spec)
try: spec.loader.exec_module(rcf)
except SystemExit: pass
g, params, cua, dua, stamp = rcf.load_device(rcf.DEVICE_JSON)
sess = dict(params)
for _k in ("session_length","subsession_count","time_spent"): sess.pop(_k, None)
sess.update({"session_count":"1"})
print()
print('=== SESSION value diff (genuine vs ours) ===')
for k in sorted(gen['session']):
    gv = gen['session'][k]; ov = str(sess.get(k, '<MISSING>'))
    if k in ('created_at','sent_at','installed_at','updated_at','gps_adid','android_uuid'):
        print('  %-26s genuine=%-30s ours=<identity/time>' % (k, gv[:30])); continue
    flag = '' if ov == gv else '   <== DIFFERS'
    print('  %-26s genuine=%-28s ours=%-28s%s' % (k, gv[:28], ov[:28], flag))
