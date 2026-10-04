"""_diffkeys.py — runner's wire body vs the GENUINE creditsea key sets."""
import re, sys, os
b = open('adj9_cap_fresh.log', 'rb').read().decode('utf-8', 'replace')
INTERNAL = {'activity_kind','adj_signing_id','adj_verification','algorithm',
            'client_sdk','headers_id','native_version'}
gen = {}
for m in re.finditer(r'map_size=(\d+)\nmap_toString=\{', b):
    seg = b[m.end():m.end()+4000]; end = seg.find('}'); raw = seg[:end]
    k = re.search(r'activity_kind=([^,]*)', raw)
    k = k.group(1) if k else '?'
    keys = set(re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=', raw)) - INTERNAL
    if k in ('session','click') and k not in gen:
        gen[k] = keys
# also the genuine client_sdk VALUE
cs = re.findall(r'client_sdk=([^,&}]+)', b)
print('genuine session wire: %d keys' % len(gen['session']))
print('genuine click   wire: %d keys' % len(gen['click']))
print('genuine client_sdk values seen:', sorted(set(cs))[:5])
print()
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj9sign')
import importlib.util
spec = importlib.util.spec_from_file_location(
    'rcf', r'C:\Users\Apps\Downloads\com.penti.app\adj9sign\run_creditsea_fixed.py')
rcf = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(rcf)
except SystemExit:
    pass
except Exception as e:
    print('runner import note:', repr(e))
gaid, params, cua, dua, stamp = rcf.load_device(rcf.DEVICE_JSON)
session = dict(params)
session.update({"session_count":"1","session_length":"0","time_spent":"0",
                "subsession_count":"1"})
ours_s = set(session) - INTERNAL
cp = {k:v for k,v in session.items() if k not in ("first_error","last_error","retry_count")}
cp.update({"source":"install_referrer","referrer_api":"google",
           "referrer":"adjust_reftag=XX","google_play_instant":"0",
           "install_version":session["app_version"],"click_time":"T0",
           "click_time_server":"T0","install_begin_time":"T1",
           "install_begin_time_server":"T1"})
ours_c = set(cp) - INTERNAL
print('runner session wire: %d keys' % len(ours_s))
print('  MISSING vs genuine:', sorted(gen['session'] - ours_s))
print('  EXTRA   vs genuine:', sorted(ours_s - gen['session']))
print()
print('runner click   wire: %d keys' % len(ours_c))
print('  MISSING vs genuine:', sorted(gen['click'] - ours_c))
print('  EXTRA   vs genuine:', sorted(ours_c - gen['click']))
