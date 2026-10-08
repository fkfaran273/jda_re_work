import urllib.parse, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_hunch as R

g = '2cff6766-14e2-439f-b229-4894ea53b87c'
u = '6dbf173d-79e4-4fa2-a9c7-62d98f68571c'
CLICK = 1791442515
S = R.build_session(g, u, CLICK + 203, CLICK)
C = R.build_click(g, u, CLICK + 203, 'X', CLICK)
A_ = R.build_attr(g, u, CLICK + 206)

def truth(n):
    t = open(os.path.join(HERE, 'saz_hunch_new/raw/%02d_c.txt' % n), encoding='utf-8', errors='replace', newline='').read()
    l0 = t.split('\r\n', 1)[0]
    if l0.startswith('GET'):
        q = l0.split(' ', 2)[1].split('?', 1)[1].rsplit(' ', 1)[0]
        return dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
    b = t.split('\r\n\r\n', 1)[1].strip()
    return dict(urllib.parse.parse_qsl(b, keep_blank_values=True))

for name, b, row in [('session', S, 29), ('click', C, 30), ('attr', A_, 32)]:
    tv = truth(row)
    diffs = []
    for k, v in b.items():
        if k in ('gps_adid','android_uuid','referrer','created_at','sent_at','installed_at','updated_at','click_time','click_time_server','install_begin_time','install_begin_time_server','partner_params'):
            continue
        if tv.get(k) != str(v):
            diffs.append((k, v, tv.get(k)))
    for k, v in tv.items():
        if k not in b and k not in ('gps_adid','android_uuid','referrer','created_at','sent_at','installed_at','updated_at','click_time','click_time_server','install_begin_time','install_begin_time_server','partner_params'):
            diffs.append(('MISSING', k, v))
    print(name, 'VALDIFFS:', diffs if diffs else 'none')
