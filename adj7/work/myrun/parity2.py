import urllib.parse, os, sys, re
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_hunch as R

# genuine hunch epochs (from the capture)
g = '2cff6766-14e2-439f-b229-4894ea53b87c'
u = '6dbf173d-79e4-4fa2-a9c7-62d98f68571c'
CLICK = 1791442515          # genuine click_time
INSTALLED = CLICK + 18.589  # +18.589
SESS = CLICK + 203.295      # genuine session created +203.295
u_click_ms = 0    # click_time ...000
SESS_SEC = int(SESS)  # 12:28:38
ATTR_SEC = SESS_SEC + 3

S = R.build_session(g, u, SESS_SEC, CLICK)
C = R.build_click(g, u, SESS_SEC, 'X', CLICK)
A_ = R.build_attr(g, u, ATTR_SEC)

def truth(n):
    t = open(os.path.join(HERE, 'saz_hunch_new/raw/%02d_c.txt' % n), encoding='utf-8', errors='replace', newline='').read()
    l0 = t.split('\r\n', 1)[0]
    if l0.startswith('GET'):
        q = l0.split(' ', 2)[1].split('?', 1)[1].rsplit(' ', 1)[0]
        return dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
    b = t.split('\r\n\r\n', 1)[1].strip()
    return dict(urllib.parse.parse_qsl(b, keep_blank_values=True))

DYN = {'gps_adid','android_uuid','referrer','created_at','sent_at','installed_at','updated_at','click_time','click_time_server','install_begin_time','install_begin_time_server','partner_params'}
ok = True
for name, built, row, when in (('session', S, 29, 'session'), ('click', C, 30, 'click'), ('attr', A_, 32, 'attr')):
    tv = truth(row)
    for k, v in built.items():
        if k in DYN: continue
        if k not in tv: print('EXTRA:', name, k); ok = False
        elif str(v) != tv[k]: print('VALDIFF', name, k, repr(v), '!=', repr(tv[k])); ok = False
    for k, v in tv.items():
        if k not in built: print('MISSING:', name, k, repr(v)); ok = False
print('static parity:', 'CLEAN' if ok else 'FAIL')
# now verify the TIMESTAMP SHAPE matches genuine to the millisecond fraction
print('our session created:', S['created_at'], '| genuine:', truth(29)['created_at'])
print('our installed:', S['installed_at'], '| genuine:', truth(29)['installed_at'])
print('our click created:', C['created_at'], '| genuine:', truth(30)['created_at'])
print('our click click_time:', C['click_time'], '| genuine:', truth(30)['click_time'])
print('our attr created:', A_['created_at'], '| genuine:', truth(32)['created_at'])
