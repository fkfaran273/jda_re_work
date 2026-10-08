import run_hunch as R, urllib.parse, os
CLICK = 1791445515
SEC = CLICK + 204
g, u = '2cff6766-14e2-439f-b229-4894ea53b87c', '6dbf173d-79e4-4fa2-a9c7-62d98f68571c'
S = R.build_session(g, u, SEC, CLICK)
C = R.build_click(g, u, SEC, 'adjust_reftag=ceA6HVPrx5HFW&utm_source=Spyke+Media&utm_campaign=SOHYPE_ADH&utm_content=%7Baffiliate_id%7D', CLICK)
A_ = R.build_attr(g, u, SEC)
os.environ['FUNNEL_MIXPANEL'] = 'f5270b2d-7fae-463d-9735-92e8600ca913'
import importlib
def truth(n):
    t = open('saz_hunch_new/raw/%02d_c.txt' % n, encoding='utf-8', errors='replace', newline='').read()
    line0 = t.split('\r\n', 1)[0]
    if line0.startswith('GET') and '?' in line0:
        return line0.split(' ', 2)[1].split('?', 1)[1].rsplit(' ', 1)[0], True
    return t.split('\r\n\r\n', 1)[1].strip(), False
for name, built, row in (('session', S, 29), ('click', C, 30), ('attr', A_, 32)):
    raw, is_q = truth(row)
    tk = [k for k, _ in urllib.parse.parse_qsl(raw, keep_blank_values=True)]
    bk = list(built.keys())
    print(name, 'built', len(bk), 'truth', len(tk), 'order_same=', bk == tk, 'set_same=', set(bk) == set(tk))
    if bk != tk:
        print('  built :', bk)
        print('  truth :', tk)
    tv = dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))
    dyn = {'gps_adid','android_uuid','referrer','created_at','sent_at','installed_at','updated_at','click_time','click_time_server','install_begin_time','install_begin_time_server','partner_params'}
    for k in bk:
        if k in dyn or k not in tv: continue
        if str(built[k]) != tv[k]:
            print('  VALDIFF', k, repr(built[k]), '!=', repr(tv[k]))
