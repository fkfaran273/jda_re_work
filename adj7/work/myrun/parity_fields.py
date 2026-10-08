"""Full field-by-field diff: OUR last live hunch bodies vs genuine row 29/30/32.

We don't keep a saz for run_hunch, so re-mint the four builders with the
genuine's own ids/times and require static parity. Then separately print
our actual LAST LIVE bodies (reconstructed from last_run_hunch.json where
possible) — the timestamp prints come from the direct console output we
have, which were eyeballed. Goal: catch any field value-level mismatch
between genuine and our builder output."""
import urllib.parse, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_hunch as R

g, u = '2cff6766-14e2-439f-b229-4894ea53b87c', '6dbf173d-79e4-4fa2-a9c7-62d98f68571c'
CLICK_SEC = 1791445515  # 2026-10-08T12:25:15+0530
INSTALLED_SEC = CLICK_SEC + 18.589
BEGIN_SEC = CLICK_SEC + 6
BEGIN_S_SEC = CLICK_SEC + 5
SESS_SEC = 1791445718  # 2026-10-08T12:28:38.559+0530 (sent second)
ATTR_SEC = SESS_SEC + 3.275

S = R.build_session(g, u, SESS_SEC, CLICK_SEC)
C = R.build_click(g, u, SESS_SEC, 'adjust_reftag=ceA6HVPrx5HFW&utm_source=Spyke+Media&utm_campaign=SOHYPE_ADH&utm_content=%7Baffiliate_id%7D', CLICK_SEC)
A_ = R.build_attr(g, u, ATTR_SEC)

def truth(n):
    t = open(os.path.join(HERE, 'saz_hunch_new/raw/%02d_c.txt' % n), encoding='utf-8', errors='replace', newline='').read()
    line0 = t.split('\r\n', 1)[0]
    if line0.startswith('GET') and '?' in line0:
        q = line0.split(' ', 2)[1].split('?', 1)[1].rsplit(' ', 1)[0]
        return dict(urllib.parse.parse_qsl(q, keep_blank_values=True)), q
    b = t.split('\r\n\r\n', 1)[1].strip()
    return dict(urllib.parse.parse_qsl(b, keep_blank_values=True)), b

DYN = {'gps_adid','android_uuid','referrer','created_at','sent_at','installed_at','updated_at','click_time','click_time_server','install_begin_time','install_begin_time_server','partner_params'}
ok = True
for name, built, row in (('session', S, 29), ('click', C, 30), ('attr', A_, 32)):
    tv, _ = truth(row)
    for k in built:
        if k in DYN:
            continue
        if k not in tv:
            print('EXTRA ours:', name, k); ok = False
        elif str(built[k]) != tv[k]:
            print('VALDIFF', name, k, repr(built[k]), '!=', repr(tv[k])); ok = False
    for k in tv:
        if k not in built:
            print('MISSING ours:', name, k, repr(tv[k])); ok = False
print('static parity:', 'CLEAN' if ok else 'FAIL')
# encoding shape for one timestamp + partner
print('sample our installed:', S['installed_at'])
print('sample genuine installed:', truth(29)[0]['installed_at'])
