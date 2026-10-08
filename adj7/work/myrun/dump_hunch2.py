import urllib.parse, os, re
HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, 'saz_hunch_new', 'raw')
def req(n):
    t = open(os.path.join(RAW, '%02d_c.txt' % n), encoding='utf-8', errors='replace', newline='').read()
    line0 = t.split('\r\n', 1)[0]
    head, _, body = t.partition('\r\n\r\n')
    return line0, head, body.strip()
for n in (29, 30, 32):
    line0, head, body = req(n)
    auth = [l for l in head.split('\r\n') if 'Authorization' in l][0]
    print('##### row', n)
    print(' AUTH:', auth[:80]); print('      ...', auth[-115:])
    m = re.search(r'signature="([0-9A-Fa-f]+)"', auth)
    print(' blob hex len:', len(m.group(1)))
    if n in (29, 30):
        f = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
        for k in ('gps_adid','android_uuid','partner_params','referrer','click_time','click_time_server','install_begin_time','install_begin_time_server','installed_at','updated_at','created_at','sent_at','ff_first_session_delay','app_version','package_name','store_name_from_system','initiating_package_name'):
            if k in f: print('  %-26s %s' % (k, f[k][:130]))
    else:
        qs = line0.split(' ', 2)[1].split('?', 1)[1].rsplit(' ', 1)[0]
        f = urllib.parse.parse_qsl(qs, keep_blank_values=True)
        print(' qparams:', len(f)); print(' qorder:', [k for k, _ in f])
        print(' full query:', qs)
