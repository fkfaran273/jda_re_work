"""Screen iOS click-link shapes: which one makes Adjust register the click
(the 302 should echo click_id / carry a reftag-bearing referrer, per the
AGENTS.md law: a booking click echoes click_id + matched id in Location)."""
import os, sys, time, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
import run_install_ios as R
from curl_cffi import requests as cr

IDFA = R.new_idfa()
IP = "103.25.128.86"
BASE = "https://app.adjust.com/1xgvk2dz"
VARIANTS = {
 'full (runner LINK)': None,  # filled from runner LINK
 'no ip_address': "campaign=NIRIO_mobsuccess_iOS&adgroup=3710&os_name=ios&idfa=%s",
 'campaign only': "campaign=NIRIO_mobsuccess_iOS&idfa=%s",
 'idfa only': "idfa=%s",
 'idfa+gps_adid': "idfa=%s&gps_adid=%s",
 'bundle only': "bundle_id=com.fdjservices.nirio&idfa=%s",
}
rows = []
for name, tmpl in VARIANTS.items():
    if name == 'full (runner LINK)':
        url = R._subst(R.LINK, IDFA, IP)
    else:
        if '%s' in tmpl:
            url = BASE + '?' + (tmpl % ((IDFA,) * tmpl.count('%s')))
        else:
            url = BASE + '?' + tmpl
    try:
        r = cr.get(url, timeout=30, impersonate="safari17_0",
                   allow_redirects=False, verify=False)
        loc = r.headers.get("Location", "")
        ck = r.headers.get("Set-Cookie", "")
        rows.append((name, r.status_code, loc[:150], ck[:60]))
        print('%-20s %s loc=%s' % (name, r.status_code, loc[:130]), flush=True)
        print('%-20s cookie=%s' % ('', ck[:110]), flush=True)
    except Exception as e:
        print('%-20s ERR %r' % (name, e), flush=True)
open(os.path.join(HERE, 'ios_click_screen.json'), 'w').write(json.dumps(rows, indent=1))
print('IDFA used:', IDFA)
