"""_clickval.py — genuine creditsea CLICK values, esp. the timing relations."""
import re
CAP = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\creditsea\adj9_cap_fresh.log'
b = open(CAP, 'rb').read().decode('utf-8', 'replace')
gen = {}
for m in re.finditer(r'map_toString=\{', b):
    seg = b[m.end():m.end()+6000]; end = seg.find('}'); raw = seg[:end]
    k = re.search(r'activity_kind=([^,]*)', raw); k = k.group(1) if k else '?'
    d = dict(re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=([^,]*)', raw))
    if k in ('session','click') and k not in gen: gen[k] = d
g = gen['click']
print('=== genuine creditsea CLICK: identity/timing fields ===')
for k in ('referrer','source','referrer_api','click_time','click_time_server',
          'install_begin_time','install_begin_time_server','installed_at',
          'updated_at','created_at','sent_at','install_version',
          'google_play_instant','country','client_sdk','session_count',
          'session_length','subsession_count','time_spent'):
    print('  %-26s = %s' % (k, g.get(k, '<absent>')))
print()
import urllib.parse
from datetime import datetime
def p(s):
    return datetime.strptime(urllib.parse.unquote(s), '%Y-%m-%dT%H:%M:%S.%fZ%z')
print('=== timing relations in the GENUINE creditsea click ===')
print('  click_time - click_time_server      = %+.0fs' % ((p(g['click_time'])-p(g['click_time_server'])).total_seconds()))
print('  install_begin - install_begin_server= %+.0fs' % ((p(g['install_begin_time'])-p(g['install_begin_time_server'])).total_seconds()))
print('  installed_at - install_begin_time   = %+.0fs' % ((p(g['installed_at'])-p(g['install_begin_time'])).total_seconds()))
print('  updated_at   - installed_at         = %+.0fs' % ((p(g['updated_at'])-p(g['installed_at'])).total_seconds()))
print('  created_at   - installed_at         = %+.0fs' % ((p(g['created_at'])-p(g['installed_at'])).total_seconds()))
print('  created_at   - click_time           = %+.0fs' % ((p(g['created_at'])-p(g['click_time'])).total_seconds()))
