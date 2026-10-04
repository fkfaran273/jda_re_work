"""_lk3.py — the genuine non-organic click's referrer vs ours, side by side."""
import sys, urllib.parse
sys.path.insert(0, '.')
import nonorg_redrive as R
cp = R.load('2_c.txt')   # the ONLY genuine non-organic /sdk_click
print('=== GENUINE non-organic /sdk_click (tracker 24pxw9rl) ===')
for k in ('referrer','referrer_api','source','click_time','install_begin_time',
          'installed_at','google_play_instant','install_version'):
    print('  %-24s = %s' % (k, cp.get(k)))
print()
ours = 'adjust_reftag=cPZFNpbirim4H&utm_source=VKM+Digital+Yeni&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic'
print('=== OURS ===')
print('  referrer =', ours)
print()
import urllib.parse as up
gr = up.unquote(cp.get('referrer',''))
print('genuine referrer (unquoted):', gr)
print('ours                        :', ours)
print()
print('IDENTICAL:', gr == ours)
