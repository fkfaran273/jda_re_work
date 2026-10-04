"""_lk1.py — the genuine non-organic click's link/reftag vs ours."""
import urllib.parse, sys
sys.path.insert(0, '.')
import click_bind_chain as CBC
import offline_funnel_freshregion as F
print('=== our tracker LINK ===')
print(F.LINK)
print()
print('=== macros present ===')
for m in ('{click_id}', '{idfa}', '{gps_adid}'):
    print('  %-12s %s' % (m, m in F.LINK))
