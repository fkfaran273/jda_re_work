"""_lk2.py — trace our tracker click's FULL redirect chain and check:
  1. Play Store (market://) not App Store (itms-apps://)
  2. the GAID the click is bound to is the SAME one we sign with
  3. the reftag format matches the genuine non-organic one
"""
import sys, uuid, urllib.parse
sys.path.insert(0, '.')
import click_bind_chain as CBC
import offline_funnel_freshregion as F

gps = str(uuid.uuid4())
print('fresh GAID for this test:', gps)
link = CBC.expand(F.LINK, gps)
print()
print('=== expanded link (query only) ===')
q = urllib.parse.parse_qsl(urllib.parse.urlsplit(link).query, keep_blank_values=True)
for k, v in q:
    print('  %-20s = %s' % (k, v[:90]))
print()
print('=== redirect chain ===')
code, ref, hops = CBC.tracker_click(link, gps)
for h in hops:
    print('  HTTP %s' % h['http'])
    loc = h['location']
    if loc:
        print('    -> %s' % loc[:220])
print()
print('final referrer:', ref)
print()
print('=== CHECKS ===')
last = hops[-1]['location'] if hops else ''
print('  Play Store scheme (market://) :', last.startswith('market://'))
print('  App Store scheme present      :', 'itms-apps' in str(last))
print('  GAID in click link            :', gps in link)
print('  gps_adid param bound          :', ('gps_adid', gps) in q or gps in urllib.parse.urlencode(q))
print('  idfa macro expanded to GAID   :', ('idfa', gps) in q)
