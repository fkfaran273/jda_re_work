"""_selfclick.py — click the tracker link ourselves, take the reftag it hands
back, then drive the install.  Removes the last manual step.

Uses the moto g64 5G profile that just produced VKM Digital Yeni, with a FRESH
uuid4 GAID (never a device GAID, never a previously-installed one).
"""
import sys, time, uuid
sys.path.insert(0, '.')
import click_bind_chain as CBC
import offline_funnel_freshregion as FFN

gps = str(uuid.uuid4())
print('fresh GAID:', gps)
link = CBC.expand(FFN.LINK, gps)
code, ref, hops = CBC.tracker_click(link, gps)
print('click HTTP:', code)
for h in hops:
    print('  hop %s -> %s' % (h['http'], h['location'][:160]))
print('referrer  :', ref)
if not ref or 'adjust_reftag=' not in (ref or ''):
    print('NO REFTAG — abort'); sys.exit(1)
print()
print('ADJ_GAID=%s' % gps)
print('ADJ_REFTAG=%s' % ref)
