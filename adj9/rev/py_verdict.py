# py_verdict.py - read the verdict for the CRAFTED (Python-signed) install identity
# with the only trustworthy oracle: the app's own AdjustAttribution file.
#
# This is the read slice 97 §13 flagged as never done - the crafted record existed
# but was only ever interrogated with crafted polls (which always answer the
# silent-Organic fallback and therefore cannot see the verdict).
#
# Usage: python py_verdict.py <gaid> <expected-marker>
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import farm_win as fw

gps = sys.argv[1]
marker = sys.argv[2] if len(sys.argv) > 2 else None
print('target GAID :', gps, flush=True)
print('marker      :', marker, flush=True)

pre, pre_ref = fw.read_verdict()
print('verdict BEFORE relaunch: %s' % json.dumps(pre), flush=True)

got = fw.set_gaid(gps)
print('GAID set -> readback %s' % got, flush=True)

fw.wipe_relaunch()
verdict, app_ref = {}, ''
for k in range(6):
    time.sleep(14 if k == 0 else 10)
    verdict, app_ref = fw.read_verdict()
    if verdict:
        break

print('app installReferrer: %s' % app_ref[:140], flush=True)
print('verdict AFTER       : %s' % json.dumps(verdict), flush=True)
if marker:
    ok = verdict.get('creative') == marker
    print('marker matches OUR crafted click: %s' % ok, flush=True)
    print('network: %s' % verdict.get('network'), flush=True)
    print('installed_at: %s' % verdict.get('installed_at'), flush=True)
    print('engagement_time: %s' % verdict.get('engagement_time'), flush=True)
json.dump({'gps': gps, 'verdict_before': pre, 'verdict_after': verdict,
           'app_install_referrer': app_ref},
          open(os.path.join(HERE, 'py_verdict_result.json'), 'w'), indent=1)
print('saved py_verdict_result.json', flush=True)