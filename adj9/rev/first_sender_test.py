# first_sender_test.py - does the FIRST /session for a fresh (gps, auid)
# define the record, so later crafted polls with the SAME bytes verify?
# Flow: fresh GAID -> python click -> wipe -> 3s app run -> stop -> plant
# our auid into ActivityState -> PYTHON session+sdk_click FIRST ->
# relaunch (app adopts our auid) -> read device verdict + offline poll.
import sys, time, uuid, base64, re, json
sys.path.insert(0, r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev')
import farm_win as fw
import adj9_full_chain as fc
import click_bind_chain as cb

fc.USE_PROXY = True
STATE = '/data/data/com.penti.app/files/AdjustIoActivityState'
UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')

GPS = str(uuid.uuid4())
AUID = str(uuid.uuid4())
CREATIVE = 'cline_fs1'
print('gps =', GPS, flush=True)
print('auid(planted) =', AUID, flush=True)

out = {'gps': GPS, 'auid': AUID, 'creative': CREATIVE}

# 1. fresh identity
got = fw.set_gaid(GPS)
print('gaid set, readback:', got, 'ok:', got == GPS, flush=True)
out['gaid_readback'] = got

# 2. python click (engagement candidate)
t_click = int(time.time())
code, ref, hops, url = fw.fire_click(GPS, CREATIVE, None)
print('click:', code, (ref or '')[:60], 't_click:', t_click, flush=True)
out['t_click'] = t_click
out['click_http'] = code
out['referrer'] = ref

# 3. wipe + brief app run so ActivityState exists, then stop
fw.su('rm -f %s /data/data/com.penti.app/files/AdjustAttribution' % STATE)
fw.su('am force-stop %s' % fw.APP)
time.sleep(2)
fw.su('am start -n %s/.ui.main.MainActivity' % fw.APP)
time.sleep(4)
fw.su('am force-stop %s' % fw.APP)
time.sleep(2)

# 4. plant our auid (same-length byte patch, like the GAID patch)
raw = fw.su_file(STATE)
m = UUID_RE.search(raw.decode('latin1'))
if not m:
    print('FATAL: no uuid in state file', flush=True)
    sys.exit(1)
old_auid = m.group(0)
patched = raw.replace(old_auid.encode(), AUID.encode())
assert len(patched) == len(raw)
fw.su('echo %s | base64 -d > /data/local/tmp/st_planted' % base64.b64encode(patched).decode())
fw.su('cat /data/local/tmp/st_planted > %s' % STATE)
chk = fw.su_file(STATE).decode('latin1')
print('planted, auid now ours:', AUID in chk, '| old gone:', old_auid not in chk, flush=True)
out['planted'] = (AUID in chk)

# 5. PYTHON FIRST-SENDER: session + sdk_click before the app ever talks
sec0 = int(time.time())
ins = fc.fmt(t_click + 12, 774)  # AFTER the click (old bug: sec0-170 => install-before-click)
r1 = fc.api_session(GPS, AUID, ins=ins)
print('PY session:', str(r1[0]), (r1[1] or '')[:110], flush=True)
out['py_session'] = [str(r1[0]), (r1[1] or '')[:300]]
ref_q = (ref or '').split('?')[-1] if ref else 'adjust_reftag=none'
r2 = fc.api_sdk_click(GPS, AUID, ref_q, t_click + 15, ins=ins)
print('PY sdk_click:', str(r2[0]), (r2[1] or '')[:110], flush=True)
out['py_sdk_click'] = [str(r2[0]), (r2[1] or '')[:300]]

# 6. relaunch: app adopts planted auid, talks to the SAME record
fw.su('am start -n %s/.ui.main.MainActivity' % fw.APP)
time.sleep(20)
a, app_ref = fw.read_verdict()
print('DEVICE verdict: %s | installReferrer: %s' % (a, app_ref[:80]), flush=True)
out['device_verdict'] = a

# 7. OFFLINE crafted poll on the same (gps, auid) - the decisive read
r3 = fc.api_attribution(GPS, AUID, None)
print('PY attribution poll:', str(r3[0]), (r3[1] or '')[:200], flush=True)
out['py_poll'] = [str(r3[0]), (r3[1] or '')[:400]]

net = (a or {}).get('network')
out['device_non_organic'] = bool(a) and net not in (None, 'Organic')
body = out.get('py_poll', ['', ''])[1]
out['py_poll_non_organic'] = ('"Organic"' not in body) and ('tracker_token' in body)
json.dump(out, open(r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev/first_sender_result.json', 'w'), indent=1)
print('FIRST-SENDER DONE device_non_organic=%s py_poll_non_organic=%s' % (out['device_non_organic'], out['py_poll_non_organic']), flush=True)

