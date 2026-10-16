# -*- coding: utf-8 -*-
"""make_bubble_android.py -- derive run_bubble_android.py from the proven
adj7-Android runner (run_hunch.py), retargeted at BubbleBus / adshustle.

Why Android: the adshustle link template passes sub3={gaid} and the tracker
copies it straight into gps_adid= -- an Android device match.  Six iOS click
shapes all came back Organic while the berain control booked, so the
campaign may simply be Android-only.

Unknowns handled:
  cert_sha1 -> None (the documented 40-NUL no-cert path; the consent/app
               hosts do not gate the signature, which we proved on berain).
  SESSION_AT -> env-tunable (default 25 s CTIT; the hunch capture used 203).
"""
import io
import os

HERE = os.path.dirname(os.path.abspath(__file__))
src = io.open(os.path.join(HERE, "run_hunch.py"), encoding="utf-8").read()

DOC_OLD = src[src.index('"""'):src.index('"""', src.index('"""') + 3) + 3]
DOC_NEW = '''"""run_bubble_android.py -- the adj7-ANDROID fresh install funnel for
BubbleBus (com.bugbomb.dumptruckjam), behind the adshustle tracker click.

    tracker  1t8ghv6f  /  campaign AH (offer 22353289) or GWM (22352108)
    app_token l5njnrkv6ayo, sdk unity5.5.0@android5.5.0,
    adj_signing_id 1300000, headers_id 8, native_version 3.62.0

The adshustle tracker 302s an Adjust link that carries the device id in
gps_adid= (it copies sub3={gaid}), so the join is a GAID join -- Android.
The iOS shape (idfa= in the click) was tried six ways and stayed Organic
while the berain control booked from the same code, same IP, same minute.

Run:
    set FUNNEL_PROXY=
    set FUNNEL_REFTAG=utm_source=(not set)^&utm_medium=(not set)
    python run_bubble_android.py
"""'''

out = src.replace(DOC_OLD, DOC_NEW, 1)

# run_fiddler keeps its OWN module-level PROXY (default 127.0.0.1:8888) and
# _connect() reads that one -- so overriding ours is not enough.  Force it
# direct here rather than editing the original run_fiddler.py.
out = out.replace('from run_fiddler import _connect, BROWSER_HEADERS',
                  'from run_fiddler import _connect, BROWSER_HEADERS\n'
                  'import run_fiddler as _RF\n'
                  '_RF.PROXY = _px0 = os.environ.get("FUNNEL_PROXY", "")\n'
                  'if _px0.strip().lower() in ("", "off", "none", "0"):\n'
                  '    _RF.PROXY = ""          # Fiddler is not running: go direct',
                  1)

out = out.replace('''CAMPAIGN = {
    "package_name": "social.hunch.app",
    "app_version": "3.2.33",
    "app_token": "vf3lochhmgw0",
    "client_sdk": "flutter5.5.0@android5.5.0",
    "cert_sha1": "aa92a18790f85d4e9b5199c7792c55f2fb0f61e1",''',
                    '''CAMPAIGN = {
    "package_name": "com.bugbomb.dumptruckjam",
    "app_version": "3.4",
    "app_token": "l5njnrkv6ayo",
    "client_sdk": "unity5.5.0@android5.5.0",
    "cert_sha1": None,          # unknown cert -> 40-NUL no-cert path''', 1)

out = out.replace('''LINK = ("https://app.adjust.com/1yzhva5b?campaign=SOHYPE_ADH"
        "&adgroup={affiliate_id}")''',
                  '''LINK = ("https://app.adjust.com/1t8ghv6f?campaign=AH&adgroup=43407"
        "&cost_type=cpi&cost_amount=1&cost_currency=USD"
        "&gps_adid={gaid}")''', 1)

out = out.replace('INSTALL_AFTER = 18           # installed = click+18.589 s (ms .589)\nSESSION_AT = 203             # session created = click+203.295 s',
                  'INSTALL_AFTER = 18           # installed = click+18.589 s (ms .589)\n'
                  '# session timing: the hunch capture used click+203 s; a short CTIT\n'
                  '# attributes just as well and keeps a run under a minute.\n'
                  'SESSION_AT = int(os.environ.get("FUNNEL_SESSION_AT", "25"))')

out = out.replace('link_chain', 'link_chain')  # no-op guard
# Default to a DIRECT connection: Fiddler is not running, and PowerShell's
# `$env:X = ""` DELETES the variable, which silently restores the 8888 default
# and then refuses the connection.  FUNNEL_PROXY=off/none also means direct.
out = out.replace('PROXY = os.environ.get("FUNNEL_PROXY", "http://127.0.0.1:8888")',
                  '_px = os.environ.get("FUNNEL_PROXY", "")\n'
                  'PROXY = "" if _px.strip().lower() in ("", "off", "none", "0") else _px')
out = out.replace('last_run_hunch.json', 'last_run_bubble_android.json')
out = out.replace('click_chain_hunch.log', 'click_chain_bubble.log')
out = out.replace('log("HUNCH INSTALL FUNNEL  app=%s  gaid=%s"',
                  'log("BUBBLEBUS ANDROID FUNNEL  app=%s  gaid=%s"')
out = out.replace('print("signer    adj7_pure (pure Python, cert %s...)" % CAMPAIGN["cert_sha1"][:12])',
                  'print("signer    adj7_pure (pure Python, cert %s)"\n'
                  '          % (CAMPAIGN["cert_sha1"] or "none -> 40-NUL path"))')

# LINK uses {gaid}; open_direct_link() must substitute it (it took no arg
# before).  Patch the call site to fill the placeholder.
out = out.replace('status, hdrs, _ = _click_get(LINK)',
                  'status, hdrs, _ = _click_get(LINK.replace("{gaid}", gaid))', 1)
out = out.replace('% (datetime.now().isoformat(), gaid, LINK))',
                  '% (datetime.now().isoformat(), gaid,\n'
                  '                   LINK.replace("{gaid}", gaid)))', 1)

io.open(os.path.join(HERE, "run_bubble_android.py"), "w",
        encoding="utf-8").write(out)
print("written run_bubble_android.py,", out.count("\n"), "lines")