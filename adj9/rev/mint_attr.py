# mint_attr.py - THE CORRECTED DECISIVE TEST.
#  * mint (device keystore) a package whose signed claim set is EXACTLY the set the
#    server will derive from the request: the app's own /attribution param set,
#    kind='attribution' in BOTH maps (the old run left 'session' in the globals,
#    which is why the payload never matched).
#  * then send it to /attribution with a query built from the mint's OWN returned
#    mapPairs - so request and signature agree by construction.
#  * GAID = e7262a88 (record exists, true state VKM 2456eyqn); recognition shows as
#    the record / 400 ask_in instead of wy7261z Organic.
import json
import os
import shlex
import subprocess
import sys
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import frida

AGJS = os.path.join(HERE, 'agent', 'adj9agent.js')
OUT = os.path.join(HERE, 'mint_attr.json')
PKG = 'com.penti.app'
TARGET_GPS = 'e7262a88-b19a-41ec-a76c-7f122fc266f2'
ATTRIB_KEYS = ['initiated_by', 'gps_adid_attempt', 'api_level', 'app_version',
               'app_token', 'os_version', 'created_at', 'device_type', 'gps_adid',
               'foreground', 'android_uuid', 'sent_at', 'offline_mode_enabled',
               'device_name', 'environment', 'needs_response_details',
               'attribution_deeplink', 'package_name', 'os_name', 'ui_mode',
               'gps_adid_src', 'tracking_enabled']
HEADER_ONLY = {'adj_signing_id', 'client_sdk', 'headers_id', 'native_version',
               'algorithm', 'adj_verification', 'activity_kind', 'endpoint'}

READY = threading.Event()
PIGGY = []
SIGMAP = []


def sh(cmd):
    return subprocess.run(['adb', 'shell', cmd], capture_output=True).stdout.decode(
        'utf-8', 'replace')


def on_msg(m, data):
    if m.get('type') == 'send':
        p = m.get('payload', {})
        t = p.get('type')
        if t == 'ready':
            READY.set()
        elif t == 'sigmap':
            SIGMAP.append(p)
        elif t == 'piggy':
            PIGGY.append(p.get('result'))
            print('[piggy]', str(p.get('result'))[:200], flush=True)
        elif t in ('nSign', 'log'):
            print('[ev]', str(p.get('type')), flush=True)
    elif m.get('type') == 'error':
        print('[!]', str(m)[:200], flush=True)


def restart_frida():
    subprocess.run(['adb', 'shell',
                    "/debug_ramdisk/su -c 'pkill -9 frs64; pkill -9 fs17root'"],
                   capture_output=True)
    time.sleep(1)
    subprocess.Popen(['adb', 'shell',
                      "/debug_ramdisk/su -c 'exec /data/local/tmp/fs17root'"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    subprocess.run(['adb', 'forward', 'tcp:27042', 'tcp:27042'], capture_output=True)


def live_map():
    """values from the last live capture (mo1.json = the app's own session map)"""
    T = os.environ.get('TEMP')
    for n in ('mo1.json', 'mo1b.json', 'mo2.json'):
        p = os.path.join(T, n)
        if os.path.exists(p):
            M = json.loads(open(p, 'rb').read().decode('utf-16'))
            return dict(M['mapPairs'])
    return {}


def main():
    live = live_map()
    print('live values available: %d keys' % len(live))
    amap = {}
    for k in ATTRIB_KEYS:
        v = live.get(k)
        if v is not None:
            amap[k] = v
    amap['gps_adid'] = TARGET_GPS
    # the app ALWAYS sends initiated_by=backend on /attribution and it is
    # payload-bearing (probe3) - omitting it could let the server inject a default
    # and break the payload match.
    amap['initiated_by'] = 'backend'
    amap['language'] = live.get('language', 'tr')
    print('mint map (%d keys): %s' % (len(amap), sorted(amap)))
    restart_frida()
    rdev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    sh("/debug_ramdisk/su -c 'am force-stop %s'" % PKG)
    time.sleep(1)
    subprocess.run(['adb', 'shell', 'pm', 'clear', PKG], capture_output=True)
    time.sleep(1)
    pid = 0
    for _ in range(30):
        pid = int(sh('pidof %s' % PKG).strip() or 0)
        if pid:
            break
        sh('am start -n %s/.ui.main.MainActivity' % PKG)
        time.sleep(0.4)
    print('[*] pre-guard attach pid', pid)
    sess = None
    for _ in range(8):
        try:
            sess = rdev.attach(pid)
            break
        except Exception as e:
            print('[!] attach retry:', str(e)[:80])
            time.sleep(0.7)
            pid = int(sh('pidof %s' % PKG).strip() or 0)
    if sess is None:
        print('[F] could not attach')
        return
    scr = sess.create_script(open(AGJS, encoding='utf-8').read())
    scr.on('message', on_msg)
    scr.load()
    for _ in range(40):
        if READY.is_set():
            break
        time.sleep(0.5)
    print('[*] ready:', READY.is_set())
    r = scr.exports_sync.setmint({'replace': True, 'kind': 'attribution',
                                  'activity': amap,
                                  'globals': {'client_sdk': 'android5.7.0',
                                              'endpoint': 'https://app.adjust.com'}})
    print('[*] setmint ->', r)
    for i in range(180):
        if PIGGY:
            break
        if i == 40:
            sh('input keyevent KEYCODE_HOME')
            time.sleep(0.6)
            sh('am start -n %s/.ui.main.MainActivity' % PKG)
        time.sleep(0.5)
    good = [p for p in PIGGY if p and p.get('auth')]
    if not good:
        print('[F] no mint with auth; piggy results:', len(PIGGY))
        return
    mint = good[0]
    json.dump(mint, open(OUT, 'w'), indent=1)
    print('[+] minted blob %d B, auth %d chars -> %s'
          % (len(mint['blobB64']), len(mint['auth']), OUT))
    pairs = mint['mapPairs']
    q = {}
    for k, v in pairs:
        if k in HEADER_ONLY or v is None:
            continue
        q.setdefault(k, v)
    print('send query (%d keys): %s' % (len(q), sorted(q)))
    parts = ['curl', '-s', '-S', '-k', '--max-time', '45', '-w',
             '\\n###HTTP:%{http_code}', '-H', 'Client-SDK: android5.7.0',
             '-H', 'User-Agent: Dalvik/2.1.0 (Linux; U; Android 12; moto g42 '
                   'Build/S2SE32.28-28-4)',
             '-H', 'Authorization: ' + mint['auth'],
             'https://app.adjust.com/attribution?' + urllib.parse.urlencode(q)]
    remote = ' '.join(shlex.quote(p) for p in parts)
    p = subprocess.run(['adb', 'shell', remote], capture_output=True, timeout=120)
    print('=== /attribution response ===')
    print(p.stdout.decode('utf-8', 'replace')[:900])
    sess.detach()


if __name__ == '__main__':
    main()