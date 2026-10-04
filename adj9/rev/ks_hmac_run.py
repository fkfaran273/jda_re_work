# ks_hmac_run.py - capture key2 by combining:
#   (1) keystore2 hook (HMAC_Init_ex -> raw key bytes, HMAC_Final -> H)
#   (2) app-side keystore HMAC for alias "key2"  (guaranteed op)
import json
import os
import subprocess
import threading
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
KS_JS = open(os.path.join(HERE, 'agent', 'ksdump8.js'), encoding='utf-8').read()
APP_JS = os.path.join(HERE, 'agent', 'ks_hmac2_b.js')
OUT = os.path.join(HERE, 'ks_hmac_capture.json')
APP = 'com.penti.app'
ks_events, app_events = [], []


def sh(cmd):
    return subprocess.run(['adb', 'shell', cmd], capture_output=True, text=True,
                          timeout=30).stdout


def restart_frida():
    subprocess.run(['adb', 'shell', "/debug_ramdisk/su -c 'pkill -9 frs64; pkill -9 fs17root'"],
                   capture_output=True)
    time.sleep(1)
    subprocess.Popen(['adb', 'shell', "/debug_ramdisk/su -c 'exec /data/local/tmp/fs17root'"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    subprocess.run(['adb', 'forward', 'tcp:27042', 'tcp:27042'], capture_output=True)


def main():
    restart_frida()
    dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')

    def ks_msg(m, data):
        if m.get('type') != 'send':
            return
        p = m.get('payload', {})
        ks_events.append(p)
        t = p.get('t')
        if t == 'hmac_key':
            print('[KS HMAC KEY] len=%s key=%s hex64=%s'
                  % (p.get('klen'), p.get('key'), p.get('hex64')), flush=True)
        elif t == 'hmac_upd':
            print('[KS upd] len=%s %s' % (p.get('len'), str(p.get('data'))[:70]), flush=True)
        elif t == 'hmac_final':
            print('[KS H] %s' % p.get('out'), flush=True)
        elif t in ('hooked', 'ready', 'symbol'):
            print('[KS %s] %s' % (t, str(p)[:120]), flush=True)

    # (1) keystore2 hook
    kspid = int(sh('pidof keystore2').strip().split()[0])
    print('keystore2 pid', kspid, flush=True)
    kssess = dev.attach(kspid)
    ksscr = kssess.create_script(KS_JS)
    ksscr.on('message', ks_msg)
    ksscr.load()
    time.sleep(1)

    # (2) app-side keystore HMAC
    def app_msg(m, data):
        if m.get('type') != 'send':
            print('[APP !]', str(m)[:200], flush=True)
            return
        p = m.get('payload', {})
        app_events.append(p)
        t = p.get('t')
        if t == 'step':
            print('[APP step] %s %s ty=%s' % (p.get('s'), str(p.get('v'))[:160],
                                              p.get('ty')), flush=True)
        else:
            print('[APP] %s' % str(p)[:260], flush=True)

    sh('/debug_ramdisk/su -c \'am force-stop %s\'' % APP)
    time.sleep(1)
    sh('am start -n com.penti.app/.ui.main.MainActivity')
    pid = 0
    for _ in range(30):
        pid = int(sh('pidof %s' % APP).strip() or 0)
        if pid:
            break
        time.sleep(0.3)
    print('pre-guard attach pid', pid, flush=True)
    appsess = None
    for _ in range(8):
        try:
            appsess = dev.attach(pid)
            break
        except Exception as e:
            print('[!] attach retry:', str(e)[:90], flush=True)
            time.sleep(0.7)
            pid = int(sh('pidof %s' % APP).strip() or 0)
            if not pid:
                sh('am start -n com.penti.app/.ui.main.MainActivity')
                time.sleep(0.6)
                pid = int(sh('pidof %s' % APP).strip() or 0)
    if appsess is None:
        print('could not attach to app', flush=True)
        return
    appscr = appsess.create_script(open(APP_JS, encoding='utf-8').read())
    appscr.on('message', app_msg)
    appscr.load()
    for i in range(25):
        time.sleep(1)
        if any(p.get('t') in ('mac', 'err') for p in app_events):
            break
    time.sleep(2)
    json.dump({'ks': ks_events, 'app': app_events}, open(OUT, 'w'), indent=1)
    print('saved', OUT, '| ks events:', len(ks_events),
          '| hmac_key:', len([e for e in ks_events if e.get('t') == 'hmac_key']))
    try:
        appsess.detach()
    except Exception:
        pass
    try:
        kssess.detach()
    except Exception:
        pass


if __name__ == '__main__':
    main()