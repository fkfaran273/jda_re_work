#!/usr/bin/env python3
"""oracle_win.py — decisive test: can a DEVICE-ORACLE-SIGNED install win
non-organic offline (app never runs for that identity)?

  1. fresh GAID -> python tracker click (marker creative)
  2. frida oracle (sign.js) mints a REAL session signature inside com.penti.app
     for fabricated install params (our GAID, fresh android_uuid, +0530 now)
  3. send /session -> expect 200 + adid
  4. mint + send /attribution (initiated_by=sdk, same identity)
  5. read the response verdict (tracker_name/network/engagement_time)

Server-side truth from slices 92/93: only a device-produced package books.
If the oracle books -> FULL offline win (no app run, unlimited installs).
If Organic -> booking needs more than the signature.
"""
import base64, json, os, re, ssl, socket, subprocess, sys, time, uuid
import urllib.parse
sys.stdout.reconfigure(line_buffering=True)
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import click_bind_chain as cb
from win_attempt import current_gaid, set_gaid, sh, su  # helpers reuse

OUT = os.path.join(HERE, "oracle_win_result.json")
PROXY_HOST, PROXY_PORT = "127.0.0.1", 8888
FRIDA_EP = "127.0.0.1:4777"
APP_TOKEN = "jut9tib0eeps"
PKG = "com.penti.app"
UA = "Adjust SDK android5.7.0"


def ensure_frs():
    r = subprocess.run(["adb", "shell", "pgrep -f 'frs64 -l'"], capture_output=True, text=True)
    if not r.stdout.strip():
        sh("/debug_ramdisk/su -c 'nohup /data/local/tmp/frs64 -l 127.0.0.1:4777 >/dev/null 2>&1 &'")
        time.sleep(2)
    subprocess.run(["adb", "forward", "tcp:4777", "tcp:4777"], capture_output=True)


class Tun:
    """HTTPS over CONNECT proxy (direct PC egress to Adjust hangs)."""

    def __init__(self):
        self.sock = None

    def _connect(self):
        s = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=25)
        s.sendall(b"CONNECT app.adjust.com:443 HTTP/1.1\r\nHost: app.adjust.com:443\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d:
                raise RuntimeError("proxy closed during CONNECT")
            buf += d
        if b" 200 " not in buf.split(b"\r\n")[0]:
            raise RuntimeError("CONNECT refused: %r" % buf[:80])
        ctx = ssl._create_unverified_context()
        self.sock = ctx.wrap_socket(s, server_hostname="app.adjust.com")

    def call(self, path, body, auth):
        if self.sock is None:
            self._connect()
        hdrs = ("POST %s HTTP/1.1\r\nHost: app.adjust.com\r\n"
                "User-Agent: %s\r\nClient-SDK: android5.7.0\r\n"
                "Authorization: %s\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: %d\r\nConnection: keep-alive\r\n\r\n"
                % (path, UA, auth, len(body)))
        self.sock.sendall(hdrs.encode() + body)
        buf = b""
        try:
            while True:
                d = self.sock.recv(65536)
                if not d:
                    break
                buf += d
                if b"\r\n\r\n" in buf and (b"ask_in" in buf or b"tracker" in buf
                                           or b"Organic" in buf or b"error" in buf):
                    break
                if len(buf) > 200000:
                    break
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.sock = None
        head, _, payload = buf.partition(b"\r\n\r\n")
        code = int(head.split(b" ")[1]) if b" " in head else 0
        return code, payload.decode("utf-8", "replace"), head.decode("latin1", "replace")


def attach_oracle(tries=6):
    import frida
    dev = frida.get_device_manager().add_remote_device(FRIDA_EP)
    js = open(os.path.join(HERE, "..", "device", "sign.js"), encoding="utf-8").read()
    last = None
    for i in range(tries):
        r = subprocess.run(["adb", "shell", "pidof " + PKG], capture_output=True, text=True)
        pids = r.stdout.strip().split()
        if not pids:
            sh("am start -n %s/.ui.main.MainActivity" % PKG)
            time.sleep(5)
            continue
        pid = int(pids[0])
        try:
            sess = dev.attach(pid)
            script = sess.create_script(js)
            script.load()
            ex = script.exports_sync if hasattr(script, "exports_sync") else script.exports
            h = ex.health()
            if h.get("loaded"):
                print("[oracle] attached pid %d (try %d)" % (pid, i + 1))
                return sess, script
        except Exception as e:
            last = e
            print("[oracle] attach try %d failed: %s" % (i + 1, e))
            ensure_frs()
            time.sleep(6)
    raise RuntimeError("oracle attach failed: %r" % last)


def mint(script, activity, globals_):
    ex = script.exports_sync if hasattr(script, "exports_sync") else script.exports
    out = ex.mint({"activity": activity, "globals": globals_})
    if not out.get("ok"):
        raise RuntimeError("mint failed: %r / %r" % (out.get("error"), out.get("stack")))
    return out["authorization"], out.get("canonical", "")


def stamp(t=None):
    t = t or time.gmtime(time.time() + 5 * 3600 + 1800)
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z+0530", t)


def install_params(gaid, auid, now):
    return {
        "store_name_from_system": "com.android.vending", "gps_adid_attempt": "1",
        "api_level": "31", "hardware_name": "S2SE32.28-28-4",
        "app_version": "3.13.9", "app_token": APP_TOKEN,
        "installed_at": stamp(time.gmtime(now - 2 * 86400)),
        "created_at": stamp(time.gmtime(now)), "wait_total": "0.0",
        "device_type": "phone", "language": "tr", "gps_adid": gaid,
        "foreground": "1", "connectivity_type": "1",
        "device_manufacturer": "motorola", "display_width": "1080",
        "device_name": "moto g42", "needs_response_details": "1",
        "os_build": "S2SE32.28-28-4", "updated_at": stamp(time.gmtime(now)),
        "cpu_type": "arm64-v8a", "retry_count": "0", "screen_size": "normal",
        "screen_format": "long", "last_error": "0", "gps_adid_src": "service",
        "wait_time": "0.0", "os_version": "12", "first_error": "0",
        "android_uuid": auid, "sent_at": stamp(time.gmtime(now)),
        "offline_mode_enabled": "0", "environment": "production",
        "screen_density": "high", "attribution_deeplink": "1",
        "session_count": "1", "display_height": "2237",
        "package_name": PKG, "initiating_package_name": "com.android.vending",
        "os_name": "android", "ui_mode": "1", "enqueue_size": "0",
        "tracking_enabled": "1",
    }


def attr_params(gaid, auid, now):
    return {
        "initiated_by": "sdk", "gps_adid_attempt": "1", "api_level": "31",
        "app_version": "3.13.9", "app_token": APP_TOKEN, "os_version": "12",
        "created_at": stamp(time.gmtime(now)), "device_type": "phone",
        "gps_adid": gaid, "foreground": "1", "android_uuid": auid,
        "sent_at": stamp(time.gmtime(now)), "offline_mode_enabled": "0",
        "device_name": "moto g42", "environment": "production",
        "needs_response_details": "1", "attribution_deeplink": "1",
        "package_name": PKG, "os_name": "android", "ui_mode": "1",
        "gps_adid_src": "service", "tracking_enabled": "1",
    }


def main():
    ensure_frs()
    res = {"runs": []}
    gaid_new = str(uuid.uuid4())
    got = set_gaid(gaid_new)
    print("[*] GAID %s (readback %s)" % (gaid_new, got))
    marker = "cline_orc1"
    url = cb.expand(cb.LINK.replace("creative=penti_generic", "creative=" + marker), gaid_new)
    code, ref, hops = cb.tracker_click(url, gaid_new)
    print("[*] click http=%s reftag=%s" % (code, (ref or "?").split("&")[0]))

    auid = str(uuid.uuid4())
    now = int(time.time())
    sess, script = attach_oracle()
    tun = Tun()

    act = install_params(gaid_new, auid, now)
    auth, canon = mint(script, act, {"activity_kind": "session", "client_sdk": "android5.7.0"})
    print("[*] session minted: auth %dB canonical %dB" % (len(auth), len(canon)))
    body = urllib.parse.urlencode(act).encode()
    c1, p1, h1 = tun.call("/session", body, auth)
    print("[*] /session -> %d %s" % (c1, p1[:200]))
    time.sleep(3)

    now2 = int(time.time())
    act2 = attr_params(gaid_new, auid, now2)
    auth2, _ = mint(script, act2, {"activity_kind": "attribution", "client_sdk": "android5.7.0"})
    body2 = urllib.parse.urlencode(act2).encode()
    c2, p2, h2 = tun.call("/attribution", body2, auth2)
    print("[*] /attribution -> %d %s" % (c2, p2[:400]))
    try:
        sess.detach()
    except Exception:
        pass
    if '"tracker_name":"Organic"' in p2 or '"network":"Organic"' in p2:
        verdict = "ORGANIC"
    elif '"tracker_token":"24' in p2 or "VKM" in p2:
        verdict = "NONORGANIC"
    else:
        verdict = "UNKNOWN"
    print("[*] VERDICT: %s" % verdict)
    res["runs"].append({"gaid": gaid_new, "auid": auid, "marker": marker,
                        "click_http": code, "referrer": ref,
                        "session_status": c1, "session_resp": p1[:300],
                        "attr_status": c2, "attr_resp": p2[:800],
                        "verdict": verdict})
    json.dump(res, open(OUT, "w"), indent=1)
    print("[*] saved", OUT)


if __name__ == "__main__":
    main()
