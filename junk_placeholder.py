#!/usr/bin/env python3
"""oracle_win.py — the decisive test: can a DEVICE-ORACLE-SIGNED install win
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
import base64, json, os, re, ssl, subprocess, sys, time, uuid
import http.client, urllib.parse
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

# ---------------------------------------------------------------- device/proxy
def ensure_frs():
    r = subprocess.run(["adb", "shell", "pgrep -f 'frs64 -l'"], capture_output=True, text=True)
    if not r.stdout.strip():
        sh("/debug_ramdisk/su -c 'killall frs64 frs64 -l' 2>/dev/null; true")
        sh("/debug_ramdisk/su -c 'nohup /data/local/tmp/frs64 -l 127.0.0.1:4777 >/dev/null 2>&1 &'")
        time.sleep(2)
    subprocess.run(["adb", "forward", "tcp:4777", "tcp:4777"], capture_output=True)

def socket_create():
    import socket
    return socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=25)

class Tun:
    """HTTPS over CONNECT proxy (the PC egress hangs direct)."""
    def __init__(self):
        self.sock = None

    def _connect(self):
        s = socket_create()
        s.connect((PROXY_HOST, PROXY_PORT))
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
        hdrs = ("POST %s HTTP1.1\r\n" % path).replace("HTTP1.1", "HTTP/1.1")
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
                if b"\r\n\r\n" in buf and b"ask_in" in buf:
                    break
                if len(buf) > 200000:
                    break
        except Exception:
            pass
        self.sock.close(); self.sock = newsock = None
        head, _, payload = buf.partition(b"\r\n\r\n")
        code = int(head.split(b" ")[1]) if b" " in head else 0
        return code, payload.decode("utf-8", "replace"), head.decode("latin1", "replace")