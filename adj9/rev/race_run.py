# race_run.py - THE VERBATIM RACE (slice 97 §5.3 branch 2):
#  click(fresh GAID) -> pm clear -> attach pre-guard -> ARM race RPC ->
#  launch -> the app signs its OWN attribution map -> the nSign hook PARKS the
#  app's thread AFTER the blob exists but BEFORE its HTTP send -> PC relays the
#  verbatim blob FIRST -> release -> read device + PC verdicts.
# If PC-verbatim == device verdict -> the blob content alone decides (booking
# by first presentation). If PC organic while device non-organic -> the server
# binds the package to the app's exact socket/session, not just content.
import base64
import http.client
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
AGJS = os.path.join(HERE, "agent", "adj9agent.js")
OUT = os.path.join(HERE, "race_result.json")
import frida
import farm_win as fw
import sig_probe as sp
import device_funnel as df

df.install_proxy("http://127.0.0.1:8888")
os.environ["ADJ_INSECURE"] = "1"

ev = {"hold": None}
HOLD, READY = threading.Event(), threading.Event()


def on_msg(m, data):
    if m.get("type") != "send":
        print("[?]", str(m)[:200]); return
    p = m.get("payload", {}); t = p.get("type")
    if t == "race_hold":
        ev["hold"] = p
        HOLD.set()
        print("[HOLD] app thread parked, blob %d pairs" % len(p.get("pairs") or []))
    elif t == "ready":
        READY.set()
        print("[ev] ready")
    elif t == "nSign":
        print("[nSign %s B]" % p.get("outLen"))
    elif t == "sigmap":
        print("[sigmap] act=%d" % len(p.get("activity") or {}))
    else:
        print("[ev]", str(p)[:140])


def sh(cmd):
    return subprocess.run(["adb", "shell", cmd], capture_output=True, text=True,
                          timeout=30).stdout


def send_auth(url, b, auth_value):
    pr = urllib.parse.urlsplit(url)
    path = pr.path + ("?" + pr.query if pr.query else "")
    conn = http.client.HTTPSConnection(pr.hostname, 443, timeout=30)
    conn.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", auth_value)
    conn.putheader("User-Agent", sp.fc.UA)
    conn.putheader("Host", pr.hostname)
    conn.putheader("Connection", "Keep-Alive")
    conn.putheader("Accept-Encoding", "gzip")
    conn.endheaders()
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    conn.close()
    return r.status, body


res = {"phases": {}}
