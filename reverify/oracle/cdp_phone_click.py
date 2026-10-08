"""Phone-click via CDP with Fetch interception: navigate Chrome to the
tracker link, PAUSE the market:// hop (capturing its full URL incl.
referrer=), abort it, and report the reftag + the adjust server Date.

Usage: python cdp_phone_click.py <url>
"""
import email.utils
import json
import sys
import time
import urllib.request
import urllib.parse

import websocket

URL = sys.argv[1]

tabs = json.load(urllib.request.urlopen("http://127.0.0.1:9222/json"))
tab = next(t for t in tabs if t["type"] == "page")
ws = websocket.create_connection(tab["webSocketDebuggerUrl"], timeout=10,
                                 suppress_origin=True)

_id = [0]
reftag = None
click_sec = None


def send(method, params=None):
    _id[0] += 1
    ws.send(json.dumps({"id": _id[0], "method": method, "params": params or {}}))


send("Network.enable")
send("Page.enable")
send("Fetch.enable", {"patterns": [{"urlPattern": "market://*"},
                                   {"urlPattern": "intent://*"}]})
send("Page.navigate", {"url": URL})

t0 = time.time()
ws.settimeout(2)
while time.time() - t0 < 25 and reftag is None:
    try:
        raw = ws.recv()
    except websocket.WebSocketTimeoutException:
        continue
    except Exception:
        break
    m = json.loads(raw)
    meth = m.get("method", "")
    p = m.get("params", {})
    if meth == "Fetch.requestPaused":
        u = p["request"]["url"]
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(u).query,
                                  keep_blank_values=True)
        if "referrer" in q:
            reftag = q["referrer"][0]
        send("Fetch.failRequest", {"requestId": p["requestId"],
                                   "errorReason": "Aborted"})
    elif meth == "Network.responseReceived":
        h = p["response"]["headers"]
        if "app.adjust.com" in p["response"]["url"]:
            d = h.get("date") or h.get("Date")
            if d and click_sec is None:
                click_sec = int(
                    email.utils.parsedate_to_datetime(d).timestamp())

print("CLICK_SEC=%s" % click_sec)
print("REFTAG=%r" % reftag)
