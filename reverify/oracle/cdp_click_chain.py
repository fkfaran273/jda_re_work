"""Capture the GENUINE Chrome click chain via CDP (no proxy, no CA, real
fingerprint): Network.enable + Page.navigate, collect every
requestWillBeSent (each carries the full request + the redirectResponse of
the previous hop).

Usage: python cdp_click_chain.py <url> [out.json] [seconds]
"""
import json
import sys
import time
import urllib.request
import uuid

import websocket

URL = sys.argv[1]
OUT = sys.argv[2] if len(sys.argv) > 2 else "genuine_click_chain.json"
SECS = int(sys.argv[3]) if len(sys.argv) > 3 else 30

tabs = json.load(urllib.request.urlopen("http://127.0.0.1:9222/json"))
tab = next(t for t in tabs if t["type"] == "page")
ws = websocket.create_connection(tab["webSocketDebuggerUrl"], timeout=10,
                                 suppress_origin=True)

events = []
_id = [0]


def send(method, params=None):
    _id[0] += 1
    ws.send(json.dumps({"id": _id[0], "method": method,
                        "params": params or {}}))
    return _id[0]


send("Network.enable")
send("Page.enable")
send("Page.navigate", {"url": URL})

ws.settimeout(2)
t0 = time.time()
while time.time() - t0 < SECS:
    try:
        raw = ws.recv()
    except websocket.WebSocketTimeoutException:
        continue
    except Exception:
        break
    msg = json.loads(raw)
    m = msg.get("method", "")
    if m == "Network.requestWillBeSent":
        p = msg["params"]
        events.append({
            "url": p["request"]["url"],
            "method": p["request"]["method"],
            "headers": p["request"]["headers"],
            "type": p.get("type"),
            "initiator": (p.get("initiator") or {}).get("type"),
            "redirect": ({
                "status": p["redirectResponse"]["status"],
                "headers": p["redirectResponse"]["headers"],
            } if "redirectResponse" in p else None),
        })
    elif m == "Network.responseReceived":
        p = msg["params"]
        events.append({
            "url": p["response"]["url"],
            "status": p["response"]["status"],
            "headers": p["response"]["headers"],
            "_resp": True,
        })

with open(OUT, "w", encoding="utf-8") as f:
    json.dump({"url": URL, "events": events}, f, indent=1)
print("captured %d events -> %s" % (len(events), OUT))
for e in events[:40]:
    tag = "R" if e.get("_resp") else ">"
    line = e["url"][:130]
    if e.get("redirect"):
        line = "[%d] %s" % (e["redirect"]["status"], line)
    elif e.get("status"):
        line = "[%d] %s" % (e["status"], line)
    print(tag, line)
