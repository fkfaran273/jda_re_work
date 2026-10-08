"""Evaluate JS in the active Chrome tab (CDP) and print the result."""
import json
import sys
import urllib.request

import websocket

EXPR = sys.argv[1]

tabs = json.load(urllib.request.urlopen("http://127.0.0.1:9222/json"))
tab = next(t for t in tabs if t["type"] == "page" and "mobpine" in t["url"])
ws = websocket.create_connection(tab["webSocketDebuggerUrl"], timeout=10,
                                 suppress_origin=True)
ws.send(json.dumps({
    "id": 1, "method": "Runtime.evaluate",
    "params": {"expression": EXPR, "returnByValue": True}}))
while True:
    msg = json.loads(ws.recv())
    if msg.get("id") == 1:
        print(json.dumps(msg["result"]["result"].get("value"), indent=1))
        break
