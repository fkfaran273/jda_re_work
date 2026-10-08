"""Tap the hunch click URL in the DEVICE's real Chrome via CDP and capture
the 302 chain (adjust hop + market referrer) exactly as the device fires it."""
import json
import re
import sys
import time
import urllib.parse
import urllib.request
import websocket

LINK = ("https://app.adjust.com/1yzhva5b?campaign=SOHYPE_ADH"
        "&adgroup={affiliate_id}")

new_tab = json.loads(urllib.request.urlopen(
    urllib.request.Request('http://127.0.0.1:9222/json/new?about:blank',
                           method='PUT'),
    timeout=10).read().decode())
page = new_tab
wsurl = page['webSocketDebuggerUrl']
print('fresh target:', page.get('id'), flush=True)

ws = websocket.create_connection(wsurl, timeout=30, suppress_origin=True)
mid = [0]
def send(method, params=None):
    mid[0] += 1
    ws.send(json.dumps({'id': mid[0], 'method': method,
                        'params': params or {}}))
    return mid[0]
send('Network.enable')
send('Page.enable')
nav_id = send('Page.navigate', {'url': LINK})
chain = []
t0 = time.time()
ws.settimeout(1.0)
seen = set()
try:
    while time.time() - t0 < 25:
        try:
            msg = json.loads(ws.recv())
        except Exception:
            continue
        m = msg.get('method', '')
        if m and m not in seen:
            seen.add(m)
            print('EVT', m, flush=True)
        if m == 'Network.responseReceived':
            p = msg['params']
            resp = p.get('response', {})
            loc = ''
            for k, v in (resp.get('headers') or {}).items():
                if k.lower() == 'location':
                    loc = v
            chain.append((resp.get('url', '')[:120], resp.get('status'), loc[:220]))
            print('RESP %s -> %s loc=%s' % (resp.get('url', '')[:100], resp.get('status'), loc[:160]), flush=True)
            if 'referrer=' in loc:
                break
        if m == 'Network.requestWillBeSent' and 'redirectResponse' in msg.get('params', {}):
            rr = msg['params']['redirectResponse']
            print('REDIR %s -> %s' % (rr.get('url', '')[:100], rr.get('status')), flush=True)
except Exception as e:
    print('ws end', e, flush=True)
ws.close()
open('device_tap_chain.json', 'w').write(json.dumps(chain, indent=1))
ref = None
for _u, _s, loc in chain:
    if 'referrer=' in loc:
        ref = urllib.parse.unquote(loc.split('referrer=', 1)[1]).split(';S.browser_fallback_url')[0]
        ref = re.sub(r'&ip_address=\{[^&]*\}', '', ref)
        break
print('REFTAG:', ref, flush=True)
open('device_reftag.txt', 'w').write(ref or '')
