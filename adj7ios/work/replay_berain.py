# -*- coding: utf-8 -*-
"""replay_berain.py -- the attribution replay rule on the berain iOS capture
(com.berain.berain, ios5.5.2 / 3.62.0 / hid 8, consent.adjust.com).

G    genuine verbatim (carved query + captured Authorization)
O    ours, same map, fresh second + nonce
ARM  our signed /session -> wait ask_in -> our signed /attribution
"""
import json
import os
import re
import sys
import time
import urllib.parse

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7ios_pure as sg  # noqa: E402

RAW = os.path.join(HERE, 'saz_berain', 'raw')
HOST = 'https://consent.adjust.com'
SDK, HID, NV = 'ios5.5.2', '8', '3.62.0'
PAT = 'signature="([0-9A-Fa-f]+)"'
ATTR, SESS = 46, 17


def carve(n):
    t = open(os.path.join(RAW, '%03d_c.txt' % n), encoding='utf-8',
             errors='replace', newline='').read()
    head, _, body = t.partition('\r\n\r\n')
    line0 = t.split('\r\n', 1)[0]
    a = [l.split(': ', 1)[1] for l in head.split('\r\n')
         if l.startswith('Authorization')][0]
    if line0.startswith('GET') and '?' in line0:
        q = line0.split(' ', 2)[1].split('?', 1)[1].rsplit(' ', 1)[0]
        params = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
    else:
        q = None
        params = dict(urllib.parse.parse_qsl(body.strip(),
                                             keep_blank_values=True))
    ua = [l.split(': ', 1)[1] for l in head.split('\r\n')
          if l.startswith('User-Agent')][0]
    return q, params, a, ua


q, params, auth, ua = carve(ATTR)
sq, sp, sauth, _ = carve(SESS)
print('== app_token', params.get('app_token'), '| bundle',
      params.get('bundle_id'))
print('== UA:', ua)


def hdrs(a=None):
    h = {'User-Agent': ua, 'Client-Sdk': SDK, 'Accept': '*/*'}
    if a:
        h['Authorization'] = a
    return h


out = {}
r = requests.get(HOST + '/attribution?' + q, headers=hdrs(auth), timeout=30)
out['G'] = {'http': r.status_code, 'json': r.json()}
print('== G genuine verbatim ->', r.status_code, r.text[:180], flush=True)

import datetime as dt
tz = dt.timezone(dt.timedelta(hours=-4))
now = time.time()
p2 = dict(params)
p2['created_at'] = dt.datetime.fromtimestamp(now, tz).strftime(
    '%Y-%m-%dT%H:%M:%S.') + '%03dZ-0400' % int(now % 1 * 1000)
p2['sent_at'] = dt.datetime.fromtimestamp(now + 0.02, tz).strftime(
    '%Y-%m-%dT%H:%M:%S.') + '%03dZ-0400' % int(now % 1 * 1000)
auth_o = sg.sign_request(p2, 'attribution', second=int(now),
                         client_sdk=SDK, headers_id=HID,
                         native_version=NV)[0]
qo = urllib.parse.urlencode(p2, quote_via=urllib.parse.quote)
r2 = requests.get(HOST + '/attribution?' + qo, headers=hdrs(auth_o),
                  timeout=30)
out['O'] = {'http': r2.status_code, 'json': r2.json()}
print('== O ours fresh sig ->', r2.status_code, r2.text[:180], flush=True)

sp2 = dict(sp)
sp2['created_at'] = p2['created_at']
sp2['sent_at'] = p2['sent_at']
auth_s = sg.sign_request(sp2, 'session', second=int(now), client_sdk=SDK,
                         headers_id=HID, native_version=NV)[0]
rs = requests.post(HOST + '/session', data=sp2, headers=hdrs(auth_s),
                   timeout=30)
out['ARM_session'] = {'http': rs.status_code, 'json': rs.json()}
print('== ARM session ->', rs.status_code, rs.text[:180], flush=True)
try:
    ai = rs.json().get('ask_in')
except Exception:
    ai = None
if ai and ai < 60000:
    time.sleep(ai / 1000.0 + 1.0)
r3 = requests.get(HOST + '/attribution?' + qo, headers=hdrs(auth_o),
                  timeout=30)
out['ARM'] = {'http': r3.status_code, 'json': r3.json()}
print('== ARM attribution ->', r3.status_code, r3.text[:180], flush=True)

json.dump(out, open(os.path.join(HERE, 'replay_berain_result.json'), 'w'),
          indent=1)
same = (out['G']['http'] == out['O']['http']
        and out['G']['json'].get('attribution')
        == out['O']['json'].get('attribution'))
print()
print('G', out['G']['http'], '| O', out['O']['http'], '| ARM',
      out['ARM']['http'], '| O == G:', same)
