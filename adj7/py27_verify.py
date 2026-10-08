# -*- coding: utf-8 -*-
import sys, json, re, hmac, hashlib, calendar
sys.path.insert(0, '.')
import adj7_pure_py27 as sg

def unhex(s):
    return s.decode('hex') if hasattr(s, 'decode') else bytes.fromhex(s)

d = json.load(open('py27_test_input.json'))
fields = d['fields']; nonce12 = unhex(d['nonce12'])
cert40 = str(d['cert40']); blob_dev = unhex(d['blob'])

ca = d['created_at']
m = re.match(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})', ca)
Y, Mo, Dd, h, mi, s = m.groups()
sec = calendar.timegm((int(Y), int(Mo), int(Dd), int(h), int(mi), int(s))) - 19800

claims = sg.build_claims('session', fields, client_sdk='android5.6.0',
                         include_block2=True)
blob = sg.sign(sec, nonce12, claims, cert40)
print('py27 session blob == device blob:', blob == blob_dev)
