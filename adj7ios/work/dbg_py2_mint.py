# -*- coding: utf-8 -*-
import binascii, json, sys
sys.path.insert(0, '.')
import adj7ios_pure_py27 as sg

v = json.load(open('gold_vectors.json'))[0]
print('vector:', v['capture'], v['sid'], v['kind'], 'sec', v['second'])
nonce = binascii.unhexlify(v['nonce12'])
claims = sg.build_claims(v['kind'], v['params'],
                         client_sdk=v.get('client_sdk', ''))
blob = sg.sign(v['second'], nonce, claims)
mine = binascii.hexlify(blob).upper()
want = v['sig'].upper()
print('len mine', len(mine), 'want', len(want))
i = 0
while i < min(len(mine), len(want)) and mine[i] == want[i]:
    i += 1
print('first diff at hex', i)
print('mine ...', mine[max(0, i - 8):i + 16])
print('want ...', want[max(0, i - 8):i + 16])
print('header mine', binascii.hexlify(blob[:16]).upper())
print('header want', want[:32])
print('claims repr head:', repr(claims[:60]))
print('params type', type(v['params']), 'nkeys', len(v['params']))
