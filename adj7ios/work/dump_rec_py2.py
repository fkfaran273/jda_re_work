# -*- coding: utf-8 -*-
import binascii, json, sys
sys.path.insert(0, '.')
import adj7ios_pure_py27 as sg2
v = json.load(open('gold_vectors.json'))[0]
nonce = binascii.unhexlify(v['nonce12'])
claims = sg2.build_claims(v['kind'], v['params'],
                          client_sdk=v.get('client_sdk', ''))
H = sg2.commitment_digest(claims, nonce)
rec = sg2.build_record(H, nonce)
open('rec_py2.bin', 'wb').write(rec)
open('H_py2.txt', 'w').write(binascii.hexlify(H).upper())
print('py2 H', binascii.hexlify(H).upper())
print('py2 rec[:64]', repr(rec[:64]))
