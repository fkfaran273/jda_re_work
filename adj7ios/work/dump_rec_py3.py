# -*- coding: utf-8 -*-
import binascii, json, sys
sys.path.insert(0, '.')
import adj7ios_pure as sg3
v = json.load(open('gold_vectors.json'))[0]
nonce = binascii.hexlify  # placeholder
nonce = bytes(bytearray.fromhex(v['nonce12']))
claims = sg3.build_claims(v['kind'], v['params'],
                          client_sdk=v.get('client_sdk', ''))
H = sg3.commitment_digest(claims, nonce)
rec = sg3.build_record(H, nonce)
open('rec_py3.bin', 'wb').write(rec)
print('py3 H', H.hex().upper())
print('py3 rec[:64]', repr(rec[:64]))
