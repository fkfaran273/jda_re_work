# -*- coding: utf-8 -*-
import json, sys
sys.path.insert(0, '.')
import adj7ios_pure as sg3
v = json.load(open('gold_vectors.json'))
fails = {}
for x in v:
    sec = x['second']
    for adv in (0, 1, 2):
        try:
            _a, blob = sg3.sign_request(x['params'], x['kind'], second=sec,
                                        nonce12=bytes(bytearray.fromhex(
                                            x['nonce12'])),
                                        client_sdk=x.get('client_sdk', ''),
                                        headers_id=x.get('headers_id', '8'),
                                        native_version=x.get(
                                            'native_version', '3.62.0'),
                                        advance=adv)
        except TypeError:
            _a, blob = sg3.sign_request(x['params'], x['kind'], second=sec,
                                        nonce12=bytes(bytearray.fromhex(
                                            x['nonce12'])),
                                        client_sdk=x.get('client_sdk', ''))
            adv = 0
        if blob.hex().upper() == x['sig'].upper():
            fails[(x['capture'], x['sid'])] = adv
            break
print('vectors needing advance>0:')
for k, adv in sorted(fails.items()):
    print('  ', k, 'advance =', adv)
