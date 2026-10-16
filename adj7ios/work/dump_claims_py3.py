# -*- coding: utf-8 -*-
import json, sys
sys.path.insert(0, '.')
import adj7ios_pure as sg3
v = json.load(open('gold_vectors.json'))[0]
c3 = sg3.build_claims(v['kind'], v['params'],
                      client_sdk=v.get('client_sdk', ''))
open('claims_py3.bin', 'wb').write(c3)
print('py3 claims len', len(c3))
print('py3 head', repr(c3[:80]))
