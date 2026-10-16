# -*- coding: utf-8 -*-
import json, sys
sys.path.insert(0, '.')
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7ios\work')
import adj7ios_pure_py27 as sg2

v = json.load(open('gold_vectors.json'))[0]
c2 = sg2.build_claims(v['kind'], v['params'],
                      client_sdk=v.get('client_sdk', ''))
open('claims_py2.bin', 'wb').write(c2)
print('py2 claims len', len(c2))
print('py2 head', repr(c2[:80]))
