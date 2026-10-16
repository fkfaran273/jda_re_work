# -*- coding: utf-8 -*-
import json, sys
sys.path.insert(0, '.')
import adj7ios_pure as sg

v = json.load(open('gold_vectors.json'))
byname = {}
for x in v:
    byname.setdefault(x['capture'], []).append(x)
# the 6 failures
fails = [('watsons', '034'), ('nirio', '33'), ('lululemon', '1'),
         ('hunchdating', '21'), ('hunchdating', '44'), ('eatr', '088')]
for cap, sid in fails:
    x = [y for y in byname[cap] if y['sid'] == sid][0]
    claims = sg.build_claims(x['kind'], x['params'],
                             client_sdk=x['client_sdk'])
    nonce = bytes(bytearray.fromhex(x['nonce12']))
    print('=== %s %s kind=%s sec=%d' % (cap, sid, x['kind'], x['second']))
    # what seconds do OTHER vectors of this capture use?
    print('    capture seconds:', [(y['sid'], y['kind'], y['second'])
                                   for y in byname[cap]])
    for adv in (0, 1, 2):
        blob = sg.sign(x['second'], nonce, claims, advance=adv)
        ok = blob.hex().upper() == x['sig'].upper()
        print('    advance=%d -> %s' % (adv, 'BYTE-EXACT' if ok else 'diff'))
        if ok:
            break
    # also: is the genuine header maybe at a NEIGHBOURING second?
    tgt = x['sig'][:32].upper()
    for d in range(-5, 6):
        if sg.make_header(x['second'] + d).hex().upper() == tgt:
            print('    genuine header == make_header(sec%+d)' % d)
