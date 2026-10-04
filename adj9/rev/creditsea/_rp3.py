"""_rp3.py — same claims, same second: testbed (proven) vs signer_simple."""
import sys, os, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
from testbed import mine_log, decode, region_parts, build_descs
import desc10_58 as D
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj9sign')
import signer_simple as sg
sg.DESC9 = bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")
_o = D.claims_for_law_58
def c58(val, kind):
    v = dict(val); v["client_sdk"] = "flutter5.8.0@android5.8.0"
    return _o(v, kind)
sg.claims_for_law = c58

s = mine_log()[0]
kind = s['val'].get('activity_kind', 'session')
dec = decode(s['blob'])
d0, d4, d2, pfx = region_parts(dec, s['second'])
raw, padded = D.claims_for_law_58(s['val'], kind)
tb = build_descs(s['second'], raw, d0, d4, d2)
print('TESTBED descs (proven 192/192):')
for i, (ln, _, data) in enumerate(tb):
    h = data.hex()[:40] if data else ''
    print('   #%-2d len=%-4d %s' % (i, ln, h))
# now the runner's path
val = dict(s['val'])
val.update({"activity_kind": kind, "client_sdk": sg.CLIENT_SDK,
            "adj_signing_id": sg.ADJ_SIGNING_ID, "headers_id": "10",
            "native_version": sg.NATIVE_VERSION,
            "adj_verification": sg.ADJ_VERIFICATION})
r2 = sg.claims_for_law(val, kind)
raw2 = r2[0] if isinstance(r2, tuple) else r2
print()
print('claims identical (testbed vs runner):', raw == raw2)
print('  testbed len=%d  runner len=%d' % (len(raw), len(raw2)))
if raw != raw2:
    for i,(a,b) in enumerate(zip(raw,raw2)):
        if a!=b:
            print('  first claim diff at byte %d' % i)
            print('    testbed: %r' % raw[max(0,i-70):i+40])
            print('    runner : %r' % raw2[max(0,i-70):i+40])
            break
print()
print('runner pinned constants:')
print('   CLIENT_SDK      =', sg.CLIENT_SDK)
print('   NATIVE_VERSION  =', sg.NATIVE_VERSION)
print('   ADJ_VERIFICATION=', sg.ADJ_VERIFICATION)
print('   ADJ_SIGNING_ID  =', sg.ADJ_SIGNING_ID)
print('   DESC8           =', sg.DESC8.hex())
print('   DESC9           =', sg.DESC9.hex())
