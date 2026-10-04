"""_verify_head.py — the head lookup must not change any signature."""
import json, sys
sys.path.insert(0, '.')
import adj9_signature as S

camp = json.load(open('apps.json'))['creditsea']
camp['head_phase'] = [43]        # was [\"0x2b\"]
dev = json.load(open('device_data.json'))

S.configure_app(camp)
print('resolved head:', S.WIN_PHASE)
p = S.build_session_request('GAID', 'AUUID', dev, camp, 1789000000)
blob, _s, _i = S.sign_request(p, 'session', second=1789000000, seed=0xDEADBEEF)
print('session sig:', bytes(blob).hex()[:48], '...')

# and the same value written the hex way must give the identical signature
camp2 = dict(camp); camp2['head_phase'] = ['0x2b']
S.configure_app(camp2)
p2 = S.build_session_request('GAID', 'AUUID', dev, camp2, 1789000000)
blob2, _s, _i = S.sign_request(p2, 'session', second=1789000000, seed=0xDEADBEEF)
print('identical to the hex form:', bytes(blob) == bytes(blob2))
