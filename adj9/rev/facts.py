# facts.py - quick fact checks: H length/shape, whether the never-run
# verbatim-replay result exists, and the desc_det outcomes.
import json
import os

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
W = json.load(open(os.path.join(REV, 'wh4_records.json'), encoding='utf-8'))
print('wh4 top keys:', list(W.keys()))
gi = W.get('golden_sign_input_idx')
print('golden_sign_input_idx:', gi)
for k, v in W.items():
    if k == 'sign_inputs':
        print('sign_inputs:', len(v))
        continue
    print('  %s: %s' % (k, (str(v)[:120])))
if 'signings' in W:
    for i, s in enumerate(W['signings']):
        print('  signing %d keys: %s' % (i, list(s.keys())))
        for kk, vv in s.items():
            print('     %s = %s' % (kk, str(vv)[:100]))
for n in ('send_mint4_result.json', 'desc_det.log', 'd4.log', 'd4_blob_result.json',
          'mint_session_result.json', 'send_mint_session_result.json',
          'poll_attr_result.json', 'amc_final.log'):
    p = os.path.join(REV, n)
    print('%-32s %s' % (n, 'EXISTS %d B' % os.path.getsize(p)
                        if os.path.exists(p) else 'missing'))
