# syntax_check99b.py - verify the slice-99 §8 probe scripts parse
import ast
import os

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
FILES = ['recog_probe.py', 'recog_probe2.py', 'recog_probe3.py',
         'final_offline_test.py', 'mint_exact_send.py', 'mint_vs_url.py',
         'peek_mo.py', 'h6_tail.py', 'h_ten.py', 'all_sign.py', 'final_d014.py',
         'h_map.py', 'h_struct.py', 'trace_survey.py']
ok = bad = 0
for f in FILES:
    p = os.path.join(REV, f)
    if not os.path.exists(p):
        print('MISSING %s' % f)
        continue
    try:
        ast.parse(open(p, encoding='utf-8').read())
        ok += 1
    except SyntaxError as e:
        print('FAIL %s: %s' % (f, e))
        bad += 1
print('parsed %d, failed %d' % (ok, bad))
for f in ('recog_probe3_result.json', 'recog_probe2_result.json',
          'recog_probe_result.json', 'final_offline_test_result.json',
          'mint_exact_send_result.json', 'all_signings.json', 'h_samples.json'):
    p = os.path.join(REV, f)
    print('%-32s %s' % (f, ('%d B' % os.path.getsize(p)) if os.path.exists(p)
                        else 'MISSING'))