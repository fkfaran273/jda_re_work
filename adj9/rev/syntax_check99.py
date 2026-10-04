# syntax_check99.py - parse every script touched/added in the slice-99 work
import ast
import os

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
FILES = ['all_sign.py', 'final_d014.py', 'verify_d014.py', 'rand_hunt.py',
         'find_words.py', 'sec_scan.py', 'det3.py', 'desc10_law.py',
         'probe_a.py', 'h_struct.py', 'h_map.py', 'h_ten.py', 'h6_tail.py',
         'trace_survey.py', 'desc10_scan.py', 'desc10_click.py', 'hh.py']
ok = bad = 0
for f in FILES:
    p = os.path.join(REV, f)
    if not os.path.exists(p):
        continue
    try:
        ast.parse(open(p, encoding='utf-8').read())
        print('OK   %s' % f)
        ok += 1
    except SyntaxError as e:
        print('FAIL %s: %s' % (f, e))
        bad += 1
print('parsed %d, failed %d' % (ok, bad))