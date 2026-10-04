# show_amc.py - dump amc_final_result.json fully
import json
r = json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\amc_final_result.json',
                   encoding='utf-8'))

def walk(d, pfx=''):
    if isinstance(d, dict):
        for k, v in d.items():
            walk(v, pfx + k + '.')
    elif isinstance(d, list):
        for i, v in enumerate(d):
            walk(v, pfx + ('%d.' % i))
    else:
        s = str(d)
        print('%-52s %s' % (pfx[:-1], s[:220]))
walk(r)
