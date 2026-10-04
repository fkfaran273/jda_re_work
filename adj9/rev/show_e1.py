# show_e1.py - display the E1 two-mint diff result
import json
r = json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\mint_e1_result.json',
                   encoding='utf-8'))
print('top keys:', list(r.keys()))
for m in r.get('mints', []):
    print('\nmint ok=%s blobLen=%s stamp=%s' % (
        m.get('ok'), m.get('blobLen'), m.get('stamp')))
    print('  err:', m.get('error'))
    print('  blob[:32]:', (m.get('blob_hex') or '')[:32])
    if m.get('diff'):
        for d in m['diff']:
            print('  DIFF:', d)
