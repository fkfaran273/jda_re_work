# show_mint4.py - dump minted4.json essentials
import json
r = json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\minted4.json',
                   encoding='utf-8'))
print('blob', len(bytes.fromhex(r['blob_hex'])), 'B')
print('stamp', r['stamp'])
print('nsign captured:', r['nsign_b64'] is not None)
print('pairs:', len(r['mapPairs']))
for k, v in r['mapPairs']:
    print(' ', k, '=', str(v)[:60])
print('auth tail:', r['authorization'][-80:])
print('sigmap keys:', list((r['sigmap'] or {}).keys()))
