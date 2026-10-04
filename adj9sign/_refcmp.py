"""_refcmp.py — genuine creditsea referrer vs what we send."""
import re
CAP = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\creditsea\adj9_cap_fresh.log'
b = open(CAP,'rb').read().decode('utf-8','replace')
for m in re.finditer(r'map_toString=\{', b):
    seg=b[m.end():m.end()+6000]; end=seg.find('}'); raw=seg[:end]
    k=re.search(r'activity_kind=([^,]*)',raw)
    if k and k.group(1)=='click':
        r=re.search(r'referrer=([^,]*)',raw)
        print('GENUINE creditsea referrer : %r' % (r.group(1) if r else None))
        break
print('OUR click referrer         : %r' % 'adjust_reftag=ct02Gf7HqS2zM')
print()
print('penti genuine referrer     : %r' % "utm_source=(not set)&utm_medium=(not set)")
print('penti winning (ours)       : %r' % 'adjust_reftag=cUDKur8xwLIBH&utm_source=VKM+Digital+Yeni&...')
