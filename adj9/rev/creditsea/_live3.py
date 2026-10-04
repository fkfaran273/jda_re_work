"""_live3.py — does the live blob decode the SAME way as the old capture?

If the live blobs decode to a valid record with consts_ok and a recoverable
region, then 0/23 means the SEED differs (sign_request picks a random one).
If they do NOT decode, the live signing used different constants entirely --
which would be the real finding.
"""
import sys, os, re, binascii
HERE=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,HERE); sys.path.insert(0,os.path.dirname(HERE))
sys.path.insert(0,'C:/Users/Apps/Downloads/com.penti.app/adj9sign')
import signer_simple as sg
from testbed import decode
b=open('adj9_cap_live_tarsan.log','rb').read().decode('utf-8','replace')
blobs=[]
for h in re.findall(r'\b([0-9a-f]{384})\b', b):
    if h not in blobs: blobs.append(h)
print('distinct live blobs: %d' % len(blobs))
good=0; bad=0
for h in blobs[:40]:
    try:
        d=decode(bytes.fromhex(h))
        ok=d.get('consts_ok')
        if ok: good+=1
        else: bad+=1
        if len(blobs) <= 6 or (good+bad) <= 6:
            print('  consts_ok=%-5s S=%08x head=%s' % (ok, d['F_seed'], d['head'].hex()[:24]))
    except Exception as e:
        bad+=1
        if (good+bad)<=6: print('  decode failed: %r' % e)
print()
print('decoded with consts_ok: %d   without/failed: %d' % (good,bad))
