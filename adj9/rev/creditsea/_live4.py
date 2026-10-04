"""_live4.py — proper extraction of out_hex blobs, then decode + mint."""
import sys, os, re
HERE=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,HERE); sys.path.insert(0,os.path.dirname(HERE))
sys.path.insert(0,'C:/Users/Apps/Downloads/com.penti.app/adj9sign')
import mint_pipeline as MP
import signer_simple as sg
import desc10_58 as D
from testbed import decode, region_parts
b=open('adj9_cap_live_tarsan.log','rb').read().decode('utf-8','replace')
blobs=[]
for m in re.finditer(r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]+)", b):
    h=m.group(1).lower()
    if len(h)==384 and h not in blobs: blobs.append(h)
print('genuine out_len=192 blobs: %d' % len(blobs))
if blobs: print('blob[0]:', blobs[0][:64])
# decode check
okc=0
for h in blobs:
    try:
        d=decode(bytes.fromhex(h))
        if d.get('consts_ok'): okc+=1
    except Exception: pass
print('decode with consts_ok: %d / %d' % (okc, len(blobs)))
