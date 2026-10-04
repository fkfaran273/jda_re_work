"""_live5.py — brute-force the head phase of a LIVE blob (the per-app constant)."""
import sys, os, re, struct
HERE=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,HERE); sys.path.insert(0,os.path.dirname(HERE))
sys.path.insert(0,'C:/Users/Apps/Downloads/com.penti.app/adj9sign')
import signer_simple as sg
from testbed import decode
b=open('adj9_cap_live_tarsan.log','rb').read().decode('utf-8','replace')
blobs=[]
for m in re.finditer(r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]+)", b):
    h=m.group(1).lower()
    if len(h)==384 and h not in blobs: blobs.append(h)
import whiten_decoder as WD
for h in blobs:
    try:
        d=WD.decode_blob(bytes.fromhex(h))
        print('decoded: consts_ok=%s F_seed=%08x head=%s' % (d['consts_ok'], d['F_seed'], d['head'].hex()))
        S=d['F_seed']; tgt=d['head']
        hits=[]
        for a in range(0x20,0x60):
            w,_,_=sg.region(S,0,0,head=(a,))
            if b''.join(x.to_bytes(4,'big') for x in w) and WD.head_words(w)==tgt: hits.append((a,))
        for a in range(0x20,0x60):
            for c in range(0x20,0x60):
                w,_,_=sg.region(S,0,0,head=(a,c))
                if WD.head_words(w)==tgt: hits.append((a,c))
        names={43:'0x2b',65:'0x41',72:'0x48',34:'0x22',46:'0x2e',7:'0x07'}
        print('   matching head phases: %s' % [ '('+','.join(names.get(x,hex(x)) for x in hh)+')' for hh in hits])
    except Exception as e:
        print('decode failed:', repr(e))
