"""_final_live.py — OUR signature vs the 3 LIVE genuine creditsea blobs.

With the right D9 and the right head (0x2b,), this is the penti criterion:
reproduce the device's own envelope byte-for-byte from live data.
"""
import sys, os, re, struct
HERE=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,HERE); sys.path.insert(0,os.path.dirname(HERE))
sys.path.insert(0,'C:/Users/Apps/Downloads/com.penti.app/adj9sign')
import whiten_decoder as WD
import signer_simple as sg
import desc10_58 as D
import mint_pipeline as MP
b=open('adj9_cap_live_tarsan.log','rb').read().decode('utf-8','replace')
blobs=[]
for m in re.finditer(r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]+)", b):
    h=m.group(1).lower()
    if len(h)==384 and h not in blobs: blobs.append(h)
# genuine maps for the claims
maps=[]
for m in re.finditer(r'map_size=(\d+)\r?\nmap_toString=\{', b):
    seg=b[m.end():m.end()+6000]; end=seg.find('}'); raw=seg[:end]
    maps.append(dict(re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=([^,]*)', raw)))
sg.DESC9=bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")
sg.WIN_PHASE=(0x2B,)
_o=D.claims_for_law_58
sg.claims_for_law=lambda v,k:_o(dict(v,client_sdk="flutter5.8.0@android5.8.0"),k)
INT={'activity_kind','adj_signing_id','adj_verification','algorithm','client_sdk','headers_id','native_version'}
# find each blob's second by header inversion over a wide window
import datetime
lo,hi=1790740000,1790743000
hdr={}
for s in range(lo,hi):
    h=MP.make_header(s).hex()
    for bl in blobs:
        if bl.startswith(h): hdr[bl]=s
print('blobs=%d inverted=%d'%(len(blobs),len(hdr)))
ok=0; tot=0
for bl,sec in hdr.items():
    best=None
    for d in maps:
        ca=d.get('created_at','')
        try: ep=int(datetime.datetime.strptime(ca,'%Y-%m-%dT%H:%M:%S.%fZ%z').timestamp())
        except Exception: continue
        if abs(ep-sec)<=90 and (best is None or abs(ep-sec)<abs(best[1]-sec)): best=(d,ep)
    if not best: continue
    d,_=best
    params={k:v for k,v in d.items() if k not in INT}
    tot+=1
    try: blob,_,info=sg.sign_request(params, d.get('activity_kind','session'), second=sec)
    except Exception as e:
        print('  mint failed', e); continue
    if bytes(blob).hex()==bl:
        ok+=1; print('  *** BYTE-EXACT live %s second=%d'%(d.get('activity_kind'),sec))
    else:
        n=sum(1 for x,y in zip(bytes(blob).hex(),bl) if x==y)
        print('  live %s second=%d -> %d/192'%(d.get('activity_kind'),sec,n))
print()
print('BYTE-EXACT %d / %d (per-fill seed is random in sign_request, so a miss')
print('is expected unless we recover the seed from the record.)' % (ok,tot))
