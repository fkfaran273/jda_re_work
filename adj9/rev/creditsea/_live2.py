"""_live2.py — invert the 33 live blob headers to get each signing second
(arithmetic, instant), pair each blob with the nearest genuine map, then mint
ONCE per pair and diff 192 bytes."""
import sys, os, re, datetime, urllib.parse
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9sign')
import mint_pipeline as MP
import signer_simple as sg
import desc10_58 as D
b = open('adj9_cap_live_tarsan.log','rb').read().decode('utf-8','replace')
blobs=[]
for h in re.findall(r'\b([0-9a-f]{384})\b', b):
    if h not in blobs: blobs.append(h)
maps=[]
for m in re.finditer(r'map_size=(\d+)\r?\nmap_toString=\{', b):
    seg=b[m.end():m.end()+6000]; end=seg.find('}'); raw=seg[:end]
    d=dict(re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=([^,]*)', raw))
    try:
        ep=int(datetime.datetime.strptime(urllib.parse.unquote(d['created_at']),
             '%Y-%m-%dT%H:%M:%S.%fZ%z').timestamp())
    except Exception: ep=None
    maps.append((d.get('activity_kind','?'), d, ep))
# invert headers
hdrs={}
lo=min([m[2] for m in maps if m[2]])-120
hi=max([m[2] for m in maps if m[2]])+120
for s in range(lo, hi+1):
    h=MP.make_header(s).hex()
    for bl in blobs:
        if bl.startswith(h): hdrs.setdefault(bl, s)
print('blobs=%d  inverted seconds=%d' % (len(blobs), len(hdrs)))
sg.DESC9 = bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")
sg.WIN_PHASE=(0x2B,)
_o=D.claims_for_law_58
sg.claims_for_law=lambda v,k:_o(dict(v,client_sdk="flutter5.8.0@android5.8.0"),k)
INT={'activity_kind','adj_signing_id','adj_verification','algorithm','client_sdk','headers_id','native_version'}
ok=0; tested=0
for bl, sec in sorted(hdrs.items(), key=lambda x:x[1]):
    best=None
    for kind,d,ep in maps:
        if ep is None: continue
        if abs(ep-sec)<=90: 
            if best is None or abs(ep-sec)<abs(best[1]-sec): best=(kind,d,ep)
    if not best: continue
    kind,d,ep=best
    params={k:v for k,v in d.items() if k not in INT}
    tested+=1
    try: blob,_,info=sg.sign_request(params, kind, second=sec)
    except Exception as e: continue
    if bytes(blob).hex()==bl:
        ok+=1; print('  BYTE-EXACT  %-12s second=%d'%(kind,sec))
    else:
        n=sum(1 for x,y in zip(bytes(blob).hex(),bl) if x==y)
        print('  %-12s second=%d  %d/192'%(kind,sec,n))
print()
print('BYTE-EXACT %d / %d tested'%(ok,tested))
