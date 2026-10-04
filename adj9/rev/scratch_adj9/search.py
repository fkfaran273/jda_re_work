import json,struct,sys,itertools
sys.path.insert(0,r'C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool')
import adj9_signer as S

data=[]
d=json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\device\rows_full.json'))
for r in d['rows']:
    data.append(('fresh',r['S'],bytes.fromhex(r['desc']['0']['hex']),bytes.fromhex(r['desc']['4']['hex'])))
o=json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\pair_h3.json'))
for r in o:
    data.append(('old',struct.unpack('<I',bytes.fromhex(r['d2']))[0],bytes.fromhex(r['d0']),bytes.fromhex(r['d4'])))

def src_of(d4b): return [int.from_bytes(d4b[i:i+2],'little') for i in range(16,32,2)]
def tgt(d0b): return [int.from_bytes(d0b[i:i+2],'little') for i in range(0,24,2)]
def mincand(t,src):
    for x in range(0x8000):
        if S._whitener_word(x,src)==t: return x

info=[]
for kind,s0,d0b,d4b in data:
    src=src_of(d4b)
    mc=[mincand(t,src) for t in tgt(d0b)]
    # full stream of _step, long
    st=s0; stream=[]
    for k in range(400): st=S._step(st); stream.append(st)
    # perm
    st=s0; perm=[0]*16
    for k in range(16):
        r=S._step(st); st=r; j=r%(k+1); perm[k],perm[j]=perm[j],k
    info.append(dict(kind=kind,S=s0,mc=mc,stream=stream,perm=perm,src=src,d4b=d4b))

for it in info:
    print(it['kind'],hex(it['S']),'mc=',['%02x'%x for x in it['mc']],'perm=',it['perm'])

print()
print('=== search: for each fresh row, where does each slot candidate appear in stream-derived x1? ===')
# Candidate derivations to test
def derivations(v, perm, idx):
    out={}
    out['v&0xff']=v&0xff
    out['v>>16&0xff']=(v>>16)&0xff
    out['v>>8&0xff']=(v>>8)&0xff
    out['v&0x7f']=v&0x7f
    out['v%128']=v%128
    out['v%16']=v%16
    out['v%8']=v%8
    out['0x40+(v&7)']=0x40+(v&7)
    out['0x40+(v>>29&7)']=0x40+((v>>29)&7)
    out['0x40+perm[idx]']=0x40+perm[idx%16]
    out['0x40+perm[idx&15]']=0x40+perm[idx&15]
    out['0x40+perm[(idx*3)&15]']=0x40+perm[(idx*3)&15]
    out['perm[idx]']=perm[idx%16]
    out['v%128 ^ (v>>16)%128']=(v&0x7f)^((v>>16)&0x7f)
    out['0x40+(v&7) + ((v>>16)&0x7f)']=None
    return out

for it in info:
    if it['kind']!='fresh': continue
    print('fresh',hex(it['S']))
    st=it['stream']; perm=it['perm']
    # for each slot, find matches of candidate x1 in each derived quantity across the first 64 stream states
    for slot in range(12):
        x=it['mc'][slot]
        hits=[]
        for k,v in enumerate(st[:64]):
            for name,val in derivations(v,perm,slot).items():
                if val==x: hits.append((name,k))
        print('  slot%2d x=%02x hits=%s'%(slot,x,hits[:12]))
