import json,struct,sys
sys.path.insert(0,r'C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool')
import adj9_signer as S
data=[]
d=json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\device\rows_full.json'))
for r in d['rows']: data.append(('fresh',r['S'],bytes.fromhex(r['desc']['0']['hex']),bytes.fromhex(r['desc']['4']['hex'])))
o=json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\pair_h3.json'))
for r in o: data.append(('old',struct.unpack('<I',bytes.fromhex(r['d2']))[0],bytes.fromhex(r['d0']),bytes.fromhex(r['d4'])))
def src_of(d4b): return [int.from_bytes(d4b[i:i+2],'little') for i in range(16,32,2)]
def tgt(d0b): return [int.from_bytes(d0b[i:i+2],'little') for i in range(0,24,2)]
def mincand(t,src):
    for x in range(0x8000):
        if S._whitener_word(x,src)==t: return x
print('== base-cycle rotations (full 12-slot and first-6) ==')
for kind,s0,d0b,d4b in data:
    src=src_of(d4b); tv=tgt(d0b)
    mc=[mincand(t,src) for t in tv]
    best=[]
    for r in range(8):
        seq=[0x40+((r+i)&7) for i in range(12)]
        hits=sum(1 for a,b in zip(seq,mc) if a==b)
        hits6=sum(1 for a,b in zip(seq[:6],mc[:6]) if a==b)
        best.append((hits,hits6,r))
    best.sort(reverse=True)
    print(f"{kind} S={s0:#010x} mc={['%02x'%x for x in mc]} top rot: {[(r,'%d/12'%h,'%d/6'%h6) for h,h6,r in best[:3]]}")
print()
print('== per-slot: is candidate in 0x40..0x47?  pattern of which slots are "cycle" ==')
for kind,s0,d0b,d4b in data:
    src=src_of(d4b); tv=tgt(d0b)
    mc=[mincand(t,src) for t in tv]
    incyc=''.join('Y' if 0x40<=x<=0x47 else '.' for x in mc)
    print(kind,hex(s0),incyc,['%02x'%x for x in mc])
