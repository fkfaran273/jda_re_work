import json,struct,sys
sys.path.insert(0,r'C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool')
import adj9_signer as S

rows=[]
d=json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\device\rows_full.json'))
for r in d['rows']:
    rows.append(dict(kind='fresh',S=r['S'],d0=bytes.fromhex(r['desc']['0']['hex']),d4=bytes.fromhex(r['desc']['4']['hex'])))
o=json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\pair_h3.json'))
for r in o:
    rows.append(dict(kind='old',S=struct.unpack('<I',bytes.fromhex(r['d2']))[0],d0=bytes.fromhex(r['d0']),d4=bytes.fromhex(r['d4'])))

def src_of(d4b): return [int.from_bytes(d4b[i:i+2],'little') for i in range(16,32,2)]
def tgt(d0b): return [int.from_bytes(d0b[i:i+2],'little') for i in range(0,24,2)]
def mincand(t,src):
    for x in range(0x8000):
        if S._whitener_word(x,src)==t: return x
def hx(v,n): return ' '.join('%0*x'%(n,v))

print('== rows with min-candidate x1 and raw PRNG stream ==')
for i,row in enumerate(rows):
    src=src_of(row['d4']); tv=tgt(row['d0'])
    mc=[mincand(t,src) for t in tv]
    st=row['S']
    # raw PRNG stream
    stream=[]
    for k in range(48):
        st=S._step(st); stream.append(st)
    print(f"row{i:2d} {row['kind']:5s} S={row['S']:#010x} mc={' '.join('%02x'%x for x in mc)}")
    print('      stream:', ' '.join('%08x'%v for v in stream[:16]))
    print('      d4[16:32] bytes:', row['d4'][16:32].hex())
    # perms
    st=row['S']; perm=[0]*16
    for k in range(16):
        r=S._step(st); st=r; j=r%(k+1); perm[k],perm[j]=perm[j],k
    print('      perm:', perm)
    # x1 candidates in 0..0xff per slot, print ones that are also stream-derived (low byte of any stream entry / (v>>k)&0xff style)
    allc=[]
    for t in tv:
        cl=[x for x in range(0x8000) if S._whitener_word(x,src)==t]
        small=[x for x in cl if x<0x100]
        allc.append(small)
    print('      cand<0x100:', [' '.join('%02x'%x for x in c) for c in allc])
