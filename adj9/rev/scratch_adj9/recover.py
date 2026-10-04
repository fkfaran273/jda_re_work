import json,struct,sys
sys.path.insert(0,r'C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool')
import adj9_signer as S

rows=[]
d=json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\device\rows_full.json'))
for r in d['rows']:
    rows.append(dict(kind='fresh',S=r['S'],d0=bytes.fromhex(r['desc']['0']['hex']),d2=bytes.fromhex(r['desc']['2']['hex']),d4=bytes.fromhex(r['desc']['4']['hex'])))
o=json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\pair_h3.json'))
for r in o:
    rows.append(dict(kind='old',S=struct.unpack('<I',bytes.fromhex(r['d2']))[0],d0=bytes.fromhex(r['d0']),d2=bytes.fromhex(r['d2']),d4=bytes.fromhex(r['d4'])))

# sanity: d4/d2 reproduce; d0 baseline
for i,row in enumerate(rows):
    assert row['d2']==row['S'].to_bytes(4,'little')
    p4=b''.join(w.to_bytes(4,'big') for w in S._d4_words(row['S']))
    assert p4==row['d4'], i

def source_of(d4b):
    return [int.from_bytes(d4b[i:i+2],'little') for i in range(16,32,2)]

def target_vals(d0b):
    vals=[int.from_bytes(d0b[i:i+2],'little') for i in range(0,24,2)]
    return vals

# Brute-force candidate x1 per slot: invert whitener for all x1 in 0..0x7FFF
def cands(target, source):
    hit={}
    for x1 in range(0x8000):
        v=S._whitener_word(x1,source)
        hit.setdefault(v,[]).append(x1)
    return hit.get(target,[])

for i,row in enumerate(rows):
    src=source_of(row['d4'])
    tv=target_vals(row['d0'])
    print(f"row{i} {row['kind']} S={row['S']:#010x}")
    for s in range(12):
        cl=cands(tv[s],src)
        # show smallest few + any in 0x40..0x47 + 0x00..0x7f
        small=[x for x in cl if x<0x80]
        cyc=[x for x in cl if 0x40<=x<=0x47]
        print(f"  slot{s:2d} target={tv[s]:#06x} ncand={len(cl):3d} min={cl[0]:#06x} in0x00-0x7f={['%#x'%x for x in small[:8]]}{'...' if len(small)>8 else ''} in0x40-0x47={['%#x'%x for x in cyc]}")
