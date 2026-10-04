
import json, struct, sys, os
sys.path.insert(0, r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev')
HERE=r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev'
from fin_vm2 import FinEx
c=json.load(open(HERE+'/corpus.json')); blobs=c['blobs']; hs=c['hs']
packed=open(HERE+'/packed_canon0.bin','rb').read()
H=bytes.fromhex(hs[0]['H'])
sec=1789043803
raw=bytes.fromhex(blobs[0]['hex']); dws=struct.unpack('>48I',raw)
hdr=raw[:16]
# inputs: desc10 = packed, desc4 = H, desc0 = zero144? start with template others
D=json.load(open(HERE+'/fin_descs.json'))
by={d['build_idx']:(d['len_dw'], bytes.fromhex(d['data_hex'])) for d in D['descs']}
by[10]=(len(packed)//4, packed)
by[4]=(8, H)
by[0]=(36, bytes(144))
ORDER=[0,9,8,4,2,7,10,5,1,6,3]
seq=[(by[i][0],0,by[i][1]) for i in ORDER]
ex=FinEx(sec, seq)
st=ex.run(max_steps=20000000)
sinks={}
for (s,n,v) in ex.emit_trace: sinks.setdefault(s,{})[n]=v
blob=b''.join(struct.pack('>I',sinks[0x5500000000].get(i,0)) for i in range(48))
diff=sum(1 for i in range(48) if struct.unpack('>I',blob[i*4:i*4+4])[0]!=dws[i])
print('status',st,'steps',ex.steps,'body diff dwords:',diff,'/44')
print('hdr match:', blob[:16]==hdr)
if diff:
    fd=[i for i in range(4,48) if struct.unpack('>I',blob[i*4:i*4+4])[0]!=dws[i]][:8]
    print('first diffs idx:',fd)

